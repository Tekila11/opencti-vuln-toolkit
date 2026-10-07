#!/usr/bin/env python3
"""
Kaspersky Security Center → DefectDojo import script

Queries KSC 15.x Open API (port 13299) for all vulnerability data via
SrvView v_vapm_vulnerability, groups findings by host, then imports
them into DefectDojo:

    Product Type : KSC administration group  (e.g. "Windows Servers")
    Product      : device display name (KLHST_WKS_DN)
    Endpoint     : hostname + IP address
    Finding      : one per (host, CVE) pair

Run daily via cron:
    0 4 * * * cd /opt/scripts/kaspersky-to-defectdojo && source .env && \\
              python3 kaspersky_to_defectdojo.py >> /var/log/kaspersky-to-defectdojo.log 2>&1
"""

import base64
import json
import logging
import os
import socket
import struct
import tempfile
from collections import defaultdict
from datetime import date
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

KSC_HOST     = os.environ["KSC_HOST"]
KSC_PORT     = int(os.environ.get("KSC_PORT", "13299"))
KSC_USERNAME = os.environ["KSC_USERNAME"]
KSC_PASSWORD = os.environ["KSC_PASSWORD"]

DD_URL          = os.environ["DD_URL"]
DD_TOKEN        = os.environ["DD_TOKEN"]
DD_MIN_SEVERITY = os.environ.get("DD_MIN_SEVERITY", "Low")
STATE_FILE      = Path(os.environ.get("STATE_FILE", "state.json"))

PAGE_SIZE    = 1000
SRVVIEW_LIMIT = 10000   # KSC caps SrvView iterators at 10k rows; query per-host to work around

# SeverityRating from KSC: 1=Warning, 2=High, 3=Critical, 4=Critical (also used)
SEVERITY_MAP = {
    0: "Info",
    1: "Low",
    2: "High",
    3: "Critical",
    4: "Critical",
}

VULN_FIELDS = [
    "KLHST_WKS_HOSTNAME",       # host GUID
    "KLHST_WKS_DN",             # host display name
    "KLHST_WKS_IP_LONG",        # IPv4 as little-endian int32 wrapped in {type,value}
    "VulnerabilityId",          # KLA bulletin ID
    "strCVE",                   # CVE identifier
    "SeverityRating",           # 1-4
    "VendorName",
    "LocalizeProductName",
    "ProductVersion",
    "bPatchAvailable",
    "DescriptionURL",
    "DetectionTime",            # {type: datetime, value: ISO string}
    "ObjPath",
    "nVulnExploitStatus",
    "nVulnMalwareStatus",
]

HOST_FIELDS = [
    "KLHST_WKS_HOSTNAME",
    "KLHST_WKS_DN",
    "KLHST_WKS_WINHOSTNAME",
    "KLHST_WKS_FQDN",
    "KLHST_WKS_DNSNAME",
    "KLHST_WKS_DNSDOMAIN",
    "KLHST_WKS_WINDOMAIN",
    "KLHST_WKS_IP_LONG",
    "KLHST_WKS_OS_NAME",
    "KLHST_WKS_GROUPID",
]


# ── KSC Session ────────────────────────────────────────────────────────────────

class KSCSession:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.base_url  = f"https://{host}:{port}/api/v1.0"
        self._user     = username
        self._pass     = password
        self._session  = requests.Session()
        self._session.verify   = False
        self._logged_in = False

    def _login(self) -> None:
        u = base64.b64encode(self._user.encode()).decode()
        p = base64.b64encode(self._pass.encode()).decode()
        r = self._session.post(
            f"{self.base_url}/login",
            headers={
                "Authorization": f'KSCBasic user="{u}", pass="{p}", internal="1"',
                "Content-Type": "application/json",
            },
            data="{}",
            timeout=30,
        )
        r.raise_for_status()
        self._logged_in = True
        log.info("KSC login OK")

    def post(self, method: str, body: dict, retry: bool = True) -> dict:
        if not self._logged_in:
            self._login()
        r = self._session.post(
            f"{self.base_url}/{method}",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=120,
        )
        if r.status_code == 401 and retry:
            self._logged_in = False
            return self.post(method, body, retry=False)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def ip_from_long(n) -> str:
        if isinstance(n, dict):
            n = n.get("value", 0)
        return socket.inet_ntoa(struct.pack(">I", int(n)))


# ── SrvView iterator helpers ───────────────────────────────────────────────────

def srvview_iter(ksc: KSCSession, view: str, fields: list, filter_str: str = "") -> list[dict]:
    """Fetch all rows from a KSC SrvView.

    KSC caps iterators at 10,000 rows. When the view has more data, callers
    must pass a per-host filter so each query stays under that limit.
    """
    res = ksc.post("SrvView.ResetIterator", {
        "wstrViewName":      view,
        "wstrFilter":        filter_str,
        "vecFieldsToReturn": fields,
        "vecFieldsToOrder":  [],
        "lifetimeSec":       3600,
    })
    if "PxgError" in res:
        raise RuntimeError(f"SrvView.ResetIterator({view}): {res['PxgError']}")

    iterator_id = res["wstrIteratorId"]

    count_res = ksc.post("SrvView.GetRecordCount", {"wstrIteratorId": iterator_id})
    total = count_res.get("PxgRetVal", 0)

    rows = []
    start = 0
    while start < total:
        end = min(start + PAGE_SIZE, total)
        chunk = ksc.post("SrvView.GetRecordRange", {
            "wstrIteratorId": iterator_id,
            "nStart": start,
            "nEnd":   end,
        })
        items = chunk.get("pRecords", {}).get("KLCSP_ITERATOR_ARRAY", [])
        for item in items:
            rows.append(item.get("value", {}))
        if len(items) < (end - start):
            break
        start = end

    ksc.post("SrvView.ReleaseIterator", {"wstrIteratorId": iterator_id})
    return rows


def fetch_vulns_for_host(ksc: KSCSession, host_guid: str) -> list[dict]:
    """Fetch vulnerability rows for a single host, filtered by GUID."""
    # KSC filter syntax: column = 'value'
    filter_str = f"KLHST_WKS_HOSTNAME = '{host_guid}'"
    try:
        rows = srvview_iter(ksc, "v_vapm_vulnerability", VULN_FIELDS, filter_str)
        return rows
    except Exception as exc:
        log.warning(f"  vuln fetch failed for {host_guid}: {exc}")
        return []


def chunk_accessor_iter(ksc: KSCSession, accessor: str) -> list[dict]:
    """Paginate through a ChunkAccessor (used by FindHosts)."""
    rows = []
    start = 0
    while True:
        chunk = ksc.post("ChunkAccessor.GetItemsChunk", {
            "strAccessor": accessor,
            "nStart": start,
            "nCount": PAGE_SIZE,
        })
        items = chunk.get("pChunk", {}).get("KLCSP_ITERATOR_ARRAY", [])
        if not items:
            break
        for item in items:
            rows.append(item.get("value", {}))
        if len(items) < PAGE_SIZE:
            break
        start += len(items)
    return rows


# ── KSC data fetching ──────────────────────────────────────────────────────────

def build_group_cache(ksc: KSCSession, group_ids: set[int]) -> dict[int, str]:
    """Return {group_id: group_name} by querying GetGroupInfo per ID."""
    cache: dict[int, str] = {}
    for gid in sorted(group_ids):
        try:
            res = ksc.post("HostGroup.GetGroupInfo", {"nGroupId": gid})
            if "PxgError" not in res:
                name = res.get("PxgRetVal", {}).get("name", "")
                if name:
                    cache[gid] = name
        except Exception as exc:
            log.warning(f"GetGroupInfo({gid}) failed: {exc}")
    log.info(f"Group cache: {cache}")
    return cache


def fetch_hosts(ksc: KSCSession) -> dict[str, dict]:
    """Return {guid: host_dict} from HostGroup.FindHosts."""
    res = ksc.post("HostGroup.FindHosts", {
        "wstrFilter":        "",
        "vecFieldsToReturn": HOST_FIELDS,
        "vecFieldsToOrder":  [],
        "lMaxLifeTime":      600,
    })
    if "PxgError" in res:
        raise RuntimeError(f"FindHosts: {res['PxgError']}")

    accessor = res["strAccessor"]
    total    = res.get("PxgRetVal", 0)
    log.info(f"FindHosts: {total} hosts")

    hosts = {}
    for row in chunk_accessor_iter(ksc, accessor):
        guid = row.get("KLHST_WKS_HOSTNAME", "")
        if guid:
            hosts[guid] = row
    return hosts


# ── Finding builder ────────────────────────────────────────────────────────────

def format_description(v: dict, ip_str: str) -> str:
    cve          = v.get("strCVE", "")
    kla_id       = v.get("VulnerabilityId", "")
    vendor       = v.get("VendorName", "")
    product_name = v.get("LocalizeProductName", "")
    product_ver  = v.get("ProductVersion", "")
    obj_path     = v.get("ObjPath", "")
    exploit_flag = v.get("nVulnExploitStatus", False)
    malware_flag = v.get("nVulnMalwareStatus", False)
    advisory_url = v.get("DescriptionURL", "")
    host_dn      = v.get("KLHST_WKS_DN", "")

    lines = [
        "## Kaspersky Vulnerability Finding",
        "",
        "### Vulnerability",
        f"- **CVE:** {cve}",
    ]
    if kla_id:
        lines.append(f"- **KLA Bulletin:** [{kla_id}]({advisory_url})" if advisory_url else f"- **KLA Bulletin:** {kla_id}")
    if advisory_url:
        lines.append(f"- **Advisory:** {advisory_url}")

    lines += ["", "### Affected Host"]
    if host_dn:
        lines.append(f"- **Device:** {host_dn}")
    if ip_str:
        lines.append(f"- **IP Address:** {ip_str}")

    lines += ["", "### Affected Software"]
    if vendor:
        lines.append(f"- **Vendor:** {vendor}")
    if product_name:
        lines.append(f"- **Application:** {product_name}")
    if product_ver:
        lines.append(f"- **Version:** {product_ver}")
    if obj_path:
        lines.append(f"- **Object path:** `{obj_path}`")

    lines += ["", "### Threat Context"]
    lines.append(f"- **Exploit known:** {'Yes' if exploit_flag else 'No'}")
    lines.append(f"- **Malware associated:** {'Yes' if malware_flag else 'No'}")

    return "\n".join(lines)


def build_finding(v: dict, host_dn: str, ip_str: str, endpoint_host: str = "") -> dict | None:
    cve = (v.get("strCVE") or "").strip()
    if not cve.upper().startswith("CVE-"):
        return None

    raw_sev  = int(v.get("SeverityRating", 0))
    severity = SEVERITY_MAP.get(raw_sev, "Medium")
    if severity == "Info":
        return None

    product_name = v.get("LocalizeProductName", "")
    product_ver  = v.get("ProductVersion", "")
    vendor       = v.get("VendorName", "")
    advisory_url = v.get("DescriptionURL", "")
    patch_avail  = bool(v.get("bPatchAvailable", False))
    exploit_flag = bool(v.get("nVulnExploitStatus", False))
    obj_path     = v.get("ObjPath", "")

    detection_raw = v.get("DetectionTime", "")
    if isinstance(detection_raw, dict):
        detection_raw = detection_raw.get("value", "")
    detected_date = str(detection_raw)[:10] if detection_raw else date.today().isoformat()

    title_parts = [p for p in [vendor, product_name, product_ver] if p]
    title = f"{cve} — {' '.join(title_parts)}" if title_parts else cve

    ep_host = endpoint_host or host_dn
    endpoints = [{"host": ep_host}] if ep_host else []

    return {
        "title":             title,
        "date":              detected_date,
        "severity":          severity,
        "description":       format_description(v, ip_str),
        "references":        advisory_url,
        "mitigation":        "Apply the patch referenced in the advisory." if patch_avail else "No patch currently available.",
        "component_name":    product_name,
        "component_version": product_ver,
        "file_path":         obj_path,
        "fix_available":     patch_avail,
        "known_exploited":   exploit_flag,
        "cve":               cve,
        "vuln_id_from_tool": cve,
        "endpoints":         endpoints,
        "active":            True,
        "verified":          False,
        "tags":              ["kaspersky"],
    }


# ── State file ─────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── DefectDojo client ──────────────────────────────────────────────────────────

class DefectDojoClient:
    def __init__(self, url: str, token: str):
        self.base    = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Accept":        "application/json",
        })
        self.session.verify = False

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.base}/api/v2{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, timeout: int = 60, **kwargs) -> dict:
        r = self.session.post(f"{self.base}/api/v2{path}", timeout=timeout, **kwargs)
        r.raise_for_status()
        return r.json()

    def get_product_type_id(self, name: str) -> int:
        results = self._get("/product_types/", params={"name": name}).get("results", [])
        if results:
            return results[0]["id"]
        log.info(f"Creating product type: {name}")
        return self._post("/product_types/", json={
            "name":             name,
            "description":      f"KSC administration group: {name}",
            "critical_product": True,
            "key_product":      True,
        })["id"]

    # Product type names that indicate one-off audits — skip when looking up by IP
    AUDIT_TYPE_KEYWORDS = {"audit", "pentest", "assessment", "one-time"}

    def _is_audit_product(self, product_id: int) -> bool:
        """Return True if the product belongs to an audit-type product type."""
        try:
            p = self._get(f"/products/{product_id}/")
            type_id = p.get("prod_type")
            if not type_id:
                return False
            pt = self._get(f"/product_types/{type_id}/")
            type_name = pt.get("name", "").lower()
            return any(kw in type_name for kw in self.AUDIT_TYPE_KEYWORDS)
        except Exception:
            return False

    def find_product_by_endpoint(self, ip_str: str, hostname: str) -> int | None:
        """Return product ID by searching endpoints for IP or hostname, skipping audit products."""
        for host_val in filter(None, [ip_str, hostname]):
            results = self._get("/endpoints/", params={"host": host_val, "limit": 10}).get("results", [])
            for ep in results:
                pid = ep.get("product")
                if not pid:
                    continue
                if self._is_audit_product(pid):
                    log.info(f"Skipping audit product {pid} for {host_val}")
                    continue
                log.info(f"Found existing product {pid} via endpoint {host_val}")
                return pid
        return None

    def _update_product_type(self, product_id: int, type_id: int) -> None:
        """Set product type to KSC group, skip audit products."""
        try:
            p = self._get(f"/products/{product_id}/")
            if p.get("prod_type") == type_id:
                return
            if self._is_audit_product(product_id):
                return
            log.info(f"Updating product {product_id} type to {type_id}")
            self.session.patch(f"{self.base}/api/v2/products/{product_id}/",
                               json={"prod_type": type_id}, timeout=30).raise_for_status()
        except Exception as exc:
            log.warning(f"Could not update product type for {product_id}: {exc}")

    def get_or_create_product(self, name: str, type_id: int,
                              win_domain: str, dns_domain: str,
                              os_name: str, ip_str: str) -> int:
        # Endpoint-based lookup first — finds products created by Wazuh or other scanners
        pid = self.find_product_by_endpoint(ip_str, name)
        if pid:
            self._update_product_type(pid, type_id)
            return pid

        results = self._get("/products/", params={"name": name}).get("results", [])
        if results:
            pid = results[0]["id"]
            self._update_product_type(pid, type_id)
            return pid
        log.info(f"Creating product: {name}")

        tags = ["kaspersky", "endpoint"]
        if win_domain:
            tags.append(f"win-domain:{win_domain.lower()}")
        if dns_domain:
            tags.append(f"dns-domain:{dns_domain.lower()}")
        if os_name:
            tags.append(f"os:{os_name.lower().replace(' ', '-')}")

        desc_parts = ["Kaspersky Security Center managed endpoint."]
        if ip_str:
            desc_parts.append(f"IP: {ip_str}")
        if win_domain:
            desc_parts.append(f"Windows domain: {win_domain}")
        if dns_domain:
            desc_parts.append(f"DNS domain: {dns_domain}")
        if os_name:
            desc_parts.append(f"OS: {os_name}")

        return self._post("/products/", json={
            "name":                 name,
            "description":          "\n".join(desc_parts),
            "prod_type":            type_id,
            "business_criticality": "high",
            "lifecycle":            "production",
            "origin":               "internal",
            "tags":                 tags,
        })["id"]

    def get_or_create_engagement(self, product_id: int) -> int:
        results = self._get("/engagements/", params={
            "product":         product_id,
            "name":            "Kaspersky Vulnerability Scan",
        }).get("results", [])
        if results:
            return results[0]["id"]
        log.info(f"Creating engagement for product {product_id}")
        return self._post("/engagements/", json={
            "name":            "Kaspersky Vulnerability Scan",
            "product":         product_id,
            "engagement_type": "CI/CD",
            "status":          "In Progress",
            "target_start":    date.today().isoformat(),
            "target_end":      "2099-12-31",
        })["id"]

    def get_existing_test_id(self, engagement_id: int) -> int | None:
        results = self._get("/tests/", params={
            "engagement": engagement_id,
            "scan_type":  "Generic Findings Import",
            "limit":      1,
        }).get("results", [])
        return results[0]["id"] if results else None

    def import_findings(self, engagement_id: int, findings: list,
                        tmpdir: str, test_id: int | None) -> tuple:
        tmp = Path(tmpdir) / f"findings_{engagement_id}.json"
        tmp.write_text(json.dumps({"findings": findings}, default=str))

        common = {
            "scan_type":        "Generic Findings Import",
            "minimum_severity": DD_MIN_SEVERITY,
            "active":           "true",
            "verified":         "false",
            "skip_duplicates":  "true",
            "tags":             "kaspersky",
        }

        with open(tmp, "rb") as f:
            if test_id:
                log.info(f"    reimport-scan (test_id={test_id})")
                result = self._post(
                    "/reimport-scan/",
                    timeout=600,
                    files={"file": ("findings.json", f, "application/json")},
                    data={**common, "test": str(test_id), "close_old_findings": "true"},
                )
                return result.get("finding_count", 0), test_id
            else:
                log.info(f"    import-scan (new test, engagement={engagement_id})")
                result = self._post(
                    "/import-scan/",
                    timeout=600,
                    files={"file": ("findings.json", f, "application/json")},
                    data={**common, "engagement": str(engagement_id)},
                )
                return result.get("finding_count", 0), result.get("test")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    log.info("=== Kaspersky → DefectDojo import starting ===")

    ksc   = KSCSession(KSC_HOST, KSC_PORT, KSC_USERNAME, KSC_PASSWORD)
    dd    = DefectDojoClient(DD_URL, DD_TOKEN)
    state = load_state()

    # 1. Fetch all host metadata (GUID → details)
    log.info("Fetching hosts …")
    hosts = fetch_hosts(ksc)

    # 2. Build group name cache from the group IDs seen on hosts
    group_ids = {
        int(h["KLHST_WKS_GROUPID"])
        for h in hosts.values()
        if h.get("KLHST_WKS_GROUPID") is not None
    }
    log.info(f"Building group cache for {len(group_ids)} groups …")
    group_cache = build_group_cache(ksc, group_ids)

    # Build GUID → group_name lookup
    guid_to_group: dict[str, str] = {}
    guid_to_meta:  dict[str, dict] = {}
    for guid, h in hosts.items():
        group_id   = h.get("KLHST_WKS_GROUPID")
        group_name = group_cache.get(int(group_id), "Kaspersky") if group_id else "Kaspersky"
        guid_to_group[guid] = group_name

        ip_str = ""
        if h.get("KLHST_WKS_IP_LONG"):
            try:
                ip_str = KSCSession.ip_from_long(h["KLHST_WKS_IP_LONG"])
            except Exception:
                pass

        guid_to_meta[guid] = {
            "product_name": (
                h.get("KLHST_WKS_DN")
                or h.get("KLHST_WKS_WINHOSTNAME")
                or guid
            ),
            "endpoint_host": (
                h.get("KLHST_WKS_FQDN")
                or h.get("KLHST_WKS_DNSNAME")
                or h.get("KLHST_WKS_WINHOSTNAME")
                or h.get("KLHST_WKS_DN")
                or guid
            ),
            "group_name":   group_name,
            "win_domain":   h.get("KLHST_WKS_WINDOMAIN", ""),
            "dns_domain":   h.get("KLHST_WKS_DNSDOMAIN", ""),
            "os_name":      h.get("KLHST_WKS_OS_NAME", ""),
            "ip_str":       ip_str,
            "dn":           h.get("KLHST_WKS_DN", ""),
        }

    # 3. Fetch vulns per host GUID to work around the ~10k iterator cap.
    log.info(f"Fetching vulnerabilities for {len(guid_to_meta)} hosts …")
    by_host: dict[str, list] = defaultdict(list)
    skipped    = 0
    total_rows = 0

    for guid, meta in guid_to_meta.items():
        try:
            rows = srvview_iter(
                ksc, "v_vapm_vulnerability", VULN_FIELDS,
                filter_str=f'KLHST_WKS_HOSTNAME = "{guid}"',
            )
        except Exception as exc:
            log.warning(f"  vuln fetch failed for {meta['product_name']}: {exc}")
            continue

        total_rows += len(rows)
        ip_str        = meta.get("ip_str", "")
        dn            = meta.get("dn", "")
        endpoint_host = meta.get("endpoint_host") or dn

        for v in rows:
            finding = build_finding(v, dn, ip_str, endpoint_host)
            if finding:
                by_host[guid].append(finding)
            else:
                skipped += 1

        if rows:
            log.info(f"  {meta['product_name']}: {len(by_host[guid])} findings ({len(rows)} rows)")

    log.info(f"Total: {total_rows} vuln rows → {sum(len(f) for f in by_host.values())} findings "
             f"across {len(by_host)} hosts ({skipped} rows skipped)")

    # 5. Import into DefectDojo
    stats = {"imported": 0, "errors": 0}

    with tempfile.TemporaryDirectory() as tmpdir:
        for guid, findings in by_host.items():
            meta = guid_to_meta.get(guid) or {
                "product_name": findings[0]["endpoints"][0]["host"] if findings and findings[0]["endpoints"] else guid,
                "group_name":   "Kaspersky",
                "win_domain":   "",
                "dns_domain":   "",
                "os_name":      "",
                "ip_str":       findings[0]["endpoints"][1]["host"] if findings and len(findings[0]["endpoints"]) > 1 else "",
            }
            name = meta.get("product_name", guid)
            log.info(f"Processing {name} ({len(findings)} findings) …")
            try:
                type_id = dd.get_product_type_id(meta.get("group_name", "Kaspersky"))
                product_id = dd.get_or_create_product(
                    name       = name,
                    type_id    = type_id,
                    win_domain = meta.get("win_domain", ""),
                    dns_domain = meta.get("dns_domain", ""),
                    os_name    = meta.get("os_name", ""),
                    ip_str     = meta.get("ip_str", ""),
                )
                engagement_id = dd.get_or_create_engagement(product_id)

                host_state = state.get(guid, {})
                test_id    = host_state.get("test_id") if isinstance(host_state, dict) else None
                if not test_id:
                    test_id = dd.get_existing_test_id(engagement_id)

                count, new_test_id = dd.import_findings(
                    engagement_id, findings, tmpdir, test_id
                )

                state[guid] = {"test_id": new_test_id, "name": name}
                save_state(state)

                log.info(f"  → {count} findings imported (test_id={new_test_id})")
                stats["imported"] += 1

            except Exception as exc:
                log.error(f"Failed for '{name}': {exc}", exc_info=True)
                stats["errors"] += 1

    log.info(
        f"=== Done — hosts={len(by_host)} "
        f"imported={stats['imported']} errors={stats['errors']} ==="
    )


if __name__ == "__main__":
    main()
