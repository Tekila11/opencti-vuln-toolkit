#!/usr/bin/env python3
"""
DefectDojo → OpenCTI asset-CVE linker

For each active, non-duplicate finding in DefectDojo that has a CVE ID:

  Wazuh findings (test tagged "wazuh"):
    - System name = product name (agent name, e.g. "APP-SRV-01")
    - Product type added as label on the System

  Kaspersky findings (test tagged "kaspersky"):
    - System name = product name (device display name)
    - Product type added as label on the System
    - Endpoint hostname stored in description

  Other findings (Nessus, auditor scans, etc.):
    - System name = endpoint host (IP or hostname)
    - Product name added as label on the System

  For all findings:
    - Finds the Vulnerability in OpenCTI by CVE name
    - Creates System if not found
    - Creates `has` relationship: System → Vulnerability
    - Updates x_opencti_affected_systems on the CVE

Startup caches (built once, before the main loop):
    - All CVEs from OpenCTI          → {cve_name: opencti_id}
    - All endpoints from DefectDojo  → {ep_id: host}
    - Systems cache (in-memory)      → {system_name: opencti_id}

State file (state.json):
    {
      "findings": [123, 456, ...],   # processed finding IDs — skipped on subsequent runs
      "systems":  {"42": "opencti-uuid", ...}  # DD product_id → OpenCTI System ID
    }
    The systems map prevents duplicate System creation when a product is renamed in DD.

Run daily via cron:
    0 7 * * * cd /opt/scripts/defectdojo-to-opencti && source .env && python3 defectdojo_to_opencti.py
"""

import json
import logging
import os
from pathlib import Path

import requests
import urllib3
from pycti import OpenCTIApiClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

DD_URL          = os.environ["DD_URL"]
DD_TOKEN        = os.environ["DD_TOKEN"]
OPENCTI_URL     = os.environ["OPENCTI_URL"]
OPENCTI_TOKEN   = os.environ["OPENCTI_TOKEN"]
DD_MIN_SEVERITY = os.environ.get("DD_MIN_SEVERITY", "Medium")
STATE_FILE      = Path(os.environ.get("STATE_FILE", "state.json"))

PAGE_SIZE = 100

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def severity_ok(sev: str) -> bool:
    try:
        return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(DD_MIN_SEVERITY)
    except ValueError:
        return False


# ── State ─────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        raw = json.loads(STATE_FILE.read_text())
        # Migrate old flat-list format
        if isinstance(raw, list):
            return {"findings": raw, "systems": {}}
        return {
            "findings": raw.get("findings", []),
            "systems":  raw.get("systems", {}),
        }
    return {"findings": [], "systems": {}}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps({
        "findings": sorted(state["findings"]),
        "systems":  state["systems"],
    }))


# ── DefectDojo client ─────────────────────────────────────────────────────────

class DefectDojoClient:
    def __init__(self, url: str, token: str):
        self.base    = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Token {token}", "Accept": "application/json"})
        self.session.verify = False

    def iter_findings(self):
        offset = 0
        while True:
            r = self.session.get(
                f"{self.base}/api/v2/findings/",
                params={
                    "active":    "true",
                    "duplicate": "false",
                    "limit":     PAGE_SIZE,
                    "offset":    offset,
                },
                timeout=30,
            )
            r.raise_for_status()
            data    = r.json()
            results = data.get("results", [])
            if not results:
                break
            yield from results
            if not data.get("next"):
                break
            offset += PAGE_SIZE

    def _fetch_all(self, path: str, extra_params: dict = None) -> list:
        results = []
        offset  = 0
        while True:
            params = {"limit": PAGE_SIZE, "offset": offset}
            if extra_params:
                params.update(extra_params)
            r = self.session.get(
                f"{self.base}/api/v2{path}",
                params=params,
                timeout=30,
            )
            r.raise_for_status()
            data = r.json()
            results.extend(data.get("results", []))
            if not data.get("next"):
                break
            offset += PAGE_SIZE
        return results

    def build_endpoint_cache(self) -> dict[int, str]:
        """Return {endpoint_id: host} for all endpoints."""
        cache = {}
        for ep in self._fetch_all("/endpoints/"):
            host = (ep.get("host") or ep.get("ip_address") or "").strip()
            if host:
                cache[ep["id"]] = host
        log.info(f"Endpoint cache: {len(cache)} entries")
        return cache

    def build_test_cache(self) -> dict[int, dict]:
        """Return {test_id: {is_wazuh, is_kaspersky, product_id, product_name, product_type_name}}."""
        pt_map = {pt["id"]: pt["name"] for pt in self._fetch_all("/product_types/")}
        prod_map = {
            p["id"]: {
                "name":              p["name"],
                "product_type_name": pt_map.get(p["prod_type"], ""),
            }
            for p in self._fetch_all("/products/")
        }
        eng_map = {
            e["id"]: {"product_id": e["product"]}
            for e in self._fetch_all("/engagements/")
        }
        cache = {}
        for t in self._fetch_all("/tests/"):
            eng  = eng_map.get(t["engagement"], {})
            prod_id = eng.get("product_id")
            prod = prod_map.get(prod_id, {})
            tags = t.get("tags") or []
            cache[t["id"]] = {
                "is_wazuh":          "wazuh" in tags,
                "is_kaspersky":      "kaspersky" in tags,
                "product_id":        prod_id,
                "product_name":      prod.get("name", ""),
                "product_type_name": prod.get("product_type_name", ""),
            }
        log.info(f"Test cache: {len(cache)} entries")
        return cache


# ── OpenCTI helpers ───────────────────────────────────────────────────────────

def build_vuln_cache(api: OpenCTIApiClient) -> dict[str, str]:
    """Fetch all Vulnerabilities from OpenCTI → {cve_name: opencti_id}."""
    cache = {}
    after = None
    while True:
        result = api.vulnerability.list(
            first=500,
            after=after,
            withPagination=True,
        )
        if isinstance(result, list):
            entities   = result
            pagination = {}
        else:
            entities   = result.get("entities", [])
            pagination = result.get("pagination", {})
        for v in entities:
            name = v.get("name", "")
            if name.startswith("CVE-"):
                cache[name] = v["id"]
        if not pagination.get("hasNextPage"):
            break
        after = pagination.get("endCursor")
    log.info(f"CVE cache: {len(cache)} entries from OpenCTI")
    return cache


_FIND_SYSTEM = """
query FindSystem($name: String!) {
  systems(search: $name) {
    edges { node { id name } }
  }
}
"""

_CREATE_SYSTEM = """
mutation CreateSystem($name: String!, $labels: [String], $description: String) {
  systemAdd(input: {
    name: $name
    description: $description
    objectLabel: $labels
  }) { id }
}
"""


def find_or_create_system(api: OpenCTIApiClient, name: str,
                           description: str | None = None,
                           labels: list[str] | None = None,
                           systems_cache: dict | None = None,
                           product_id: int | None = None,
                           state: dict | None = None) -> str:
    """Find or create a System, using state to survive product renames.

    Lookup order:
      1. state["systems"][product_id]  — stable across DD renames
      2. in-memory systems_cache[name] — fast within-run dedup
      3. OpenCTI name search           — first run / state missing
    """
    pid_key = str(product_id) if product_id else None

    # 1. State lookup by DD product ID (survives renames)
    if pid_key and state is not None:
        sys_id = state["systems"].get(pid_key)
        if sys_id:
            if systems_cache is not None:
                systems_cache[name] = sys_id
            return sys_id

    # 2. In-memory cache (within-run dedup)
    if systems_cache is not None and name in systems_cache:
        sys_id = systems_cache[name]
        if pid_key and state is not None and pid_key not in state["systems"]:
            state["systems"][pid_key] = sys_id
            save_state(state)
        return sys_id

    # 3. OpenCTI name search
    result = api.query(_FIND_SYSTEM, {"name": name})
    for edge in result.get("data", {}).get("systems", {}).get("edges", []):
        if edge["node"]["name"] == name:
            sys_id = edge["node"]["id"]
            if systems_cache is not None:
                systems_cache[name] = sys_id
            if pid_key and state is not None:
                state["systems"][pid_key] = sys_id
                save_state(state)
            return sys_id

    # 4. Create
    result = api.query(_CREATE_SYSTEM, {
        "name":        name,
        "description": description,
        "labels":      labels or [],
    })
    sys_id = result["data"]["systemAdd"]["id"]
    if systems_cache is not None:
        systems_cache[name] = sys_id
    if pid_key and state is not None:
        state["systems"][pid_key] = sys_id
        save_state(state)
    return sys_id


_UPDATE_AFFECTED_SYSTEMS = """
mutation UpdateVulnAffectedSystems($id: ID!, $value: [Any]!) {
  vulnerabilityEdit(id: $id) {
    fieldPatch(input: [{key: "x_opencti_affected_systems", value: $value}]) {
      id
    }
  }
}
"""


def update_affected_systems(api: OpenCTIApiClient, vuln_id: str, cve_name: str) -> None:
    rels = api.stix_core_relationship.list(
        toId=vuln_id,
        relationship_type="has",
        fromTypes=["System"],
        withPagination=False,
    )
    entities = rels if isinstance(rels, list) else (rels or {}).get("entities", [])
    systems = sorted({
        rel.get("from", {}).get("name", "").strip()
        for rel in entities
        if isinstance(rel.get("from"), dict) and rel["from"].get("name")
    } - {""})
    if not systems:
        return
    api.query(_UPDATE_AFFECTED_SYSTEMS, {
        "id":    vuln_id,
        "value": [", ".join(systems)],
    })
    log.info(f"  x_opencti_affected_systems → {len(systems)} system(s) for {cve_name}")


def link_exists(api: OpenCTIApiClient, from_id: str, to_id: str) -> bool:
    result = api.stix_core_relationship.list(
        fromId=from_id,
        toId=to_id,
        relationship_type="has",
        withPagination=False,
    )
    entities = result if isinstance(result, list) else result.get("entities", [])
    return len(entities) > 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("=== DefectDojo → OpenCTI linker starting ===")

    dd    = DefectDojoClient(DD_URL, DD_TOKEN)
    api   = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN, ssl_verify=False)
    state = load_state()

    log.info("Building caches …")
    test_cache     = dd.build_test_cache()
    endpoint_cache = dd.build_endpoint_cache()
    vuln_cache     = build_vuln_cache(api)
    systems_cache: dict[str, str] = {}  # name → opencti_id, built during run

    stats = {"linked": 0, "already_done": 0, "no_cve": 0,
             "cve_missing": 0, "skipped_sev": 0, "errors": 0}
    updated_vulns: dict[str, str] = {}  # vuln_id → cve_name

    processed_findings = set(state["findings"])

    for finding in dd.iter_findings():
        fid      = finding["id"]
        vuln_ids = [v["vulnerability_id"] for v in finding.get("vulnerability_ids", [])
                    if v.get("vulnerability_id", "").startswith("CVE-")]
        cve      = vuln_ids[0] if vuln_ids else (finding.get("cve") or "")
        severity = finding.get("severity", "")

        if not cve or not cve.startswith("CVE-"):
            stats["no_cve"] += 1
            continue

        if fid in processed_findings:
            stats["already_done"] += 1
            continue

        if not severity_ok(severity):
            stats["skipped_sev"] += 1
            continue

        endpoints = finding.get("endpoints", [])
        if not endpoints:
            processed_findings.add(fid)
            state["findings"] = list(processed_findings)
            save_state(state)
            continue

        vuln_id = vuln_cache.get(cve)
        if not vuln_id:
            log.debug(f"{cve} not in OpenCTI yet, skipping")
            stats["cve_missing"] += 1
            continue

        test_info    = test_cache.get(finding.get("test", 0), {})
        is_wazuh      = test_info.get("is_wazuh", False)
        is_kaspersky  = test_info.get("is_kaspersky", False)
        product_name  = test_info.get("product_name", "")
        product_type  = test_info.get("product_type_name", "")
        product_id    = test_info.get("product_id")
        use_prod_name = is_wazuh or is_kaspersky

        log.info(f"Finding #{fid} — {cve} — {severity} — "
                 f"{'wazuh' if is_wazuh else 'kaspersky' if is_kaspersky else 'scan'}")

        ep_success = 0
        for ep_id in endpoints:
            host = endpoint_cache.get(ep_id)
            if not host:
                log.warning(f"  Endpoint {ep_id} not in cache, skipping")
                continue

            try:
                if use_prod_name:
                    system_name = product_name
                    labels      = [product_type] if product_type else []
                    description = host if host != product_name else None
                else:
                    system_name = host
                    labels      = [product_name] if product_name else []
                    description = None

                sys_id = find_or_create_system(
                    api, system_name,
                    description=description,
                    labels=labels,
                    systems_cache=systems_cache,
                    product_id=product_id,
                    state=state,
                )

                if not link_exists(api, sys_id, vuln_id):
                    api.stix_core_relationship.create(
                        fromId=sys_id,
                        toId=vuln_id,
                        relationship_type="has",
                        description=f"DefectDojo finding #{fid}: {finding.get('title', '')}",
                    )
                    log.info(f"    → linked {system_name} → {cve}")
                    stats["linked"] += 1
                    updated_vulns[vuln_id] = cve
                ep_success += 1
            except Exception as exc:
                log.warning(f"  Error for endpoint {host}: {exc}")
                stats["errors"] += 1

        if ep_success > 0:
            processed_findings.add(fid)
            state["findings"] = list(processed_findings)
            save_state(state)

    # Update x_opencti_affected_systems for every CVE that got new links this run
    if updated_vulns:
        log.info(f"Updating x_opencti_affected_systems for {len(updated_vulns)} CVE(s) …")
        for vuln_id, cve_name in updated_vulns.items():
            try:
                update_affected_systems(api, vuln_id, cve_name)
            except Exception as exc:
                log.warning(f"  Could not update affected systems for {cve_name}: {exc}")

    log.info(
        f"=== Done — linked={stats['linked']} "
        f"already_done={stats['already_done']} "
        f"no_cve={stats['no_cve']} "
        f"cve_missing={stats['cve_missing']} "
        f"skipped_sev={stats['skipped_sev']} "
        f"errors={stats['errors']} ==="
    )


if __name__ == "__main__":
    main()
