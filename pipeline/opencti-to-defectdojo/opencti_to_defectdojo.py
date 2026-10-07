#!/usr/bin/env python3
"""
OpenCTI → DefectDojo enrichment script

For each active DefectDojo finding with a CVE ID, fetches enrichment from OpenCTI:
  - epss_score / epss_percentile       → native DefectDojo fields
  - KEV status                         → known_exploited field + "KEV" tag
  - ATT&CK techniques                  → tags (ATT&CK:Txxxx)
  - x_opencti_score                    → appended to description
  - x_opencti_cwe                      → cwe field (integer)

State file tracks enriched finding IDs so subsequent runs only process new findings.

Run daily via cron:
    0 8 * * * cd /opt/scripts/opencti-to-defectdojo && source .env && python3 opencti_to_defectdojo.py
"""

import json
import logging
import os
import re
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

DD_URL        = os.environ["DD_URL"]
DD_TOKEN      = os.environ["DD_TOKEN"]
OPENCTI_URL   = os.environ["OPENCTI_URL"]
OPENCTI_TOKEN = os.environ["OPENCTI_TOKEN"]
STATE_FILE    = Path(os.environ.get("STATE_FILE", "state.json"))

PAGE_SIZE = 100

# ── State ─────────────────────────────────────────────────────────────────────

def load_state() -> set[int]:
    if STATE_FILE.exists():
        return set(json.loads(STATE_FILE.read_text()))
    return set()


def save_state(state: set[int]) -> None:
    STATE_FILE.write_text(json.dumps(sorted(state)))


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
                params={"active": "true", "duplicate": "false",
                        "limit": PAGE_SIZE, "offset": offset},
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

    def patch_finding(self, fid: int, payload: dict) -> None:
        r = self.session.patch(
            f"{self.base}/api/v2/findings/{fid}/",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        r.raise_for_status()

    def get_tags(self, fid: int) -> list[str]:
        r = self.session.get(
            f"{self.base}/api/v2/findings/{fid}/",
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("tags", [])


# ── OpenCTI helpers ───────────────────────────────────────────────────────────

CVE_FIELDS = """
    id
    name
    x_opencti_epss_score
    x_opencti_epss_percentile
    x_opencti_cisa_kev
    x_opencti_score
    x_opencti_cwe
"""


def fetch_cve(api: OpenCTIApiClient, cve_id: str) -> dict | None:
    result = api.vulnerability.list(
        filters={
            "mode": "and",
            "filters": [{"key": ["name"], "values": [cve_id],
                         "operator": "eq", "mode": "or"}],
            "filterGroups": [],
        },
        customAttributes=CVE_FIELDS,
        withPagination=False,
    )
    entities = result if isinstance(result, list) else result.get("entities", [])
    return entities[0] if entities else None


def extract_attack_patterns(api: OpenCTIApiClient, cve_opencti_id: str) -> tuple[list[str], list[str]]:
    """Returns (tags, display_labels) where tags are sanitized for DD and display_labels include the full name."""
    tags = []
    display_labels = []
    try:
        rels = api.stix_core_relationship.list(
            fromId=cve_opencti_id,
            relationship_type="related-to",
            toTypes=["Attack-Pattern"],
            first=50,
        )
        for rel in (rels or []):
            to_obj = rel.get("to", {})
            if not isinstance(to_obj, dict):
                continue
            tech_id = to_obj.get("id")
            if not tech_id:
                continue
            pattern = api.attack_pattern.read(id=tech_id, customAttributes="id x_mitre_id name")
            mitre_id = (pattern or {}).get("x_mitre_id", "")
            name     = (pattern or {}).get("name", "")
            if mitre_id and mitre_id.startswith("T"):
                # DefectDojo tags cannot contain &, :, or spaces
                tags.append(f"attck-{mitre_id}")
                display_labels.append(f"{mitre_id} — {name}" if name else mitre_id)
    except Exception:
        pass
    return tags, display_labels


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("=== OpenCTI → DefectDojo enrichment starting ===")

    dd    = DefectDojoClient(DD_URL, DD_TOKEN)
    api   = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN, ssl_verify=False)
    state = load_state()

    stats = {"enriched": 0, "already_done": 0, "no_cve": 0,
             "cve_missing": 0, "errors": 0}

    for finding in dd.iter_findings():
        fid = finding["id"]
        vuln_ids = [v["vulnerability_id"] for v in finding.get("vulnerability_ids", [])
                    if v.get("vulnerability_id", "").startswith("CVE-")]
        cve = vuln_ids[0] if vuln_ids else (finding.get("cve") or "")

        if not cve or not cve.startswith("CVE-"):
            stats["no_cve"] += 1
            continue

        if fid in state:
            stats["already_done"] += 1
            continue

        # Fetch enrichment from OpenCTI
        try:
            cve_data = fetch_cve(api, cve)
        except Exception as exc:
            log.warning(f"OpenCTI lookup failed for {cve}: {exc}")
            stats["errors"] += 1
            continue

        if not cve_data:
            log.debug(f"{cve} not found in OpenCTI")
            stats["cve_missing"] += 1
            continue

        log.info(f"Enriching finding #{fid} — {cve}")

        epss_score       = cve_data.get("x_opencti_epss_score")
        epss_percentile  = cve_data.get("x_opencti_epss_percentile")
        in_kev           = cve_data.get("x_opencti_cisa_kev", False)
        opencti_score    = cve_data.get("x_opencti_score")
        attack_tags, attack_labels = extract_attack_patterns(api, cve_data["id"])

        cwe_raw = cve_data.get("x_opencti_cwe")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else None
        cwe_str = str(cwe_raw) if cwe_raw else ""
        cwe_num = None
        if cwe_str:
            m = re.search(r"\d+", cwe_str)
            if m:
                cwe_num = int(m.group())

        # Build enrichment note to append to description
        note_lines = ["\n\n---\n**OpenCTI Enrichment**"]
        if opencti_score is not None:
            note_lines.append(f"- Contextual score: {opencti_score}/100")
        if epss_score is not None:
            note_lines.append(f"- EPSS: {epss_score:.4f} ({(epss_percentile or 0)*100:.1f}th percentile)")
        if in_kev:
            note_lines.append("- **In CISA KEV** (actively exploited)")
        if attack_labels:
            note_lines.append(f"- ATT&CK: {', '.join(attack_labels)}")
        if cwe_num is not None:
            note_lines.append(f"- CWE: CWE-{cwe_num}")

        # Merge tags (existing + new)
        try:
            existing_tags = finding.get("tags", [])
        except Exception:
            existing_tags = []

        new_tags = list(set(existing_tags) | set(attack_tags))
        if in_kev and "KEV" not in new_tags:
            new_tags.append("KEV")

        # Build PATCH payload
        payload: dict = {"tags": new_tags}

        if epss_score is not None:
            payload["epss_score"]      = round(epss_score, 6)
        if epss_percentile is not None:
            payload["epss_percentile"] = round(epss_percentile, 6)
        if in_kev:
            payload["known_exploited"] = True
        if cwe_num is not None and not finding.get("cwe"):
            payload["cwe"] = cwe_num

        # Append enrichment note to description
        existing_desc = finding.get("description", "") or ""
        if "OpenCTI Enrichment" not in existing_desc:
            payload["description"] = existing_desc + "\n".join(note_lines)

        try:
            dd.patch_finding(fid, payload)
            log.info(
                f"  → epss={epss_score} kev={in_kev} "
                f"score={opencti_score} tags={attack_tags}"
            )
            stats["enriched"] += 1
        except Exception as exc:
            log.warning(f"  PATCH failed for finding #{fid}: {exc}")
            stats["errors"] += 1
            continue

        state.add(fid)
        save_state(state)

    log.info(
        f"=== Done — enriched={stats['enriched']} "
        f"already_done={stats['already_done']} "
        f"no_cve={stats['no_cve']} "
        f"cve_missing={stats['cve_missing']} "
        f"errors={stats['errors']} ==="
    )


if __name__ == "__main__":
    main()
