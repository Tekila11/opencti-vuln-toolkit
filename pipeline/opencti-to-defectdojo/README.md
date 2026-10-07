# opencti-to-defectdojo

Enriches active DefectDojo findings with threat intelligence from OpenCTI:
EPSS score/percentile, KEV status, ATT&CK technique tags, and contextual score.

## Data flow

```
DefectDojo API
  GET /api/v2/findings/?active=true&duplicate=false

         ↓  (per finding CVE ID)

OpenCTI API
  vulnerability.list(name=CVE-XXXX-YYYY)
    → x_opencti_epss_score / x_opencti_epss_percentile
    → x_opencti_cisa_kev
    → x_opencti_score
  stix_core_relationship.list(fromId=cve_id, toTypes=["Attack-Pattern"])
    → attack_pattern.read(id=tech_id) → x_mitre_id + name

         ↓

DefectDojo API
  PATCH /api/v2/findings/{id}/
    epss_score, epss_percentile, known_exploited, tags, description
```

## Prerequisites

- Python 3.10+
- pycti pinned to `7.260318.0` (must match OpenCTI version 7.26.0318)
- Network access from the host running these scripts to OpenCTI port 8080
- OpenCTI API token with read access
- EPSS and KEV connectors active in OpenCTI (otherwise those fields will be empty)

## Installation

```bash
mkdir -p /opt/scripts/opencti-to-defectdojo
cd /opt/scripts/opencti-to-defectdojo
# copy opencti_to_defectdojo.py, requirements.txt, .env.example
pip3 install -r requirements.txt
cp .env.example .env
```

## Configuration

Edit `.env`:

| Variable | Description |
|---|---|
| `DD_URL` | DefectDojo base URL, e.g. `http://192.168.x.x:8080` |
| `DD_TOKEN` | DefectDojo API token (Profile → API v2 Key) |
| `OPENCTI_URL` | OpenCTI base URL, e.g. `http://192.168.x.x:8080` |
| `OPENCTI_TOKEN` | OpenCTI API token (Profile → API Key) |
| `STATE_FILE` | Path to state JSON (default: `./state.json`) |

## Usage

```bash
# Test run
set -a && source .env && set +a
python3 opencti_to_defectdojo.py

# Cron — daily at 7am (after defectdojo-to-opencti at 6am)
0 7 * * * cd /opt/scripts/opencti-to-defectdojo && set -a && source .env && set +a && python3 opencti_to_defectdojo.py >> /var/log/oc-to-dd.log 2>&1
```

## What gets patched

| DefectDojo field | Source | Notes |
|---|---|---|
| `epss_score` | `x_opencti_epss_score` | Rounded to 6 decimal places |
| `epss_percentile` | `x_opencti_epss_percentile` | Rounded to 6 decimal places |
| `known_exploited` | `x_opencti_cisa_kev` | Set to `true` if in KEV; never set to `false` |
| `cwe` | `x_opencti_cwe` | Integer only; skipped if finding already has a CWE |
| `tags` | ATT&CK techniques + KEV | Sanitized as `attck-T1234` (no `&`, `:`, spaces) — merged with existing tags |
| `description` | All fields above | Enrichment block appended once; ATT&CK shown as `T1234 — Technique Name` |

The enrichment block is appended only once (idempotent check on `"OpenCTI Enrichment" in description`).

## State file

`state.json` stores a list of enriched finding IDs. Each finding is processed once.
Delete it to re-enrich all findings from scratch:

```bash
rm /opt/scripts/opencti-to-defectdojo/state.json
```

Note: deleting state.json will append a **duplicate enrichment block** to descriptions
of already-enriched findings. To fully re-enrich cleanly, also remove the existing
enrichment blocks from finding descriptions in DefectDojo first.

## Known quirks

- **KEV field name**: the correct field is `x_opencti_cisa_kev` (Boolean), **not**
  `x_opencti_in_kev` (does not exist in OpenCTI 7.26).
- **`objectsRelatedTo` does not exist**: ATT&CK patterns cannot be fetched inline
  in the CVE query. They require a separate `stix_core_relationship.list()` call,
  then `attack_pattern.read(id=tech_id)` to get `x_mitre_id` (not returned by default
  in relationship `to` objects).
- **ATT&CK tags**: stored as `attck-T1234` in tags (DefectDojo rejects `&`, `:`, spaces).
  Full name (`T1234 — Technique Name`) is written to the description enrichment block.
  Delete `state.json` and re-run to update findings enriched with an older format.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot query field "x_opencti_in_kev"` | Wrong KEV field name | Use `x_opencti_cisa_kev` — already fixed in current version |
| `Cannot query field "objectsRelatedTo"` | Field doesn't exist in 7.26 | Use separate relationship query — already fixed |
| `cve_missing=N` | CVE not in OpenCTI | NVD CVE connector not synced yet |
| `already_done=N` on first run | Stale state.json | `rm state.json` and re-run |
| `DD_URL` KeyError | `.env` not sourced | `set -a && source .env && set +a` |
