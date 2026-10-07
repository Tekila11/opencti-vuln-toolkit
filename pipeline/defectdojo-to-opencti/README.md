# defectdojo-to-opencti

For each active, non-duplicate DefectDojo finding with a CVE ID, creates a **System**
entity in OpenCTI and links it to the corresponding Vulnerability via a `has` relationship
(`System → has → Vulnerability`).

The script handles two finding sources differently:

| Source | System name | Alias | Label |
|---|---|---|---|
| **Wazuh** (test tagged `wazuh`) | Agent name (DD product name) | Endpoint IP | Wazuh group (product type) |
| **Mass scan** (Nessus, auditor…) | Endpoint host / IP | — | Product name |

## Data flow

```
Startup caches (built once before the main loop):

  DefectDojo API
    GET /api/v2/product_types/  ┐
    GET /api/v2/products/       │  → test cache   {test_id: {is_wazuh, product_name, product_type_name}}
    GET /api/v2/engagements/    │
    GET /api/v2/tests/          ┘
    GET /api/v2/endpoints/         → endpoint cache {ep_id: host}

  OpenCTI API
    vulnerability.list (paginated) → CVE cache {cve_name: opencti_id}

Main loop (no CVE or endpoint API calls — all resolved from cache):

  DefectDojo API
    GET /api/v2/findings/?active=true&duplicate=false

         ↓  (per finding, only when CVE is in cache and not already processed)

  OpenCTI API
    systems(search=name)           → find existing System (+ in-memory cache after first lookup)
    systemAdd(...)                 → create System if absent
    stix_core_relationship.list()  → check if link already exists
    stix_core_relationship.create  → create System → has → Vulnerability
    vulnerabilityEdit(fieldPatch)  → update x_opencti_affected_systems on CVE
```

The `has` relationship direction (`System → has → Vulnerability`) is required by:
- The OpenCTI UI "Affected systems" field on each CVE
- The `cve-affected-systems-connector` and dashboard filters

## Prerequisites

- Python 3.10+
- pycti pinned to `7.260318.0` (must match OpenCTI version)
- Network access from the host running these scripts to OpenCTI port 8080
- OpenCTI API token with write access (create System entities and relationships)
- CVEs must already exist in OpenCTI (imported by the NVD CVE connector)

## Installation

```bash
mkdir -p /opt/scripts/defectdojo-to-opencti
cd /opt/scripts/defectdojo-to-opencti
# copy defectdojo_to_opencti.py, requirements.txt, .env.example
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
| `DD_MIN_SEVERITY` | Minimum finding severity to process (default: `Medium`) |
| `STATE_FILE` | Path to state JSON (default: `./state.json`) |

## Usage

```bash
# Test run
set -a && source .env && set +a
python3 defectdojo_to_opencti.py

# Cron — daily at 6am (after the imports: Wazuh 4am, Kaspersky 5am)
0 6 * * * cd /opt/scripts/defectdojo-to-opencti && set -a && source .env && set +a && python3 defectdojo_to_opencti.py >> /var/log/dd-to-oc.log 2>&1
```

## Wazuh finding detection

Wazuh findings are identified via the **test tag**, not the engagement name.
The `wazuh-to-defectdojo` script tags every test it creates with `wazuh`.
At startup, `defectdojo_to_opencti.py` builds a cache:

```
product_types → products → engagements → tests
```

Each test entry stores `{is_wazuh, product_name, product_type_name}`.
This is O(1) per finding — no extra API calls during the main loop.

## State file

`state.json` stores a list of processed DefectDojo finding IDs. A finding is only marked
done when at least one endpoint link succeeded. Delete it to reprocess all findings from scratch:

```bash
rm /opt/scripts/defectdojo-to-opencti/state.json
```

## Resetting (clean slate)

If you need to delete all Systems and recreate them (e.g. after changing relationship type):

```python
# Run with OPENCTI_URL and OPENCTI_TOKEN set in environment
from pycti import OpenCTIApiClient
import os

api = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"], ssl_verify=False)
after = None
deleted = 0
while True:
    result = api.stix_domain_object.list(types=["System"], first=100, after=after, withPagination=True)
    entities  = result.get("entities", []) if isinstance(result, dict) else (result or [])
    page_info = result.get("pagination", {}) if isinstance(result, dict) else {}
    for s in entities:
        api.stix_domain_object.delete(id=s["id"])
        print(f"Deleted {s.get('name', s['id'])}")
        deleted += 1
    if not page_info.get("hasNextPage"):
        break
    after = page_info.get("endCursor")
print(f"Done — {deleted} systems deleted")
```

Then delete `state.json` and rerun the script.

## Known quirks

- **CVE field**: The script reads from `vulnerability_ids[].vulnerability_id` first, falls back to
  the top-level `cve` field. Both paths are covered.
- **Endpoints**: the `endpoints` field in findings returns integer IDs. These are resolved
  from the startup endpoint cache (built once via `GET /api/v2/endpoints/`) — no per-finding API calls.
- **System vs Observable**: assets are created as **System** entities (Identity domain objects),
  not as Hostname or IPv4-Addr observables, for cleaner representation in OpenCTI.
- **Relationship type**: must be `has` (not `related-to`). The `cve-affected-systems-connector`
  and dashboard filters both expect `System → has → Vulnerability`.
- **pycti version**: pin to match your OpenCTI version. Newer pycti may introduce types
  not recognized by older OpenCTI.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| All findings treated as mass-scan (no Wazuh logic) | Test tags not loaded | Verify `wazuh-to-defectdojo` ran and tests have `wazuh` tag via `curl .../api/v2/tests/` |
| `no_cve=N` for all findings | CVE stored in `vulnerability_ids[]` not `cve` field | Already handled; check `vuln_ids` extraction in script |
| `host` empty for endpoint ID | Endpoint not in cache at startup | Check `GET /api/v2/endpoints/` returns results; verify DD_TOKEN has read access |
| `cve_missing=N` | CVE not yet imported by NVD CVE connector | Wait for connector to sync or reset connector state |
| `PermissionError` on state.json | Wrong file ownership | `sudo chown <user> /opt/scripts/defectdojo-to-opencti/` |
| Affected Systems column empty in dashboard | Wrong relationship type in old data | Delete Systems, reset state.json, rerun script |
