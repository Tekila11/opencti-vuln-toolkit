# wazuh-to-defectdojo

Imports vulnerability findings from Wazuh Indexer (OpenSearch) into DefectDojo,
**one product per agent**, enriched with IP from the Wazuh REST API.

## Data flow

```
Wazuh Indexer (OpenSearch :9200)
  wazuh-states-vulnerabilities-*  →  grouped by agent ID

Wazuh REST API (:55000)
  GET /agents                     →  agent name, IP, group, status

         ↓

DefectDojo API
  Product Type: <Wazuh agent group>   (e.g. "servers-linux", "windows-workstations")
                                       "default" group → "Endpoints"
  └── Product: <agent name>           (e.g. "APP-SRV-01", "mon-srv-01")
      └── Engagement: Wazuh Vulnerability Scan (CI/CD)
          └── Test (reused via state.json)
              └── Findings (endpoint = agent IP; fallback: hostname)
```

First run: `import-scan/` creates a new Test and stores `{test_id, name}` in `state.json`.  
Subsequent runs: `reimport-scan/` updates the existing Test (closes resolved findings, adds new ones).

## Prerequisites

- Python 3.10+
- Network access from the host running these scripts to:
  - Wazuh Indexer port 9200
  - Wazuh Manager API port 55000
- Wazuh Indexer user `defectdojo-indexer` with read access to `wazuh-states-vulnerabilities-*`
- Role `wazuh-readonly` created in Wazuh Indexer (Security → Roles) and mapped to `defectdojo-indexer`
- Wazuh API user (e.g. `dd-agent-reader`) with `agents:read` permission

> **Note:** `readall` is a reserved role in Wazuh Indexer and cannot be mapped.
> You must create a custom role.

## Installation

```bash
mkdir -p /opt/scripts/wazuh-to-defectdojo
cd /opt/scripts/wazuh-to-defectdojo
# copy wazuh_to_defectdojo.py, requirements.txt, .env.example
pip3 install -r requirements.txt
cp .env.example .env
```

## Configuration

Edit `.env`:

| Variable | Description |
|---|---|
| `OPENSEARCH_HOST` | Wazuh Indexer IP or hostname |
| `OPENSEARCH_PORT` | OpenSearch port (default: `9200`) |
| `OPENSEARCH_USER` | `defectdojo-indexer` |
| `OPENSEARCH_PASS` | Password set when creating the user |
| `WAZUH_API_URL` | Wazuh Manager API base URL, e.g. `https://192.168.x.x:55000` |
| `WAZUH_API_USER` | Wazuh API user (e.g. `dd-agent-reader`) |
| `WAZUH_API_PASS` | Wazuh API password (ASCII-safe — avoid `!`, `£`, `$`) |
| `DD_URL` | DefectDojo base URL, e.g. `http://192.168.x.x:8080` |
| `DD_TOKEN` | DefectDojo API token (Profile → API v2 Key) |
| `DD_MIN_SEVERITY` | Minimum severity to import (default: `Low`) |
| `STATE_FILE` | Path to state JSON (default: `./state.json`) |

## Usage

```bash
# Test run
set -a && source .env && set +a
python3 wazuh_to_defectdojo.py

# Cron — daily at 4am
0 4 * * * cd /opt/scripts/wazuh-to-defectdojo && set -a && source .env && set +a && python3 wazuh_to_defectdojo.py >> /var/log/wazuh-to-dd.log 2>&1
```

## State file

`state.json` maps each agent ID (stable across renames) to its test ID and current name:

```json
{
  "006": {"test_id": 4, "name": "APP-SRV-01"},
  "009": {"test_id": 7, "name": "mon-srv-01"}
}
```

The script handles these scenarios automatically:

| Scenario | Behaviour |
|---|---|
| Agent renamed | Product renamed in DefectDojo to match the new agent name |
| Agent moved to a different group | Product type updated in DefectDojo |
| Agent disconnected (no current findings) | Import skipped — existing findings preserved |
| `state.json` lost | Existing test recovered from DefectDojo API before creating a new one |

Delete `state.json` to force a full reimport as a fresh test (useful after a schema change or full reset).

## Severity filtering

Info-level findings are skipped at source (`SKIP_SEVERITIES = {"untriaged", "none", "-", "info"}`).
Use `DD_MIN_SEVERITY` to additionally filter Low findings (default allows Low and above).

## Product type mapping

The Wazuh agent **group** is used as the DefectDojo product type:

- Group `default` → product type `Endpoints`
- Any other group → product type = group name (e.g. `servers-linux`, `windows-workstations`)

Assign agents to meaningful groups in the Wazuh dashboard for automatic categorisation.

## Enriched description fields

Each finding description includes (when available):

- OS full version (`host.os.full`)
- Package path, license, architecture
- CVSS temporal/environmental score fallback
- Fix condition (`vulnerability.scanner.condition`)
- Data source (`vulnerability.scanner.source`)
- Wazuh manager name and agent version

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ConnectionError` on port 9200 | Firewall blocks the script's host from reaching the Indexer | Open port 9200 for that source IP |
| `AuthorizationException` | `defectdojo-indexer` missing index permissions | Check role mapping in Wazuh Indexer Security → Roles |
| `Could not build agent cache` | Wazuh API unreachable or wrong credentials | Check `WAZUH_API_URL`, port 55000 open, password has no shell-special chars |
| Agent cache: 0 entries | Wrong password — token acquired but invalid (missing `?raw=true`) | Verify `WAZUH_API_PASS` contains no `!` or `£`; test manually with `curl` |
| All findings reimported as new | `state.json` deleted or corrupted | Script recovers existing test from DefectDojo automatically |
| `DD_TOKEN` KeyError | `.env` not sourced | Run `set -a && source .env && set +a` before the script |
| Import timeout | Large agent (10k+ findings) exceeds 60s | Already handled — import timeout set to 600s |
