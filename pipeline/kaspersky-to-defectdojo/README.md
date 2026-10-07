# kaspersky-to-defectdojo

Imports vulnerability findings from Kaspersky Security Center (KSC) 15.x into DefectDojo.

## How it works

1. Authenticates to the KSC Open API (port 13299, KSCBasic auth)
2. Fetches all managed hosts via `HostGroup.FindHosts`
3. Resolves group names via `HostGroup.GetGroupInfo`
4. Queries `v_vapm_vulnerability` per host GUID to retrieve CVE findings
5. For each host, looks up or creates a DefectDojo product (by IP first, then by name)
6. Imports findings under a "Kaspersky Vulnerability Scan" engagement

## DefectDojo structure

| DD object | Value |
|---|---|
| Product Type | KSC administration group name (e.g. "Servers", "IT Team") |
| Product | Host display name (`KLHST_WKS_DN`) |
| Engagement | Kaspersky Vulnerability Scan (CI/CD, permanent) |
| Scan type | Generic Findings Import |

On subsequent runs, `reimport-scan` is used to close fixed vulnerabilities and add new ones.

## Product deduplication

When a product already exists in DefectDojo for the same machine (e.g. created by the Wazuh connector), it is reused:

1. Search by IP via DD endpoints — skips products whose product type marks them as audit scope
2. Search by hostname
3. Create new product if no match found

The product type is always updated to the KSC group name, except for audit products.

## KSC service account

Role required: **Vulnerability and patch management operator** (`Opérateur de gestion des vulnérabilités et des correctifs` on a French KSC)

Scope assignments needed (add one entry per group):

- Serveur d'administration
- Appareils administrés
- Each additional group not covered by the above (check via `debug_srvview.py`)

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `KSC_HOST` | KSC server IP or FQDN |
| `KSC_PORT` | KSC API port (default: 13299) |
| `KSC_USERNAME` | Service account username |
| `KSC_PASSWORD` | Service account password |
| `DD_URL` | DefectDojo base URL (e.g. `https://192.168.x.x:8443`) |
| `DD_TOKEN` | DefectDojo API token |
| `DD_MIN_SEVERITY` | Minimum severity to import (default: `Low`) |
| `STATE_FILE` | Path to state file (default: `state.json`) |

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run
source .env
python3 kaspersky_to_defectdojo.py
```

## Cron (daily at 05:00)

```
0 5 * * * cd /opt/scripts/kaspersky-to-defectdojo && source .env && python3 kaspersky_to_defectdojo.py >> /var/log/kaspersky-to-defectdojo.log 2>&1
```

## State file

`state.json` maps host GUIDs to DefectDojo test IDs:

```json
{
  "00000000-0000-0000-0000-000000000000": {
    "test_id": 42,
    "name": "WIN-SRV-01"
  }
}
```

Delete `state.json` to force a full reimport from scratch.

## Debugging

`debug_srvview.py` probes the KSC API to verify connectivity, check visible host/vuln counts, and identify missing group scope assignments.

```bash
source .env
python3 debug_srvview.py
```
