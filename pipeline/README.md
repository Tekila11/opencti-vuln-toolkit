# Pipeline scripts

Four Python scripts that run on a schedule outside OpenCTI. Together they connect the detection
sources (Wazuh, Kaspersky) to DefectDojo, then keep DefectDojo and OpenCTI in sync in both
directions.

```
04:00  wazuh-to-defectdojo      Wazuh (OpenSearch :9200)    →  DefectDojo
05:00  kaspersky-to-defectdojo  Kaspersky KSC (API :13299)  →  DefectDojo
06:00  defectdojo-to-opencti    DefectDojo  →  OpenCTI   (System → has → Vulnerability)
07:00  opencti-to-defectdojo    OpenCTI     →  DefectDojo (EPSS, KEV, CWE, ATT&CK, score)
```

Each script has its own directory with a detailed `README.md` covering configuration and
troubleshooting, plus a `requirements.txt` and a `.env.example`.

## Scripts

| Directory | Role | Details |
|---|---|---|
| [`wazuh-to-defectdojo/`](wazuh-to-defectdojo) | Imports system vulnerabilities from Wazuh | [README](wazuh-to-defectdojo/README.md) |
| [`kaspersky-to-defectdojo/`](kaspersky-to-defectdojo) | Imports application vulnerabilities from Kaspersky KSC | [README](kaspersky-to-defectdojo/README.md) |
| [`defectdojo-to-opencti/`](defectdojo-to-opencti) | Creates `System` assets in OpenCTI and links them to CVEs | [README](defectdojo-to-opencti/README.md) |
| [`opencti-to-defectdojo/`](opencti-to-defectdojo) | Enriches DefectDojo findings with OpenCTI intelligence | [README](opencti-to-defectdojo/README.md) |

[`wazuh-agent-install/`](wazuh-agent-install) holds the Wazuh agent enrollment script. It is not
part of the cron pipeline.

## Common prerequisites

- Python 3.10 or newer
- `pip3 install -r requirements.txt` in each directory
- For the OpenCTI-facing scripts (`defectdojo-to-opencti`, `opencti-to-defectdojo`), a `pycti`
  version matching your OpenCTI platform release
- Each script reads its configuration from a local `.env` (copy `.env.example` to `.env`)

## Installing a script

```bash
cd pipeline/<script>
pip3 install -r requirements.txt
cp .env.example .env     # then fill in the values
```

## Scheduling

The examples below assume the scripts are deployed to `/opt/scripts/` on the host that can reach
both platforms.

```cron
0 4 * * * cd /opt/scripts/wazuh-to-defectdojo     && set -a && . ./.env && set +a && python3 wazuh_to_defectdojo.py     >> /var/log/wazuh-to-dd.log 2>&1
0 5 * * * cd /opt/scripts/kaspersky-to-defectdojo && set -a && . ./.env && set +a && python3 kaspersky_to_defectdojo.py >> /var/log/kaspersky-to-dd.log 2>&1
0 6 * * * cd /opt/scripts/defectdojo-to-opencti   && set -a && . ./.env && set +a && python3 defectdojo_to_opencti.py   >> /var/log/dd-to-oc.log 2>&1
0 7 * * * cd /opt/scripts/opencti-to-defectdojo   && set -a && . ./.env && set +a && python3 opencti_to_defectdojo.py   >> /var/log/oc-to-dd.log 2>&1
```

The 04:00 → 05:00 → 06:00 → 07:00 order matters. The imports have to populate DefectDojo before
the asset linking runs against OpenCTI, and that linking has to finish before the enrichment pass
reads back from OpenCTI. Running them out of order will not corrupt anything, but a given night's
findings will lag a cycle behind.

## State (`state.json`)

Every script keeps a `state.json` in its own directory recording what it has already processed.
This makes runs idempotent: re-running a script does not create duplicates.

Deleting `state.json` forces a full reprocess. Check the script's own README first, particularly
for `opencti-to-defectdojo`, which will then rewrite the enrichment block in every finding
description.

## Quick checks

```bash
# What each script last processed
cat /opt/scripts/*/state.json | head

# Run logs
tail /var/log/wazuh-to-dd.log /var/log/kaspersky-to-dd.log /var/log/dd-to-oc.log /var/log/oc-to-dd.log

# Is the schedule installed?
crontab -l
```

## Running a script by hand

```bash
cd /opt/scripts/<script>
set -a && . ./.env && set +a
python3 <script>.py
```
