# Dashboards

Importable OpenCTI custom dashboards.

| File | Dashboard | Widgets |
|---|---|---|
| `opencti-cti-dashboard.json` | Vulnerability CTI Overview | Total CVEs, CVEs with an EPSS score, CVEs in CISA KEV, CVEs with a CWE, plus a sortable CVE list |

## Importing

In OpenCTI, go to **Dashboards → Custom dashboards**, then use **Import dashboard** and select the
JSON file.

The CVE list widget shows CVSS3 score and severity, the CISA KEV flag and the EPSS score as columns.
Sorting by EPSS or by `x_opencti_score` gives a working remediation queue.

## Dependencies

The widgets read fields that connectors have to populate first:

| Column | Needs |
|---|---|
| CVSS3 Score / Severity | Official NVD CVE connector |
| EPSS Score | Official FIRST EPSS connector |
| CISA KEV | Official CISA KEV connector |
| CWE | [`cwe-enrich-cna`](../connectors/cwe-enrich-cna) or the NVD CVE connector |

A widget showing zero on a fresh platform usually means the matching connector has not completed its
first run yet, not that the dashboard failed to import.

## Version note

These exports carry an `openCTI_version` field. Importing into a substantially different platform
version can fail or silently drop widgets. The file here was exported from the 7.x line; on a
mismatch, recreate the widgets by hand using the table above.
