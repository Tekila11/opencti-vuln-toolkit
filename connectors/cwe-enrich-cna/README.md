# CWE Enrichment from CNA

OpenCTI connector that enriches every CVE with its CWE weakness classification using the NVD API.

## What it does

1. Downloads the full NVD CVE dataset in bulk (2 000 CVEs/page, ~170 requests)
2. Builds a `CVE-ID → [CWE-XX, ...]` map from NVD's CNA-assigned weaknesses
3. Paginates all Vulnerabilities in OpenCTI
4. For each CVE missing `x_opencti_cwe`, sends a STIX bundle updating it

The `x_opencti_cwe` field is used by the `cve-attack-mapper` connector (step 2 — CWE→CAPEC→ATT&CK chain) and by the *Top CWE Categories* dashboard widget.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `OPENCTI_URL` | yes | OpenCTI platform URL (e.g. `http://opencti:8080`) |
| `OPENCTI_TOKEN` | yes | Admin API token |
| `CONNECTOR_ID` | yes | UUID v4 — unique per deployment |
| `CONNECTOR_NAME` | yes | Display name in OpenCTI UI |
| `CONNECTOR_SCOPE` | yes | `vulnerability` |
| `CONNECTOR_TYPE` | yes | `EXTERNAL_IMPORT` |
| `CONNECTOR_DURATION_PERIOD` | yes | ISO 8601 duration, e.g. `P1D` (daily) |
| `CONNECTOR_LOG_LEVEL` | no | `info` (default) |
| `NVD_API_KEY` | yes | NVD API key — required for 50 req/30s rate limit |
| `CWE_BATCH_SIZE` | no | OpenCTI pagination batch size (default: `500`) |

## External dependencies

- `services.nvd.nist.gov` — HTTPS 443

## Docker build

```bash
docker compose build connector-cwe-enrich
docker compose up -d connector-cwe-enrich
```

## Files

```
cwe-enrich-cna/
├── Dockerfile
├── requirements.txt       # pycti, stix2, requests
├── config.yml.sample
└── src/
    ├── main.py            # entry point
    └── connector.py       # NVD bulk fetch + x_opencti_cwe bundle
```

## Notes

- Uses `send_stix2_bundle()` — operation counts visible in OpenCTI Works UI
- CWE labels are not added — only the structured `x_opencti_cwe` field
- Idempotent — skips CVEs that already have `x_opencti_cwe` set
- NVD values `NVD-CWE-OTHER` and `NVD-CWE-NOINFO` are ignored
- Run order: this connector should run **before** `cve-attack-mapper`
