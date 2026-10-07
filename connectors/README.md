# Connectors

Eight custom OpenCTI connectors. All register as `EXTERNAL_IMPORT` and schedule their own runs
from `CONNECTOR_DURATION_PERIOD`, looping on an interval rather than reacting to a single entity.
Each one wraps its work in `helper.api.work.initiate_work` / `to_processed` so progress shows up
under **Data → Connectors** in the UI.

## Enrichment connectors

These read what is already in OpenCTI (plus public feeds) and write derived fields or
relationships back.

| Connector | Writes | Default period |
|---|---|---|
| [`cwe-enrich-cna`](cwe-enrich-cna) | `x_opencti_cwe` from NVD CNA-assigned weaknesses | `P1D` |
| [`cve-cpe-mapper`](cve-cpe-mapper) | `Software → has → Vulnerability` from NVD CPE configurations | `P1D` |
| [`cve-attack-mapper`](cve-attack-mapper) | `CVE → related-to → ATT&CK Technique` | `P1D` (sample config uses `P7D`) |
| [`cve-score`](cve-score) | `x_opencti_score` (0–100) | `P1D` |
| [`cve-affected-systems`](cve-affected-systems) | `x_opencti_affected_systems` | `PT6H` |

Order matters on a cold platform. `cwe-enrich-cna` has to populate `x_opencti_cwe` before
`cve-attack-mapper` can walk the CWE→CAPEC→ATT&CK chain, and `cve-attack-mapper` has to create its
relationships before `cve-score` can weigh the ATT&CK tactic and threat-actor factors. On a steady
schedule they converge on their own after a cycle or two.

Note that the official NVD CVE connector also populates `x_opencti_cwe` in the same format. If you
run it, `cwe-enrich-cna` is largely redundant; verify against your own data before deploying both.

## Asset and report import connectors

These bring in data OpenCTI has no other source for.

| Connector | Source | Creates | Default period |
|---|---|---|---|
| [`forescout-asset`](forescout-asset) | Forescout eyeSight | `System`, `IPv4-Addr`, `Software` | `P1D` |
| [`kaspersky-asset`](kaspersky-asset) | Kaspersky Security Center 15.x | `System`, `IPv4-Addr`, `Software` | `P1D` |
| [`dgssi-bulletin`](dgssi-bulletin) | DGSSI / maCERT bulletins | `Report`, linked to CVEs and assets | `PT6H` |

## Deployment

Add the connector to your OpenCTI `docker-compose.yml`, pointing `build` at its directory:

```yaml
  connector-cve-score:
    build: ./connectors/cve-score
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CVE_SCORE_ID}
      - CONNECTOR_NAME=CVE Contextual Score
      - CONNECTOR_SCOPE=vulnerability
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_DURATION_PERIOD=PT6H
      - CONNECTOR_LOG_LEVEL=info
    restart: always
    depends_on:
      opencti:
        condition: service_healthy
```

Generate a distinct `CONNECTOR_ID` for each one:

```bash
uuidgen
```

Then start it and watch the first cycle:

```bash
docker compose up -d connector-cve-score
docker compose logs -f connector-cve-score
```

A connector that restarts in a loop is almost always a missing, malformed or duplicated
`CONNECTOR_ID`. Check that before anything else.

## Development notes

Connectors that call the NVD API want an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key),
which raises the rate limit from 5 to 50 requests per 30 seconds. Without one, a full pass over the
CVE corpus takes hours.

To trigger an immediate run instead of waiting out the period, reset the connector state from
**Data → Connectors** in the OpenCTI UI.

The `pycti` pin in each `requirements.txt` tracks the OpenCTI platform release and has to match the
version you run. Upgrade them together.

`pycti` 7.x changed the filter format in ways worth knowing when editing these:

```python
filters = {
    "mode": "and",
    "filters": [{"key": ["modified"], "values": [since], "operator": "gt", "mode": "or"}],
    "filterGroups": [],
}
```

`key` must be a list, each filter item needs its own `mode`, and `withPagination=True` returns
`{"entities": [...], "pagination": {...}}` rather than a bare list.
