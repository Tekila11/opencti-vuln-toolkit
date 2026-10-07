# dgssi-bulletin-connector

An OpenCTI external-import connector that scrapes [dgssi.gov.ma/fr/bulletins](https://www.dgssi.gov.ma/fr/bulletins/) and ingests DGSSI/maCERT security bulletins as `Report` objects. Each report is automatically linked to the CVEs, CPE Software observables, and internal System assets already present in OpenCTI.

---

## How it works

1. Fetches the DGSSI bulletin listing page — all 2400+ bulletin URLs are present in the static HTML
2. For each bulletin page, parses the metadata table (reference, date, risk level, impact level), the bilan paragraph, affected systems, CVE list, risks, solution, reference URLs, and PDF link
3. Creates a STIX `Report` object with the bulletin data
4. Links existing OpenCTI objects into the report:
   - **Entities tab**: `Vulnerability` objects for each CVE (from NVD connector) + `System` identity objects for internal assets running affected software (from `defectdojo-to-opencti`)
   - **Observables tab**: `Software` (CPE) observables linked to those CVEs (from `cve-cpe-mapper`)
5. Applies a risk-level label (Critique / Important / Modéré / Faible) to the report
6. For malware/threat bulletins: creates `File` observables (SHA-256 IOC hashes) and `IPv4Address` observables (C2 IPs, public only)
7. On first run: ingests all bulletins. On subsequent runs: stops once it reaches bulletins older than `last_run`, so only new or recently updated bulletins are processed

**Sync behavior**: reports are upserted via `send_stix2_bundle(update=True)`. The Report STIX ID is deterministic from `(title, published_date)`, so re-ingesting an updated bulletin overwrites the existing report without creating a duplicate.

---

## Bulletin types

### Vulnerability bulletins

| OpenCTI field | Source |
|---|---|
| Name | Bulletin title |
| Description | Bilan de la vulnérabilité paragraph |
| Content | HTML block: metadata table, bilan, affected systems, CVEs, risks, solution |
| Publication date | Date de publication |
| Report type | `Bulletin DGSSI` |
| Label | Risk level (Critique / Important / Modéré / Faible) |
| Author | DGSSI Organization |
| External references | PDF link + vendor advisory URLs |
| Entities | CVE Vulnerabilities + affected internal Systems |
| Observables | CPE Software observables |

### Malware / threat bulletins

Same structure, with:

| Entities | Malware object (created if missing) |
|---|---|
| Observables | File (SHA-256 hashes) + IPv4Address (C2 IPs, public only) |

---

## Prerequisites

Complete these steps once in OpenCTI before starting the connector.

**1. Create the DGSSI Organization**

Data > Entities > Organizations > Create — name must be exactly `DGSSI`. Used as the report author. If missing, reports are created without an author and a warning is logged.

**2. Create the report type**

Settings > Customization > Vocabularies > `report_types` > Add `Bulletin DGSSI`. Must match `DGSSI_REPORT_TYPE` exactly.

**3. Create risk labels**

Settings > Labels — create the four labels (the connector auto-creates missing ones, but pre-creating avoids the extra API call):

| Label | Color |
|---|---|
| Critique | `#d32f2f` |
| Important | `#f57c00` |
| Modéré | `#fbc02d` |
| Faible | `#388e3c` |

**4. Run dependent connectors first**

For full linking on first run:
- `connector-cve` (NVD) — CVE Vulnerability objects must exist
- `cve-cpe-mapper` — `Software → has → CVE` relationships must exist
- `defectdojo-to-opencti` + `connector-cve-affected-systems` — `System → has → CVE` relationships must exist

If these have not run yet, reports are still created but with fewer linked objects. The next DGSSI run after those connectors have populated data will upsert the reports with the missing links.

---

## Configuration

### config.yml

```yaml
opencti:
  url: 'http://opencti:8080'
  token: 'ChangeMe'

connector:
  id: 'ChangeMe'                        # generate with: uuidgen
  type: 'EXTERNAL_IMPORT'
  name: 'DGSSI Bulletin Connector'
  scope: 'report'
  duration_period: 'PT6H'
  log_level: 'info'
  auto_create_service_account: true
  auto_create_service_account_confidence_level: 80

dgssi_bulletin:
  confidence: 80
  report_type: 'Bulletin DGSSI'
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | — | OpenCTI instance URL |
| `OPENCTI_TOKEN` | — | OpenCTI API token |
| `CONNECTOR_ID` | — | Unique UUID (generate with `uuidgen`) |
| `CONNECTOR_NAME` | — | Display name in OpenCTI |
| `CONNECTOR_DURATION_PERIOD` | `PT6H` | Run interval as ISO 8601 duration |
| `CONNECTOR_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |
| `DGSSI_CONFIDENCE` | `80` | Confidence level (0–100) |
| `DGSSI_REPORT_TYPE` | `Bulletin DGSSI` | Must match the vocabulary entry |

---

## Deployment

Add to `.env`:

```bash
CONNECTOR_DGSSI_BULLETIN_ID=<uuidgen>
```

Build and start:

```bash
cd /opt/opencti/docker
docker compose build connector-dgssi-bulletin
docker compose up -d connector-dgssi-bulletin
```

Check logs:

```bash
docker compose logs -f connector-dgssi-bulletin
```

### First run

The first run scrapes all ~2400 bulletin pages at 0.3 s intervals — expect 20–30 minutes. Progress is logged every 50 bulletins:

```
Progress: 50/2492 | ingested=48 errors=2
Progress: 100/2492 | ingested=96 errors=4
...
```

### Reset state

To force a full re-import: Data > Ingestion > Connectors > DGSSI Bulletin Connector > Reset state.

---

## File structure

```
dgssi-bulletin-connector/
├── Dockerfile
├── README.md
├── config.yml.sample
├── requirements.txt          # pycti, requests, stix2, beautifulsoup4
└── src/
    ├── main.py               # entry point
    ├── connector.py          # OpenCTI ingestion, report building, object linking
    └── scraper.py            # HTTP fetching and HTML parsing of dgssi.gov.ma
```

### scraper.py

Handles all HTTP and HTML logic. Key behaviors:
- Forces HTTPS and follows redirects manually to avoid the server's HTTP downgrade redirect
- Sets `resp.encoding = "utf-8"` explicitly to fix French character encoding
- Targets Drupal's `field__item` div for section content to avoid including heading text
- Validates IP octets (0–255, no zero-padding) to reject version strings misidentified as IPs

### connector.py

Key methods:
- `_lookup_cve` — finds an existing Vulnerability by CVE ID, cached per run
- `_find_cpe_observables` — queries `Software → has → CVE` for each CVE, filters by `entity_type == software`
- `_find_affected_systems` — queries `System → has → CVE` for each CVE, filters by `entity_type == system`
- `_lookup_or_create_malware` — finds or creates a Malware object by name
- `_get_or_create_label` — finds or creates a risk-level label with the correct color
- `_ingest_bulletin` — builds the STIX bundle, sends it, then applies the label via `add_label` API call
- `_process` — orchestrates a full run with incremental date filtering

---

## Important notes

- **No DGSSI API exists**: the site has no RSS feed, JSON endpoint, or sitemap. Scraping is the only access method.
- **HTTP redirect to port 80**: individual bulletin pages redirect via HTTP 301. The scraper follows redirects manually and forces HTTPS on every hop, so it keeps working where plain HTTP egress is not permitted.
- **Label assignment via API**: labels are applied with `add_label` after the STIX bundle is sent, not inside the bundle. OpenCTI's `x_opencti_labels` STIX field takes label values, not IDs, and is unreliable for pre-existing labels.
- **CPE and System linking requires prior connector runs**: if `cve-cpe-mapper` or `defectdojo-to-opencti` have not populated their relationships yet, those tabs will be empty on first ingest and filled on the next DGSSI run.
