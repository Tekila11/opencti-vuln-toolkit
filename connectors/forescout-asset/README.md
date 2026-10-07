# Forescout Asset Connector

External-import connector that pulls the live device inventory from Forescout eyeSight and creates the corresponding objects in OpenCTI.

## What it creates

For each device in Forescout:

| Object | Type | Notes |
|---|---|---|
| Device record | `System` (Identity) | Name = hostname or IP |
| IP address | `IPv4-Addr` | |
| MAC address | `MAC-Addr` | When available |
| Hostname | `Hostname` | When different from IP |
| CPE link | `System → related-to → Software` | Links to existing CPE observables |

The CPE link is the key step: once `System → related-to → Software(CPE)` and `Software → has → Vulnerability` (created by `cve-cpe-mapper`) both exist, OpenCTI shows which CVEs affect which assets.

```
Forescout device (OS: FortiOS 7.0.1)
  → System → related-to → Software(cpe:2.3:o:fortinet:fortios:7.0.1:...)
                                    ↓ (already exists via cve-cpe-mapper)
                           Software → has → CVE-XXXX
```

## Prerequisites

- Forescout **eyeExtend Open Integration Module** must be installed on the appliance
- A dedicated API user created in Forescout (`System Settings → User Management`)
- The connector host IP must be whitelisted in Forescout (`System Settings → eyeExtend → Open Integration Module`)
- CPE connector must have run at least once (provides the Software observables to link against)

## Configuration

### `.env` (docker-compose)

```dotenv
CONNECTOR_FORESCOUT_ID=<uuidgen>
FORESCOUT_HOST=192.168.x.x          # Forescout appliance IP or FQDN
FORESCOUT_USERNAME=opencti_api      # Web API user (NOT the DEX user)
FORESCOUT_PASSWORD=<password>
```

### docker-compose service

```yaml
connector-forescout-assets:
  build: ../connectors/forescout-asset-connector
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=${CONNECTOR_FORESCOUT_ID}
    - CONNECTOR_NAME=Forescout Asset Import
    - CONNECTOR_SCOPE=identity
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_DURATION_PERIOD=P1D
    - CONNECTOR_CONFIDENCE_LEVEL=60
    - CONNECTOR_LOG_LEVEL=info
    - FORESCOUT_HOST=${FORESCOUT_HOST}
    - FORESCOUT_USERNAME=${FORESCOUT_USERNAME}
    - FORESCOUT_PASSWORD=${FORESCOUT_PASSWORD}
    - FORESCOUT_VERIFY_TLS=false
    - FORESCOUT_HOST_FIELDS=hostname,vendor,cl_vendor,cl_os,cl_patchlevel,cl_category,cl_model
  restart: always
  depends_on:
    opencti:
      condition: service_healthy
```

### `FORESCOUT_HOST_FIELDS`

Comma-separated list of Forescout property names to request per host. Defaults:

| Field | Mapped to |
|---|---|
| `hostname` | System name + Hostname observable |
| `cl_vendor` | CPE vendor matching |
| `cl_os` | CPE product matching |
| `cl_patchlevel` | CPE version matching |
| `cl_category` | System description |
| `cl_model` | System description |
| `vendor` | Fallback vendor |

Adjust to match the actual property names configured in your Forescout deployment.

## CPE matching

Forescout provides free-text OS/vendor strings (e.g., `"Windows 10 Enterprise"`, `"FortiOS"`).
The connector normalizes these to lowercase + underscores and uses a substring `contains` search against the `cpe` field of existing Software observables.

Only **firmware/OS CPEs** (`cpe:2.3:o:...`) and **application CPEs** (`cpe:2.3:a:...`) are matched — hardware CPEs (`cpe:2.3:h:...`) are not imported by the CPE connector and carry no version info.

CPE matching is fuzzy by design. Forescout OS names do not follow NVD naming conventions exactly — some manual normalization may be needed for unusual vendors.

## Deploy

```bash
# Generate a UUID for the connector
uuidgen   # copy to CONNECTOR_FORESCOUT_ID in .env

# Fill in Forescout credentials in .env

# Build and start
cd openCTI/docker
docker compose build connector-forescout-assets
docker compose up -d connector-forescout-assets

# Check logs
docker compose logs -f connector-forescout-assets
```

## Known limitations

- **No hardware CPE matching** — vulnerability linking only works for devices with a detectable OS/firmware version.
- **CPE naming inconsistencies** — NVD CPE strings are created by analysts, not vendors. Fuzzy matching helps but won't catch everything.
- **Internal IPs** — do NOT configure Kaspersky enrichment to auto-enrich these IPs; internal RFC1918 addresses return `gray` (unknown zone) and leak your network topology.
- **Session token TTL** — the connector handles automatic re-auth when the token expires (401 response).
- **Forescout API docs are paywalled** — behind Salesforce/Okta SSO; field names may differ between appliance versions.
