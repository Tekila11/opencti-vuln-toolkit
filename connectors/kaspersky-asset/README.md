# Kaspersky Asset Connector

External-import connector that pulls the managed device inventory from Kaspersky Security Center
(KSC) 15.x and creates the matching asset objects in OpenCTI.

KSC already knows every managed endpoint and the software installed on it. This connector turns
that inventory into OpenCTI entities so vulnerability data can be tied to real hosts instead of
floating free as CVE records.

## What it creates

For each managed device:

| Object | Type | Source |
|---|---|---|
| `System` | Identity | The managed endpoint |
| `IPv4-Addr` | Observable | Device IP, decoded from the KSC integer representation |
| `System → related-to → IPv4-Addr` | Relationship | Links the host to its address |
| `System → related-to → Software` | Relationship | Installed app matched to an existing CPE observable |

The connector does not create `Software` observables. It matches installed applications against CPE
observables already present in OpenCTI (from the official CPE connector) and links only what it
finds. Matching covers application CPEs (`cpe:2.3:a:...`) and OS or firmware CPEs
(`cpe:2.3:o:...`), keyed on publisher, display name and version.

## Why it matters

Combined with [`cve-cpe-mapper`](../cve-cpe-mapper), this completes the exposure chain:

```
System ──related-to──▶ Software (CPE) ──has──▶ Vulnerability (CVE)
```

Once both sides exist, a CVE in OpenCTI can be traced to the hosts actually running the affected
software, which is what [`cve-affected-systems`](../cve-affected-systems) aggregates into
`x_opencti_affected_systems`.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | yes | | OpenCTI platform URL |
| `OPENCTI_TOKEN` | yes | | OpenCTI API token |
| `CONNECTOR_ID` | yes | | Unique UUID for this connector (`uuidgen`) |
| `CONNECTOR_NAME` | no | | Display name in the OpenCTI UI |
| `CONNECTOR_TYPE` | yes | | `EXTERNAL_IMPORT` |
| `CONNECTOR_DURATION_PERIOD` | no | `P1D` | ISO 8601 interval between runs |
| `KSC_HOST` | yes | | KSC server hostname or IP |
| `KSC_PORT` | no | `13299` | KSC Open API port |
| `KSC_USERNAME` | yes | | KSC service account |
| `KSC_PASSWORD` | yes | | KSC service account password |

The KSC account needs read access to the managed device inventory. A read-only service account is
sufficient; this connector never writes to KSC.

## Deployment

```yaml
  connector-kaspersky-asset:
    build: ./connectors/kaspersky-asset
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_KASPERSKY_ASSET_ID}
      - CONNECTOR_NAME=Kaspersky Asset Connector
      - CONNECTOR_SCOPE=identity
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_DURATION_PERIOD=P1D
      - CONNECTOR_LOG_LEVEL=info
      - KSC_HOST=${KSC_HOST}
      - KSC_PORT=13299
      - KSC_USERNAME=${KSC_USERNAME}
      - KSC_PASSWORD=${KSC_PASSWORD}
    restart: always
    depends_on:
      opencti:
        condition: service_healthy
```

```bash
docker compose up -d connector-kaspersky-asset
docker compose logs -f connector-kaspersky-asset
```

## Notes

The KSC Open API returns IP addresses as signed 32-bit integers. The connector converts these to
dotted-quad form before creating the `IPv4-Addr` observable.

Objects are sent in batched STIX bundles rather than one per device, which keeps the worker queue
manageable on estates of a few thousand hosts.

To force a run instead of waiting out `CONNECTOR_DURATION_PERIOD`, reset the connector state from
**Data → Connectors** in the OpenCTI UI.

If no `Software` relationships appear, confirm the CPE connector has populated Software observables
first. This connector can only link against CPEs that already exist.
