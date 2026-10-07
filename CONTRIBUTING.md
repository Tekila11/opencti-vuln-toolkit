# Contributing

Issues and pull requests are welcome.

## Before opening a pull request

- Keep each connector self-contained. A connector directory holds its own `Dockerfile`,
  `requirements.txt`, `config.yml.sample` and `README.md`, and does not import from its siblings.
- Configuration comes from environment variables or `config.yml`, read through
  `get_config_variable`. Never hardcode a URL, token or API key, not even a placeholder one.
- New or changed behaviour belongs in the component's own `README.md`.
- Keep runs idempotent. A connector should skip entities whose computed value already matches, and a
  pipeline script should record progress in `state.json` so a re-run does not duplicate findings.

## Respecting the data model

Asset exposure is `Software → has → Vulnerability`. The reverse direction is rejected by the
OpenCTI API and will not populate the UI. See [`docs/architecture.md`](docs/architecture.md) before
adding relationships.

## Secrets

Never commit a real token, password or API key. `.gitignore` excludes `.env` and `config.yml`;
only `.env.example` and `config.yml.sample` are tracked, and they contain placeholders only.

If you do commit a credential by accident, rotate it first and rewrite history second. Rotation is
what actually fixes the exposure.

## pycti compatibility

`pycti` tracks the OpenCTI platform release, so the pin in each `requirements.txt` has to match the
version you run. When upgrading, move the components together and watch for these 7.x filter rules:

```python
filters = {
    "mode": "and",
    "filters": [{"key": ["modified"], "values": [since], "operator": "gt", "mode": "or"}],
    "filterGroups": [],
}
```

`key` must be a list, every filter item needs its own `mode`, and `withPagination=True` returns
`{"entities": [...], "pagination": {...}}` rather than a bare list.

## Testing a change

There is no unit test suite. Verify against a real OpenCTI instance:

```bash
docker compose build connector-<name>
docker compose up -d connector-<name>
docker compose logs -f connector-<name>
```

Reset the connector state from **Data → Connectors** to force an immediate run, and confirm the
field or relationship you expect actually appears on an entity in the UI.
