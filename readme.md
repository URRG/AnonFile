# AnonFlow

Self-hosted, policy-driven anonymization and release governance for enterprise data.

AnonFlow detects sensitive information, applies a release-specific transformation,
validates the output, and emits a signed Release Card containing privacy risk,
utility/legibility, subjectivity, sensitivity, and eligibility evidence.

## Quick start

```sh
cp .env.example .env
make up
```

Open the dashboard at `http://localhost:3000` and the API documentation at
`http://localhost:8000/docs`.

For local development without Docker:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r services/api/requirements-dev.txt
PYTHONPATH=services/api .venv/bin/uvicorn app.main:app --reload

cd apps/web
npm install
npm run dev
```

## Release modes

- **External anonymized release:** the default for external buyers; no retained
  identifier mapping and strict fail-closed validation.
- **Restricted pseudonymized processing:** preserves stable entities only within
  one release, and requires named-recipient, access-control, expiry, and audit
  controls.

Scores are engineering evidence, never a legal certification of anonymity or
regulatory compliance. Read the full [documentation](docs/README.md) before
processing customer data.

## Development checks

```sh
PYTHONPATH=services/api .venv/bin/python -m pytest -q services/api/tests
cd apps/web && npm run build
```

## License

Apache-2.0. See [LICENSE](LICENSE).
