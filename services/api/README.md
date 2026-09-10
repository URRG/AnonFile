# AnonFlow API

The demo control plane for a policy-driven anonymisation release workflow. It deliberately uses in-memory persistence so it is safe to run locally and easy to replace with production repositories later.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000/docs` for the interactive API.

## Workflow

1. `POST /datasets` with text or records and declared release context.
2. `POST /releases` with its dataset ID and a `release_mode`.
3. Inspect `GET /releases/{id}` and its signed-style release card at `/releases/{id}/card`.
4. For `REVIEW_REQUIRED`, submit `POST /reviews/{id}/decision`.

`external_anonymized` performs irreversible, document-local labels. `restricted_pseudonymized` uses deterministic tokens scoped to a release; this is **not** anonymous data and is deliberately marked restricted.

## Design decisions

See the repository-level `docs/DECISIONS.md` for production decisions. This service demonstrates the API contract and safety gates, not legal compliance. It has no database, KMS, authentication, malware scanning, OCR, or production-grade entity recognition. Those boundaries are exposed by the models and should be backed by dedicated adapters before handling customer data.
