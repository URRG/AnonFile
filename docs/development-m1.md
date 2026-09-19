# M1 developer guide

Only synthetic/local testing is authorized by this milestone. Never load enterprise source data into this workbench. Production deployment, anonymity qualification and buyer delivery are not implemented.

## Authentication setup

Generate a separate token for each principal using `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Configure `ANONFLOW_DEV_PRINCIPALS` as a JSON array with objects containing `token`, `subject`, `tenant`, and `roles`. Allowed roles: `processor`, `reviewer`, `buyer`. Token strings must be unique and at least 32 characters. Keep generated tokens in local environment variables or ignored `.env`, never in source control. Processor and reviewer must have different authenticated subjects. Empty configuration makes protected routes return 503.

For Compose, populate `.env` and run `docker compose up --build`. Ports bind to loopback. For direct execution, set the environment variables explicitly (the Python service does not load `.env`), plus `WEB_ORIGIN=http://localhost:5173`, then run:

```text
cd services/api
python -m pip install -r requirements-dev.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```text
cd apps/web
npm ci --ignore-scripts
npm run dev -- --host 127.0.0.1
```

Open the localhost UI and supply the processor token. Changing request fields clears earlier evidence. The UI submits dataset metadata including intended recipient, then requests processing. Metadata is not a rights assertion or an enforced buyer contract. All output remains withheld. Intended-use/recipient authorization comes in a later milestone.

## Tests

From `services/api`: `python -m pytest -q`. From `apps/web`: `npm test` and `npm run build`. Container test targets: `make api-test`, `make web-test` (Docker required). CI executes Python and client tests plus the TypeScript/Vite build. Tests use only synthetic fixtures, no cloud model or customer data.

## Independent gold-label evaluation

From `services/api`:

```text
python -m app.evaluate --gold tests/fixtures/evaluation/synthetic-gold.jsonl --baseline rules-v1
```

See the fixture README for exact filenames/schema and supplied-prediction evaluation. Use separately annotated gold labels, frozen before examining detector output. Gold and predictions use half-open Unicode code-point offsets against original text. Reports distinguish strict exact-match and relaxed same-category overlap. They report precision, recall, F1, counts by entity and documents with missed gold spans, not a fabricated universal privacy score. Empty denominators remain null. Input/code hashes support internal reproducibility, not authenticity, representativeness or a cryptographic signature. Reports contain no raw text, record identifiers or paths, but remain internal sensitive evidence.

The bundled synthetic examples are regression fixtures, not a qualification benchmark. Detection metrics do not establish final-output leakage, resistance to linkage, utility retention, dataset rights or legal anonymity. Reports cannot approve a release. Independent final-output scanning and a source-specific holdout qualification protocol are future work.

## Limits and known gaps

- One nonempty text input OR a nonempty list of objects, not both; at most 2 MB UTF-8 processing input, 10,000 records, depth 32 and bounded nodes. The HTTP body has a separate 2.1 MB cap, so JSON escaping/metadata can reduce the effective accepted payload.
- Immutable-original spans and overlap union prevent replacement offsets from skipping known hits. Recognized sensitive fields suppress descendants; numeric sensitive values become null. Sensitive values in object keys are rejected instead of collision-prone renaming. This is not comprehensive semantic detection.
- Restricted-mode aliases are local, noncryptographic and not a production tokenization vault. Numbers may be unvalidated candidates. Learned names, medical/business meaning, indirect identification and relationships remain incomplete.
- Development storage is bounded and expires on access, with no secure-erasure or durable-audit claim. Crash recovery, cross-worker consistency, at-rest encryption, OIDC, rate controls and production isolation remain unimplemented.
- Findings are aggregate metadata. They and supplied dataset names/metadata still require access control; do not populate metadata fields with source secrets.
- No endpoint retains or returns processing output. Rejection creates a new in-memory card revision; approval is prohibited. No self-review bypass, customer export or automatic pass exists.
