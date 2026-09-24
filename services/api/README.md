# Development API

Synthetic data only. Run a single worker. See [development guide](../../docs/development-m1.md) for configuration and evaluation.

From this directory: `python -m pip install -r requirements-dev.txt`, `python -m pytest`, `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.

`ANONFLOW_DEV_PRINCIPALS` must be an explicit JSON array of token/subject/tenant/roles. Tokens require at least 32 characters. Empty configuration closes protected routes with 503. No default credential exists. In `development`, static development credentials are available only when explicitly selected. In `production`, `ANONFLOW_AUTH_MODE=jwt` plus the pinned-JWKS configuration documented in [M20](../../docs/implementation-m20-oidc-identity.md) is mandatory; static credentials are rejected. This identity foundation does not make this development API production-ready.

Dataset intake/listing requires processor role. Release/card reads require processor or reviewer in the same tenant. Review rejection requires an independent reviewer. Approval always returns 409. Buyers have no data routes. Responses contain no processing output. Storage and review snapshots are bounded process memory, not a durable audit ledger.
