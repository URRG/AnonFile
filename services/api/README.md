# Development API

Synthetic data only. Run a single worker. See [development guide](../../docs/development-m1.md) for configuration and evaluation.

From this directory: `python -m pip install -r requirements-dev.txt`, `python -m pytest`, `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.

`ANONFLOW_DEV_PRINCIPALS` must be an explicit JSON array of token/subject/tenant/roles. Tokens require at least 32 characters. Empty configuration closes protected routes with 503. No default credential exists. `ANONFLOW_ENV=development` is the only supported environment. Never substitute this mechanism for production authentication.

Dataset intake/listing requires processor role. Release/card reads require processor or reviewer in the same tenant. Review rejection requires an independent reviewer. Approval always returns 409. Buyers have no data routes. Responses contain no processing output. Storage and review snapshots are bounded process memory, not a durable audit ledger.
