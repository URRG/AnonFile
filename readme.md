# AnonFlow

Secure processing foundation for a future data-intermediary release-assurance product.
The target workflow is enterprise source data → intermediary processing and qualification → explicitly approved buyer delivery.

## Current status: M1, synthetic development only

This is **not production-ready** and must not receive customer data. The current rules do not establish anonymity or data-sale rights. There is no approved release, candidate-output API, buyer download, signature assurance or invented privacy/utility score. All release output is withheld; approval requests fail closed.

Implemented: bounded typed text/JSON processing, Unicode-aware original-offset spans, sensitive-field suppression, explicit development authentication, tenant/role checks, independent-review restrictions, safe error responses, and a gold-label detection evaluation CLI. The browser displays metadata only and has no offline success fallback.

Process-local storage loses state on restart and is single-worker only. Expiry is enforced on access after at most one hour; it is not secure deletion. Static development tokens are not OIDC. Set `ANONFLOW_ENV` to anything other than `development` and startup is refused. Synthetic-use restrictions are an operational prerequisite, not a classifier that can recognize real data.

## Local setup

Use Python 3.12 and Node 22. Copy `.env.example` to an ignored `.env` and configure locally generated random tokens. No credentials are supplied. See [development guide](docs/development-m1.md) for configuration, tests and evaluation.

With Docker Compose installed, `docker compose up --build` serves localhost ports 3000 (web) and 8000 (API). The default stack deliberately excludes the previous unintegrated database, storage and sleeping-worker scaffolding. No existing infrastructure volumes are deleted. Those capabilities remain future work.

Without Docker, run the API and Vite as described in the development guide. The API does not automatically load `.env`; explicitly export its variables for non-Compose execution.

## Gates to a commercial product

1. Real OIDC, durable isolated storage, managed keys, retention/deletion, tamper-evident audit, workload isolation and egress controls.
2. Hardened parsers with byte/field/page provenance, domain and multilingual detectors, license-reviewed model inventory.
3. Independent final-output scanning, re-identification/linkage attacks, source-specific privacy and utility qualification, expert-reviewed threshold policies.
4. Rights and recipient/purpose controls, immutable approved artifacts, independent signed approval and recipient-bound delivery.
5. Paid design-partner pilots, external security testing and measurable acceptance criteria.

Do not interpret historical architecture documents as implemented controls. [M1 contract and ownership](docs/implementation-m1.md) describes this milestone; [development guide](docs/development-m1.md) documents current behavior.
