# AnonFlow

Secure processing foundation for a future data-intermediary release-assurance product.
The target workflow is enterprise source data → intermediary processing and qualification → explicitly approved buyer delivery.

## Current status: M2b, synthetic development only

This is **not production-ready** and must not receive customer data. The current rules do not establish anonymity or data-sale rights. There is no approved release, candidate-output API, buyer download, signature assurance or invented privacy/utility score. All release output is withheld; approval requests fail closed.

Implemented: bounded typed text/JSON processing, Unicode-aware original-offset spans, sensitive-field suppression, explicit development authentication, tenant/role checks, independent-review restrictions, safe error responses, and a gold-label detection evaluation CLI. The browser displays metadata only and has no offline success fallback.

M2a adds strict text/CSV/JSON/JSONL intake with source accounting and record/line provenance, optional AES-GCM encrypted SQLite persistence, transactional deletion/review and authenticated audit history, and an offline RS256 JWT access-token verifier with server-bound roles/tenants. The workbench sends all formats through strict intake. Neither raw source nor candidate output is returned.

M2b adds immutable policy snapshots, explicit supplier rights/purpose/recipient gates, and tenant-scoped idempotent processing-run registration. These controls persist in the optional encrypted local store. Runs remain `REGISTERED`: there is no worker transition, candidate artifact, evaluation pass, buyer authorization or delivery capability.

Default memory storage loses state on restart and is single-worker only. Optional SQLite is a bounded, local development adapter, not a production database or KMS. Expiry is enforced on access after at most one hour; cleanup is not secure deletion or backup erasure. JWT verification is not an OIDC login system, online revocation or automatic key rotation. Set `ANONFLOW_ENV` to anything other than `development` and startup is refused. Synthetic-use restrictions are an operational prerequisite, not a classifier that can recognize real data.

## Local setup

Use Python 3.12 and Node 22. Copy `.env.example` to an ignored `.env` and configure locally generated random tokens. No credentials are supplied. See the [base development guide](docs/development-m1.md), [M2a setup and limitations](docs/development-m2.md), and [M2b control-plane guide](docs/development-m2b.md).

With Docker Compose installed, `docker compose up --build` serves localhost ports 3000 (web) and 8000 (API). The default stack deliberately excludes the previous unintegrated database, storage and sleeping-worker scaffolding. No existing infrastructure volumes are deleted. Those capabilities remain future work.

Without Docker, run the API and Vite as described in the development guide. The API does not automatically load `.env`; explicitly export its variables for non-Compose execution.

## Gates to a commercial product

1. Real OIDC, durable isolated storage, managed keys, retention/deletion, tamper-evident audit, workload isolation and egress controls.
2. Hardened parsers with byte/field/page provenance, domain and multilingual detectors, license-reviewed model inventory.
3. Independent final-output scanning, re-identification/linkage attacks, source-specific privacy and utility qualification, expert-reviewed threshold policies.
4. Rights and recipient/purpose controls, immutable approved artifacts, independent signed approval and recipient-bound delivery.
5. Paid design-partner pilots, external security testing and measurable acceptance criteria.

Do not interpret historical architecture documents as implemented controls. [M1 contract](docs/implementation-m1.md) is historical; [M2a contract](docs/implementation-m2.md), [M2b control-plane contract](docs/implementation-m2b.md), and their development guides describe the current increments. Docker runtime verification remains outstanding on the implementation host; native tests do not substitute for that gate.
