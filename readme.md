# AnonFlow

Secure processing foundation for a future data-intermediary release-assurance product.
The target workflow is enterprise source data → intermediary processing and qualification → explicitly approved buyer delivery.

## Current status: synthetic demo and security foundations, not production-ready

This is **not production-ready** and must not receive customer data. The current rules do not establish anonymity or data-sale rights. There is no approved release, production candidate-output API, or buyer download. Release output is withheld and approval requests fail closed. An explicitly opted-in development-only synthetic inspector can display an unqualified transformed preview and let an operator save a local demo candidate after a synthetic-data acknowledgement. That review copy is not qualification, approval, or a production export.

Implemented: bounded typed text/JSON processing, Unicode-aware original-offset spans, sensitive-field suppression, explicit development authentication, tenant/role checks, independent-review restrictions, safe error responses, and a gold-label detection evaluation CLI. The advanced browser control plane displays metadata only and has no offline success fallback. The separately enabled synthetic inspector supports small UTF-8 text/CSV/JSON/JSONL previews and prominently disclaims incomplete detection.

M2a adds strict text/CSV/JSON/JSONL intake with source accounting and record/line provenance, optional AES-GCM encrypted SQLite persistence, transactional deletion/review and authenticated audit history, and an offline RS256 JWT access-token verifier with server-bound roles/tenants. The workbench sends all formats through strict intake. Neither raw source nor candidate output is returned.

M2b adds immutable policy snapshots, explicit supplier rights/purpose/recipient gates, and tenant-scoped idempotent processing-run registration. These controls persist in the optional encrypted local store.

M3 adds a processor-only local execution step. It retains an exact transformed candidate only as an encrypted private record, while the API exposes bounded metadata such as digest, byte count and aggregate transformation ledger. A reviewer can request an aggregate-only residual scan and a non-authorizing qualification record bound to the candidate, policy, rights, recipient and purpose. There is still no candidate download/preview, approval, buyer authorization or delivery capability.

M4 adds strict contracts for pluggable detector evidence, policy-derived transformation obligations and source-free benchmark evidence. Detector outputs must be aggregate-only and explicitly mapped to the policy taxonomy; unsupported labels, coverage gaps and adapter failures fail closed. Benchmark evidence is always observational and cannot authorize a release.

M5 wires the local rules worker to sealed policy obligations. The worker records the operation it actually performed (redaction, pseudonymization or nullification) and the pipeline quarantines blocked, review-required, uncovered or mismatched transformations. Unsupported method identifiers are rejected, failed residual evidence quarantines the run, and qualification preserves known threshold violations even when other categories are unmeasured. The current rules worker only assesses PII, PAYMENT and CREDENTIAL families; full taxonomy enforcement therefore quarantines every normal rules-only run. This is intentional: a quarantined private artifact is not a candidate ready for evaluation, approval or sale. Stale local worker claims can be terminally recovered after their lease expires.

Default memory storage loses state on restart and is single-worker only. Optional SQLite is a bounded, local development adapter, not a production database or KMS. Expiry is enforced on access after at most one hour; cleanup is not secure deletion or backup erasure. The access-token verifier is a narrow identity foundation, not an OIDC login system, discovery client, refresh flow, introspection service, or complete production deployment. In `production`, only explicitly configured JWT authentication is accepted; its trusted local JWKS can be atomically rotated or revoked, and only `/health` and authenticated `/identity` are exposed. This does **not** make the application production-ready: all intake, processing, evidence, release, approval, delivery, and output routes return 503.

## Local setup

Use Python 3.12 and Node 22. Copy `.env.example` to an ignored `.env` and configure locally generated random tokens. No credentials are supplied. See the [base development guide](docs/development-m1.md), [M2a setup and limitations](docs/development-m2.md), [M2b control-plane guide](docs/development-m2b.md), [M3 private-candidate contract](docs/implementation-m3.md), [M4 evidence contract](docs/implementation-m4.md), [M5 pipeline contract](docs/implementation-m5.md), [M8 independent evidence foundations](docs/implementation-m8.md), and [M9 delivery-governance evidence](docs/implementation-m9-delivery-governance.md).

With Docker Compose installed, `docker compose up --build` serves localhost ports 3000 (web) and 8000 (API). The default stack deliberately excludes the previous unintegrated database, storage and sleeping-worker scaffolding. No existing infrastructure volumes are deleted. Those capabilities remain future work.

For a local, no-Docker synthetic upload and rules-preview walkthrough, see the
[demo guide](docs/synthetic-demo.md). The complete set of remaining product
gates is tracked in the [demo-to-product roadmap](docs/demo-to-product-roadmap.md).
The synthetic review UI's typed relationship model and strict evidence rules
are documented in the [entity graph contract](docs/entity-relationship-graph.md);
identifier replacement safety tiers are in the [format-aware pseudonym policy](docs/format-aware-pseudonyms.md).

Without Docker, run the API and Vite as described in the development guide. The API does not automatically load `.env`; explicitly export its variables for non-Compose execution.

## Gates to a commercial product

1. Real OIDC, durable isolated storage, managed keys, retention/deletion, tamper-evident audit, workload isolation and egress controls.
2. Hardened parsers with byte/field/page provenance, domain and multilingual detectors, license-reviewed model inventory.
3. Independent final-output scanning, re-identification/linkage attacks, source-specific privacy and utility qualification, expert-reviewed threshold policies.
4. Rights and recipient/purpose controls, immutable approved artifacts, independent signed approval and recipient-bound delivery.
5. Paid design-partner pilots, external security testing and measurable acceptance criteria.

Do not interpret historical architecture documents as implemented controls. [M1 contract](docs/implementation-m1.md) is historical; [M2a contract](docs/implementation-m2.md), [M2b control-plane contract](docs/implementation-m2b.md), [M3 contract](docs/implementation-m3.md), [M4 contract](docs/implementation-m4.md), [M5 contract](docs/implementation-m5.md), [M8 evidence foundations](docs/implementation-m8.md), and [M9 delivery-governance evidence](docs/implementation-m9-delivery-governance.md) describe the current increments. Docker runtime verification remains outstanding on the implementation host; native tests do not substitute for that gate.
