# Architecture

> Historical design reference, not implemented controls. M1 is synthetic-only, rules-based and withholds all release output. Scores, independent validation, infrastructure and approval described below are not current capabilities. Use [current development guide](development-m1.md) for runnable instructions.

## Design objective

AnonFlow is a release-governance pipeline, not a simple redaction tool. It makes data minimization, contextual privacy risk, downstream usefulness, and human accountability observable before data leaves a tenant boundary.

```text
source -> intake -> quarantine -> normalize/classify -> detect -> transform
       -> independent validation + attack tests -> score -> review/gate -> release
```

## Components

| Component | Responsibility | Data boundary |
| --- | --- | --- |
| Dashboard | Dataset registration, policy selection, review, Release Card viewing | No raw content in browser unless privileged review session |
| Control-plane API | Authentication, metadata, policy/version selection, authorization, audit events | Metadata only where possible |
| Durable workflow | Retries, state transitions, approval holds, idempotency | Job references and encrypted work objects |
| Parsing workers | File checks, extraction, schema inference, OCR isolation | Raw/working zones only |
| Detection workers | Pattern, checksum, context, NER, and optional adjudication | Working zone only |
| Transform workers | Suppression, generalization, synthetic replacement, tokenization | Working and release zones |
| Validation workers | Independent scanners, protected source comparison, linkability and attack tests | Isolated validation boundary |
| Object storage | Raw, working, quarantine, and release objects | Separate prefixes/buckets and IAM roles |
| PostgreSQL | Tenants, policies, jobs, findings, approvals, signed-card metadata | No source payloads |

PostgreSQL, Redis, object storage, and workflow infrastructure are deployment dependencies. Temporal makes a release job recoverable across retries and approval waits. Redis contains only short-lived coordination state.

## Data zones and lifecycle

1. **Raw**: encrypted original. Access is restricted to ingestion/parsing workers; it expires by policy.
2. **Quarantine**: unsafe files and validation failures. Download is prohibited; a reviewer can see findings only.
3. **Working**: encrypted transient normalized fragments, detections, and intermediate transformation material. It has the shortest retention.
4. **Release**: final output, signed Release Card, policy snapshot, and evidence digest. Only the approved recipient scope can read it.

Every object is addressed by tenant, dataset, and immutable run ID. No worker accepts an object path provided directly by a client. Metadata records provenance, legal basis, residency, intended use, recipient, retention, policy version, and code/model versions.

## Pipeline stages

1. **Intake** validates content type and size, scans malware, limits archive extraction, strips active content, captures provenance, and assigns a tenant/data classification.
2. **Normalization** converts supported text, JSON, and CSV into a canonical record stream. Parser errors quarantine only the failing object and preserve no plaintext error payload.
3. **Classification and detection** apply deterministic recognizers, NER, context rules, custom tenant recognizers, and—only under explicit egress policy—LLM adjudication.
4. **Transformation** applies the selected release-mode policy. It records every action and reason at field/span level.
5. **Independent validation** uses a detector ensemble distinct from detection, scans rendered output plus filenames/metadata/OCR, and runs protected source-identifier comparisons.
6. **Risk and utility evaluation** calculates score inputs, quasi-identifier groups, relationship/linkability findings, and task-retention tests.
7. **Gate and review** evaluates hard rules. Humans may approve only a reviewable result; they cannot override `BLOCKED` critical credentials or a failed privacy test without starting a stricter rerun.
8. **Release** signs the Release Card and provides an expiring, recipient-scoped access path. The card binds content digest, policy, transformations, tests, and approval record.

## Release modes

| Mode | Primary use | Identifier behavior | Required controls |
| --- | --- | --- | --- |
| `anonymized_external` | Data licensing/external buyer | Direct IDs removed; no mapping retained; labels document-local unless safe linkage is proven | Re-identification tests, minimized quasi-identifiers, recipient/purpose-bound card |
| `pseudonymized_restricted` | Internal analysis or named controlled recipient | HMAC-derived tokens stable only within one release scope | KMS separation, dual approval for mapping access, no broad export, expiry/audit/watermarking |

Pseudonymization reduces exposure but remains potentially personal data. Anonymization is contextual: output must be validated against plausible auxiliary information and declared recipient capabilities.

## Public interfaces

- `POST /datasets`: registers a dataset with source provenance, owner, retention, jurisdiction, purpose, and recipient context.
- `POST /releases`: starts an immutable run from a dataset and versioned policy; returns a durable job identifier.
- `GET /releases/{id}/card`: returns the signed Release Card and decision, subject to authorization.
- `POST /reviews/{id}/decision`: records a reviewer decision, rationale, and evidence reference.

Connector, parser, recognizer, transformer, evaluator, and attack-simulator plugins use typed contracts and must declare supported formats, data egress behavior, version, and test fixtures.
