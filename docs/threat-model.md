# Threat model

> Historical design reference, not implemented controls. M1 is synthetic-only, rules-based and withholds all release output. Scores, independent validation, infrastructure and approval described below are not current capabilities. Use [current development guide](development-m1.md) for runnable instructions.

## Assets and trust boundaries

Protected assets include source records, mapping material, customer-specific recognizers, release artifacts, encryption/signing keys, provenance, reviewer decisions, and audit records. The principal boundaries are tenant-to-tenant, raw-to-working/release zones, worker-to-control plane, privileged reviewer-to-standard user, and customer VPC-to-external services.

## Threats and required controls

| Threat | Example | Required control |
| --- | --- | --- |
| Residual disclosure | NER misses a nickname in free text | Independent detector ensemble, protected source comparison, review gate, canary fixtures |
| Re-identification | Buyer joins age/ZIP/job records with public data | Quasi-identifier analysis, suppression/generalization, contextual attack harness, recipient-bound policy |
| Cross-release linkage | Same token appears in separate buyer datasets | Token scope is tenant + release + entity type; external labels are document-local by default |
| Mapping abuse | Insider requests original identity | Separate KMS-protected mapping store, dual authorization, short expiry, immutable access log |
| Credential leakage | API token reaches released text | Secret recognizers, `BLOCKED` decision, remediation integration, no output download |
| Cross-tenant access | Object path guessing or worker bug | Tenant-scoped IAM, opaque IDs, authorization checks, per-tenant keys, isolation tests |
| Malicious files | Archive bomb, macro, malformed PDF | MIME/content validation, sandboxed parsing, malware scan, archive/time/resource limits |
| Prompt injection | PDF instructs an LLM to exfiltrate text | Treat content as data, isolate OCR, prohibit model tools, local inference/explicit egress only |
| Observability leakage | Raw text in exception/traces | Structured redacted logs, content-free telemetry, secret scanning of logs, access controls |
| Supply-chain compromise | Compromised model/parser image | Pinned digests, SBOM, signature verification, vulnerability scanning, minimal runtime images |
| Release tampering | Artifact swapped after approval | Content hashes, signed Release Cards, immutable storage/versioning, expiring links |

## Security requirements

- Encrypt data in transit and at rest. Production uses customer-managed KMS keys with rotation and distinct keys for raw, release, mapping, and signing operations.
- Use OIDC, MFA at the identity provider, RBAC plus tenant/sensitivity/purpose attributes, least-privilege service accounts, and no shared production credentials.
- Keep raw source content out of logs, metrics, tracing, dashboards, error trackers, analytics, and model-training data.
- Block unrestricted outbound network access from parser/detection workers. Cloud model invocation requires policy approval, an allowlisted endpoint, and a recorded egress event.
- Retain audit events append-only with actor, action, resource, policy/version, decision, request correlation ID, and timestamp.
- Test data isolation, authorization, secret detection, prompt injection, malformed input, release tampering, and re-identification in continuous integration.

## Incident handling

On suspected exposure: immediately revoke release links and credentials, freeze related jobs and mappings, preserve immutable audit evidence, determine affected artifacts/recipients, and invoke the customer incident process. Do not delete evidence or overwrite impacted releases. Notification and legal decisions remain with the customer’s incident/legal authority.
