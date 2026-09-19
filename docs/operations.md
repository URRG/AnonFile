# Operations and deployment

> Historical design reference, not implemented controls. M1 is synthetic-only, rules-based and withholds all release output. Scores, independent validation, infrastructure and approval described below are not current capabilities. Use [current development guide](development-m1.md) for runnable instructions.

## Local development

Copy `.env.example` to `.env`, set unique local secrets, then run `make up`. `make down` stops the stack while preserving volumes; use Docker volume management deliberately if a full local data wipe is required. Do not use local defaults with customer data.

The Compose stack has PostgreSQL, Redis, Temporal, MinIO, API, worker, and web services. The initial API/web implementations supply their own Dockerfiles. Until they exist, Compose build commands will fail by design rather than silently running an incomplete stack.

## Production baseline

Deploy into a customer-controlled Kubernetes cluster/VPC with:

- Separate namespaces/service accounts for control plane, parsing, detection, validation, and reviewer services.
- Managed PostgreSQL, object storage with versioning and lifecycle policy, managed Redis, and a durable workflow backend.
- Customer-managed KMS/HSM keys, workload identity, OIDC integration, network policies, private endpoints, and default-deny egress.
- A dedicated validation worker pool with no release-write permission; it can only emit signed evidence.
- Horizontal scaling for stateless workers; queue depth, execution latency, error rate, validation failures, and release-gate rate as primary metrics.

Do not expose databases, object-store consoles, Temporal UI, or internal worker endpoints publicly. Terminate TLS at an approved ingress and enforce request-size/rate limits.

## Secrets and configuration

Use a deployment secret manager, never plain environment files, for database, object-storage, signing, and OIDC values. Rotate secrets on deployment, compromise, or schedule. Separate development, staging, and production accounts/buckets/keys. `ALLOW_CLOUD_LLM` remains false unless the active policy explicitly allows egress.

## Backup, retention, and deletion

Back up metadata, policies, audit events, and release artifacts according to customer recovery objectives. Encrypt backups with distinct keys and regularly restore-test them. Configure lifecycle expiration independently for raw, working, quarantine, mappings, and releases; legal holds override deletion. Deletion requests must produce an audit event and include all derivatives/mappings within scope.

## Release operations

Before enabling a policy for production, review its entity coverage, confidence thresholds, transformations, attack tests, recipient restrictions, utility acceptance criteria, and benchmark evidence. Monitor drift by source type and entity type; unexpected detector disagreement or increased review/block rates trigger policy review. Re-run releases after parser, recognizer, transformation, policy, or input changes—never alter an approved artifact in place.

## Readiness checklist

- OIDC, tenant authorization, and least-privilege service identities are tested.
- Customer KMS keys and key rotation are configured.
- Egress is denied by default and cloud-model policy is reviewed.
- Object-store lifecycle/versioning, backups, recovery, and audit retention are verified.
- Supported formats/locales have published benchmark coverage and synthetic adversarial fixtures.
- Incident contacts, release approvers, and data-retention owners are assigned.
- A privacy/security review is completed for the intended jurisdiction and data use.
