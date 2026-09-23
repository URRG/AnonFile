# M18: independent release-authorization request foundation

M18 adds a deliberately narrow, development-only control plane for an
independent human authorization workflow. It is not a release mechanism. No
route returns source/candidate bytes, an artifact location, recipient value,
credential, token, export, download or delivery instruction.

## Admission and scope

`POST /release-cases/{case_id}/release-authorization-requests` accepts no
body and requires an idempotency key. The server derives every binding from a
live M14 release case and its live M15 decision. The only M15 state eligible
to become a pending authorization request is the complete-evidence holding:
`INSUFFICIENT_EVIDENCE` with exactly
`INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED`. It is M15's intentionally
non-authorizing representation of a clean privacy assessment. Quarantine,
missing/stale evidence, altered scope, expired controls and ambiguous decision
selection all fail closed.

The request is Ed25519-signed by a tenant-scoped server authority and binds
the case and privacy-decision identifiers/digests plus a digest of their exact
canonical scope. Its short expiry is bounded by the case, privacy decision,
authorization authority and one hour. Request ids are tenant-secret-derived
from case/idempotency key. A request remains explicitly pending until two
separate human roles have signed; even then its posture remains
`NO_RELEASE_OR_DELIVERY_AUTHORIZATION`.

## Human approvals

`POST /release-authorization-requests/{request_id}/approvals` accepts one
complete Ed25519 approval envelope. It is verified against server-owned
configuration, and must bind the request digest, scope digest, case id and
processing-run id exactly. The caller identity must equal the signed approver,
must differ from the request creator, and may record only one approval. The
two required roles are `privacy_reviewer` and `release_authorizer`; a config
cannot assign both roles to one person, and a request cannot contain duplicate
subjects or roles. Reposting the exact same approval envelope is idempotent;
any reuse of its identifier with a changed signed scope conflicts. In development, every configured approver must also be an
explicit, separate `reviewer` dev principal at application startup.

Requests and approvals are individual immutable control records with signed
audit events. Run/case invalidation recursively tombstones dependent requests
and approvals. Every read and approval re-verifies the live M14/M15 basis,
authority expiry, signatures and exact scope; no stale request survives as an
actionable control.

## Configuration

`ANONFLOW_RELEASE_AUTHORIZATION_AUTHORITIES` is optional. If it is absent the
routes fail closed. Each tenant has one object with a 32-byte base64 Ed25519
private key and exactly distinct public-key approvers, including both roles.
See `.env.example` for the exact JSON shape. This is an in-process local
development boundary, not a production identity, HSM/KMS, signing ceremony,
recipient-delivery or legal-approval system.
