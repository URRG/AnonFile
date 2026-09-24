# M22 production-substrate contracts

`app.production_substrate` is a small, metadata-only contract foundation. M26
adds `app.postgres_metadata.PostgresControlPlaneMetadata`, a narrowly scoped
PostgreSQL adapter for those `ControlPlaneMetadata` values. It provides real,
tenant-scoped transactional metadata persistence with create-only/exact-version
CAS and idempotent transaction IDs after an operator explicitly applies
`services/api/migrations/001_m26_postgres_metadata.sql`.

The adapter takes only an injected connection factory; it has no
environment-driven startup configuration, DSN parsing, credential handling,
TLS verification policy, network policy, API route registration, or automatic
schema migration. Those connection and transport controls are caller-owned and
unimplemented here. PostgreSQL is a free, self-hostable open-source dependency,
but this small adapter is not a production enablement claim.

The database constraints and adapter validate bounded record shape and bind an
idempotent transaction replay to its exact canonical result. They do **not**
cryptographically authenticate database rows: a privileged database writer can
still replace one valid-shaped metadata value with another. Tamper evidence and
authenticated backups remain future work outside this slice.

## Contract guarantees

- A `TenantMetadataTransaction` is explicitly one-tenant and bounded. Its
  writes are an exact immutable tuple with unique record ids; every write must
  have an expected version for optimistic concurrency (`0` is create-only).
- `ControlPlaneMetadata` copies and freezes a deliberately narrow metadata
  vocabulary: only named control/ciphertext SHA-256 commitments (not arbitrary
  `*_digest` fields such as a reversible `email_digest`), opaque
  object/key/record/work/claim/worker references, fixed state tokens, and named
  positive counters. Arbitrary strings, nested structures, bytes, and
  unrecognized fields reject. Its optional
  `EncryptedObjectReference` carries only opaque object and key references,
  ciphertext digest, ciphertext byte count, and fixed AES-256-GCM identifier.
  It accepts neither a path/URL nor data bytes.
- `LeasedWorkerClaim` records a bounded UTC lease, strictly positive delivery
  attempt and fencing epoch, and a distinct predecessor claim for reclaim.
  This is the record shape required for leased at-least-once claim/reclaim;
  it does not itself implement scheduling or delivery.
- `validate_adapter_declaration` is exact and fail-closed.  A candidate must
  declare every required capability as literal `True`, with no omitted or
  unknown capability.  Validation does not certify a provider or enable it.

## Deliberate gaps

M26 persists metadata only; it never accepts raw/candidate bytes, plaintext,
ciphertext, or object bytes. It does not encrypt or store an object, provide a
KMS/key lifecycle claim, claim or reclaim worker work, run a queue, authenticate
any caller, or enable production traffic. There is no migration from the
development SQLite store. A later integration must independently test the
object/KMS/worker plane, authentication and authorization, network/workload
isolation, queue redelivery/fencing, observability, backups/deletion, egress,
incident recovery, and production-route controls. Passing these contract or
adapter tests is not production readiness or release authorization.
