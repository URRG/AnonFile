# M22 production-substrate contracts

`app.production_substrate` is a small, metadata-only contract foundation for a
future production adapter.  It introduces no adapter implementation, storage
configuration, secrets, queue connection, worker process, API route, or
production-route enablement.

## Contract guarantees

- A `TenantMetadataTransaction` is explicitly one-tenant, bounded, has unique
  record writes, and requires expected versions for optimistic concurrency.
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

No M22 code commits a transaction, encrypts or stores an object, claims work,
reclaims a lease, authenticates a worker, or proves multi-process atomicity.
There is no migration from the development SQLite store and no production
configuration.  A later integration must independently test a real adapter's
atomic tenant isolation, database/object-store durability, KMS/key rotation,
network and workload isolation, queue redelivery and fencing behavior,
observability, backups/deletion, egress, and incident recovery.  Passing these
shape validators is not production readiness or release authorization.
