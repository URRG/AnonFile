# M48b1 source dataset snapshots

M48b1 stores an immutable, tenant-bound identity for an already-described
source dataset: opaque source reference, content/provenance/input-schema
digests, positive `source_byte_count`, expiry, and a canonical domain-separated
digest.
The source reference is globally unique and deliberately uses the M48a
`supplierdatasetref:v1` form. Generation zero is ACTIVE; only one append-only
terminal QUARANTINED, REVOKED, or EXPIRED fence can follow it.

Creation locks the durable active application-tenant identity first, rechecks
that fence and the PostgreSQL clock before commit, and rejects global or
cross-tenant identity collisions unless every persisted field exactly matches.
`lock_active` requires a live READ COMMITTED transaction, locks the immutable
row, then reads the latest fence in the following statement and checks DB-clock
expiry. The lock remains with the caller through its own mutation.

This is metadata only. It stores no source bytes, object location, PII, rights
assertion, API, worker, upload, or release authority.
