# M25 repository audit-head commitment

`DevelopmentStore.audit_head(tenant)` returns an immutable, source-safe
`AuditHead` snapshot with only `sequence` and `audit_chain_commitment`.  The
commitment has the exact `audithead:v1:<43 base64url characters>` form
accepted by M10's `AuditAnchorCheckpoint`.  It is a domain-separated HMAC over
the tenant, sequence, and the private terminal audit MAC; it is not the raw
MAC and contains no event, actor, action, object identifier, record
commitment, or key material.  The explicit empty-chain seed is committed too,
so an empty tenant has a definite tenant-specific head.

The method obtains this pair under the same lock and authenticated transaction
used for repository operations.  SQLite reloads and verifies the complete
encrypted audit chain in its `BEGIN IMMEDIATE` transaction before the pair is
returned.  Consequently a caller never combines a sequence from one local
snapshot with a commitment from another.  The head remains stable across a
SQLite close/reopen using the same key.  Key rotation deliberately re-chains
the local audit MACs, so callers must obtain a fresh head after rotation; the
new head still authenticates the same sequence under the new active audit key.
It also changes the commitment, so this local store cannot recompute an old
anchored head after rotation unless pre/post-rotation continuity evidence was
retained independently.

A later, explicitly authorized integration can pass the returned
`head.audit_chain_commitment` to `AuditAnchorAuthority.issue`, together with a
separately managed opaque tenant reference, checkpoint identifier, parent
digest, and trusted timestamps.  `head.sequence` is the repository audit-event
count, while `AuditAnchorAuthority.issue(sequence=...)` requires the separate
checkpoint ordinal, beginning at one even if the first referenced audit head
contains many events.  They must not be mapped one-to-one.  M25 does not call
that authority, issue a checkpoint, claim an external anchor, or provide any
transport or receipt.  It is not a production-readiness claim:
durable cross-process coordination, external receipts, key custody, trusted
time, retention, monitoring, and independent review remain out of scope.
