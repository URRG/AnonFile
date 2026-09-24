# M45b1 inert candidate-custody foundation

This is an immutable PostgreSQL metadata statement that a candidate artifact is
expected to be uploaded. It binds tenant-scoped opaque custody identity, five
exact SHA-256 commitments (artifact, run, policy, schema and provenance), a
positive expected byte count, and expiry. It deliberately has no object
location, bytes, KMS/key reference, URL, API route, worker, issuer or legacy
store import.

Generation zero is PENDING_UPLOAD only. An append-only terminal fence can be
QUARANTINED, REVOKED, or (only at/after the PostgreSQL expiry clock) EXPIRED.
`lock_pending` requires READ COMMITTED, locks the immutable intent row, then
checks the newest fence and database clock. A future mutation must retain that
lock and recheck the database clock before commit. This is custody metadata,
not upload completion, object integrity, release eligibility, approval, or
delivery authority.
