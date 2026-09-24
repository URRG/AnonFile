# M45a1: PostgreSQL release-control foundation

This slice introduces only a PostgreSQL-owned immutable snapshot identity and a
monotonic terminal fence. It has no HTTP route, signer, M39 admission,
candidate retrieval, delivery capability, or bridge from the development M14--M21
store. It must not be described as a migrated release workflow.

`ReleaseControlSnapshot` contains an opaque exact control digest and expiry.
Its state is an append-only fence sequence: generation zero is ACTIVE; later
generations are terminal REVOKED or QUARANTINED. A future issuer/finalizer must
call `lock_active(cursor, ...)` inside its own **READ COMMITTED** PostgreSQL
transaction, keep that transaction open through its mutation, and recheck the
database clock immediately before committing. The adapter serializes every
reader/writer on the immutable snapshot row before reading the newest fence in
a fresh statement. `fence()` is inspection only.

This append-only implementation intentionally rejects REPEATABLE READ and
SERIALIZABLE callers. Those isolation levels can retain an old transaction
snapshot after waiting for the immutable row lock; supporting them requires a
different mutable-head/serialization design. This is not a general serializable
authorization primitive.

The next safe slice must make the records represented by `control_digest`
authoritative in this same transaction domain (or implement a genuinely atomic
delegation/revocation protocol). A signed copy from `DevelopmentStore`, an
async export, or an outbox event cannot provide revocation safety.
