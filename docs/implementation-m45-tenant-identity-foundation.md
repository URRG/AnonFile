# M45a3 PostgreSQL tenant identity foundation

M45a3 records one immutable, one-to-one application tenant to opaque PostgreSQL
`tenantref` mapping and an append-only terminal fence. A mapping begins ACTIVE
at generation zero and may later become DISABLED or QUARANTINED. `lock_active`
uses a stable mapping-row lock plus fresh READ COMMITTED fence read so a caller
cannot observe stale ACTIVE state after waiting behind a terminal fence.
It rejects idle/autocommit or unknown transaction-state cursors: callers must
retain the active transaction and row lock through their own durable mutation.

This is only a future authorization building block. It has no provisioning,
admin route, legal approval, signer, release control migration, candidate
custody, M39 admission, or issuer integration. Mapping creation must be called
only from a future separately authorized administrative workflow; this module
does not establish that a mapping is legally or operationally approved.
Production routes remain closed.
