# M48b2 policy/method snapshot authority

Migration 017 is an independent immutable PostgreSQL ledger for a tenant-scoped,
opaque policy-method reference. Deploy it in the ordered sequence after migration
016, though it deliberately has no table or foreign-key dependency on 016.

Each snapshot commits policy, method identifier/version, method configuration,
taxonomy mapping and output-schema SHA-256 digests, plus expiry. Its canonical
digest is SHA-256 over domain-separated, ASCII canonical JSON
(`anonflow-policy-method-snapshot:v1\\0`). The row and every fence are immutable.
Snapshot expiry and fence timestamps are constrained to whole UTC seconds, so
raw SQL cannot create immutable rows the authority's strict timestamp decoder
would reject.
Generation zero is `ACTIVE`; only `QUARANTINED`, `REVOKED`, and `EXPIRED` can be
appended at generation one. A PostgreSQL insert trigger locks the parent snapshot
and independently rejects a missing baseline, a second terminal transition, or
any other raw-SQL history bypass. The same trigger rejects raw `EXPIRED` inserts
before the parent snapshot's second-precision PostgreSQL-clock expiry boundary.

Creation and active locking take server-supplied application-tenant and expected
M45a3 generation inputs. They require an active READ COMMITTED transaction, lock
the M45a3 stable tenant row, then lock the snapshot row. Creation repeats the
tenant fence and database-clock checks just before commit. A caller must retain a
`lock_active` transaction through any future mutation and recheck it before its
own commit.

This is metadata only. It provides no API, worker, method execution, bytes,
object-storage access, approval, or release authority.
