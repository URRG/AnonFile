# M39a PostgreSQL publication-intent ledger

`app.postgres_publication_intents` persists one immutable metadata-only
`PENDING` plan before a later object-publication worker is allowed to perform
any I/O.  It is an injected PostgreSQL DB-API adapter: each factory call must
return a fresh connection with `autocommit=True`, and the adapter explicitly
owns `BEGIN`/`COMMIT`/`ROLLBACK`.  Operators must apply migration
`003_m39_publication_intents.sql` separately.

An intent binds an exact `publicationref:v1:<43 base64url chars>` to one
tenant, encrypted object/key/work references, a target metadata-record
reference and metadata kind, a stable metadata transaction id, request and
policy commitments, and an expected version.  This is the immutable metadata
write template a later finalizer must use rather than accepting worker-supplied
record fields.  Its optional metadata attributes are deliberately limited to
`authorization_ref`, `release_case_ref`, and a positive `sequence`.
`expected_version` follows metadata CAS semantics: `0` is create-only and a
positive value is an update of that exact version.
All are opaque references or a bounded integer; arbitrary strings, URLs,
payloads, ciphertext, envelopes, and wrapped data-encryption keys reject.

`begin()` uses both the tenant-scoped publication ref and `(tenant_ref, transaction_id)` as
immutable identities.  It creates the row once or returns only the exact same
canonical plan; reusing either identity with a changed plan fails closed.
`read()` requires the owning tenant ref, so a cross-tenant lookup is absent.
Database constraints also enforce reference grammar and the permanent
`PENDING` initial state.

Because M38 binds each create-only `(tenant_ref, object_ref)` object marker to
one publication ref, the ledger also permits only one intent for an object
within a tenant.  Work refs are not globally unique here: a future, separately
authorized policy may intentionally construct distinct output objects from one
work item; every object still has its own immutable intent.  A conflict on an
already-intended object that is not the same publication/transaction is
fail-closed rather than returning another plan.

This slice does **not** publish, finalize, claim, recover, authorize a caller,
or establish crash recovery.  In particular, it is not a release or
production-readiness claim.  A subsequent, separately reviewed transaction
must combine the durable intent with a fenced worker claim and the M38
publication-recovery boundary.
