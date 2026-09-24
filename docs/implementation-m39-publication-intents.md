# M39a PostgreSQL publication-intent ledger

`app.postgres_publication_intents` persists one immutable metadata-only
`PENDING` plan before a later object-publication worker is allowed to perform
any I/O.  It is an injected PostgreSQL DB-API adapter: each factory call must
return a fresh connection with `autocommit=True`, and the adapter explicitly
owns `BEGIN`/`COMMIT`/`ROLLBACK`.  Operators must apply migration
`003_m39_publication_intents.sql`, then
`006_m42_publication_payload_bindings.sql`, and then
`007_m43_publication_authorizations.sql` separately.

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

Each `begin(intent, binding, attestation)` additionally commits a `PublicationPayloadBinding`
in the same PostgreSQL transaction.  The binding contains the tenant,
publication, encrypted object/key references, plan commitment, an exact-byte
payload commitment, byte size, and one supported serialization identifier
(`binary-v1` or `jsonl-utf8-v1`).  It never contains the payload, a URL,
ciphertext, envelope, or key material.  Its `payload_digest` is
`SHA256("anonflow-release-payload:v1\\0" || uint64_be(size) || exact_bytes)`;
the binding digest canonically commits every binding field other than itself.

`begin()` uses both the tenant-scoped publication ref and `(tenant_ref, transaction_id)` as
immutable identities.  It creates the intent and binding once or returns only
the exact same canonical pair; reusing either identity with a changed plan or
binding fails closed.  A legacy M39 intent with no binding is deliberately not
retrofit: replay, `read()`, and `read_binding()` all fail closed rather than
attaching a potentially unauthorized payload after the fact. `read()` and
`read_binding()` require the owning tenant ref, so a cross-tenant lookup is
absent. Database constraints also enforce reference grammar and the permanent
`PENDING` initial state.

The binding is a technical integrity commitment, not business authorization.
`begin()` additionally requires a short-lived externally issued M43a signed
attestation that commits the exact plan, destination and binding. The caller
supplies only a pinned Ed25519 public-key verifier: it has no signing key and
does not infer rights or approvals. The ledger validates signature/scope and
uses PostgreSQL's clock to reject future-issued or expired attestations before
the atomic insert. `read()`, `read_binding()`, and `read_authorization()`
revalidate the matching durable attestation against that same clock; missing,
expired, corrupt, untrusted, or legacy authorization rows fail closed.

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
