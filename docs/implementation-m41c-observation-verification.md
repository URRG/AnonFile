# M41c observation-bound object verification

`PostgresPublicationObservationVerifier` is a non-remediating diagnostic path
for one current M41 `OBSERVED` lease. Its caller supplies only tenant,
publication, the observation token and epoch, and a call-scoped OpenBao token.
The adapter loads the M39 intent, M42 payload binding and live M43 signed
authorization itself. It never accepts a caller-provided object reference, key,
binding, worker claim, or authorization as proof.

It first confirms at PostgreSQL's clock that the lease is still `OBSERVED`, no
completion exists, a durable M28 job exists, and no M28 worker claim is live.
It then calls the concrete
worker recovery adapter outside any database transaction. All object, marker,
envelope, key unwrap and authentication failures are collapsed into
`NOT_VERIFIED`; none of their details are stored or returned. A successful
recovery becomes `VERIFIED` only when its exact tenant/object/publication/key
and M42 binding match the persisted scope.

The postflight transaction locks M39 intent, M42 binding, M43 authorization,
M41 observation, completion and worker job in that order, repeats every gate,
and appends exactly one immutable result for the observation epoch. It rechecks
the same database-clock lease immediately before commit. If a lease,
authorization, completion or live claim changes during remote I/O, no result is
written and the call returns a non-actionable result. An intent lacking a durable
job is likewise non-actionable: this slice does not classify no-job orphans.
Commit uncertainty fails
closed; a replay cannot append a second epoch result.

The evidence table stores only tenant/publication identifiers, observation
epoch, `VERIFIED`/`NOT_VERIFIED`, binding digest, authorization digest and a
database timestamp. A `VERIFIED` result additionally carries only the
authenticated ciphertext digest and size, so it identifies the exact encrypted
object version; `NOT_VERIFIED` carries neither. Exact replay must match that
outcome and version or fails closed. The table contains no plaintext, ciphertext
bytes, object key, URL, wrapped key, reference, or OpenBao token.

Verification is not repair, approval, release, finalization, delivery or a
claim. It never writes/deletes/adopts an object, changes metadata, creates or
acknowledges work, or turns evidence into a release permission. Any later
finalization must obtain a normal fresh worker claim and independently repeat
M40 recovery and authorization checks.
