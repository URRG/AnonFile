# M41a bounded publication reconciliation observations

`PostgresPublicationReconciler` is a tenant-scoped PostgreSQL-only scanner
for old M39 `PENDING` intents that have no M40 completion.  It reads no object
storage, calls no key service, and carries no payload, URL, ciphertext,
wrapped key, or token in its database rows.

The caller supplies a keyset cursor and a limit of at most 100. PostgreSQL's
clock decides both intent age and M28 claim expiry. An intent with an active,
unexpired worker claim is skipped. For an eligible plan, a row in
`anonflow_publication_observations` receives an opaque short-lived observation
token through an absent-or-expired lease CAS. A concurrent scanner therefore
cannot observe the same publication until that lease expires. Every granted
lease and every explicit quarantine appends an immutable event row.

The only quarantine transition is the fixed,
`OPERATOR_CONFIRMED_UNRECOVERABLE`, reason and it requires the caller's current
unexpired observation token. Scanning never quarantines automatically. It also
never deletes an object, adopts an S3 object, writes metadata, finalizes a
publication, acknowledges a job, or changes worker claims.

Commit outcome uncertainty fails closed. A retry may see no result while the
already committed observation lease remains active; it must wait for expiry or
use a separately authorized operational read path. This is intentionally safer
than issuing a second active scanner token.

This is not a repair worker, object reconciliation system, delivery workflow,
or production-readiness claim. Remaining work includes operator authorization,
auditable read/report endpoints, object verification outside the transaction,
and an explicitly reviewed remediation/finalization protocol.
