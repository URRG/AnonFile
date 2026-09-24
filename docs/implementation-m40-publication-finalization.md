# M40b claim-fenced publication finalization

`PostgresPublicationFinalizer` is a database-only orchestration seam.  Before
calling it, a worker must create/recover and cryptographically authenticate the
M38 encrypted object; no S3 or OpenBao request occurs while this adapter holds
a PostgreSQL transaction.

In one explicit transaction it locks the immutable M39 intent, any completion
receipt, the worker job, M26 metadata idempotency row, and target metadata row,
in that order.  It derives the only metadata write from the locked intent plus
the authenticated encrypted-object reference, applies M26 CAS, records a
completion receipt, and acknowledges the exact unexpired claim.  A crash rolls
back all of those database changes.  Exact replay returns the stored result;
different completion inputs and stale/expired claims fail closed.

This is neither an approval, a release, nor a delivery mechanism.  It cannot
make an object-store write atomic with PostgreSQL, cannot erase an orphan, and
does not make an S3 marker an authorization proof.  Operators need a separate
reconciliation/quarantine protocol for failed or tampered objects.
