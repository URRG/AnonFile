# M40b claim-fenced publication finalization

`PostgresPublicationFinalizer` is a database-only orchestration seam.  Before
calling it, a worker must create/recover and cryptographically authenticate the
M38 encrypted object; no S3 or OpenBao request occurs while this adapter holds
a PostgreSQL transaction.

Construction requires a deployment-owned reference verifier.  It must recover
and authenticate the exact M38 object (including the publication-bound AAD)
before `BEGIN`; a bare `EncryptedObjectReference` is only syntax and is never
accepted as proof.  The verifier-to-commit interval remains a storage TOCTOU:
retention/immutable-object controls and the later read-time authentication
check remain necessary.

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
