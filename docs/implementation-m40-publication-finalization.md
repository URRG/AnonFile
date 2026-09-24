# M40b claim-fenced publication finalization

`PostgresPublicationFinalizer` requires a concrete `WorkerEncryptedObjects`
adapter and a per-call OpenBao token. It recovers and cryptographically
authenticates the exact M38 encrypted object **before** opening the database
transaction. The token is never stored on the finalizer, and no S3 or OpenBao
request occurs while it holds a PostgreSQL transaction. A caller cannot replace
the verification step with an identity callback.

The concrete worker recovers and authenticates the exact M38 object (including
the publication-bound AAD) before `BEGIN`; a bare `EncryptedObjectReference`
is only syntax and is never accepted as proof. The verification-to-commit
interval remains a storage TOCTOU:
retention/immutable-object controls and the later read-time authentication
check remain necessary.

In one explicit transaction it locks the immutable M39 intent, any completion
receipt, the worker job, M26 metadata idempotency row, and target metadata row,
in that order.  It derives the only metadata write from the locked intent plus
the authenticated encrypted-object reference, applies M26 CAS, records a
completion receipt, and acknowledges the exact unexpired claim. A crash before
commit rolls back all of those database changes. Exact replay after commit
returns the stored result; altered inputs and stale/expired claims for an
unfinalized publication fail closed.

This is neither an approval, a release, nor a delivery mechanism.  It cannot
make an object-store write atomic with PostgreSQL, cannot erase an orphan, and
does not make an S3 marker an authorization proof.  Operators need a separate
reconciliation/quarantine protocol for failed or tampered objects.
