# M40b claim-fenced publication finalization

`PostgresPublicationFinalizer` requires a concrete `WorkerEncryptedObjects`
adapter and a per-call OpenBao token. Before recovering an object, it reads the
immutable M39 intent and its M42 payload binding in a short read-only database
transaction. The binding commits to the exact payload digest, byte count,
serialization, intended object/key, and plan. The worker receives that binding
and cryptographically authenticates the exact M42 envelope **before** opening
the write transaction. The token is never stored on the finalizer, and no S3
or OpenBao request occurs while it holds a PostgreSQL transaction. A caller
cannot replace verification with an identity callback.

The concrete worker recovers and authenticates the exact M42 object (including
the publication-bound AAD and payload commitment) before `BEGIN`; a bare
`EncryptedObjectReference` is only syntax and is never accepted as proof. An
old M39 intent without an M42 binding fails closed rather than being bound after
the fact. The verification-to-commit
interval remains a storage TOCTOU:
retention/immutable-object controls and the later read-time authentication
check remain necessary.

In one explicit transaction it locks the immutable M39 intent, the M42 binding,
any completion receipt, the worker job, M26 metadata idempotency row, and
target metadata row, in that order. It re-decodes and compares the locked
binding with the preflight binding before deriving the only metadata write.
The completion receipt includes the full binding and encrypted reference,
applies M26 CAS, and acknowledges the exact unexpired claim. A crash before
commit rolls back all of those database changes. Exact replay after commit
returns the stored result; altered inputs and stale/expired claims for an
unfinalized publication fail closed.

This is neither an approval, a release, nor a delivery mechanism.  It cannot
make an object-store write atomic with PostgreSQL, cannot erase an orphan, and
does not make an S3 marker an authorization proof.  Operators need a separate
reconciliation/quarantine protocol for failed or tampered objects.
