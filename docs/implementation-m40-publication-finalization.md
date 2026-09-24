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
the immutable M43 authorization, the optional M41 reconciliation observation,
any completion receipt, the worker job, M26 metadata idempotency row, and
target metadata row, in that order. A
terminal M41 `QUARANTINED` observation rejects finalization. Quarantine takes
the same intent-first lock and declines after an M40 completion, so the two
terminal decisions cannot both commit. It re-decodes and compares the locked
binding with the preflight binding before deriving the only metadata write.
The M43 attestation is verified with a concrete tenant-scoped pinned Ed25519
verifier and PostgreSQL's clock in the preflight read, then re-verified under
the locked rows in the write transaction. It commits to the exact plan,
metadata target/kind, and M42 binding. The finalizer verifies it once more at
the database clock immediately before commit; expiry rolls back every staged
metadata, acknowledgement, and receipt mutation. Pin reload/revocation must
be completed outside the transaction; no S3, OpenBao, key-loader, or network
work occurs while locks are held.

The completion receipt includes the full binding, encrypted reference, and
M43 authorization digest/issuer/validity identity, applies M26 CAS, and
acknowledges the exact unexpired claim. A crash before commit rolls back all
of those database changes. Missing legacy authorization, altered/unpinned
authorization, scope drift, or expiry fails closed. Exact replay after a grant
expires also fails closed; a future status reader, not `finalize`, must expose
the durable prior completion.

This is neither an approval, a release, nor a delivery mechanism.  It cannot
make an object-store write atomic with PostgreSQL, cannot erase an orphan, and
does not make an S3 marker an authorization proof.  Operators need a separate
reconciliation/quarantine protocol for failed or tampered objects.
