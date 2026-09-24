# M19 externally signed audit receipts

`app.external_audit_receipts` verifies an external anchor receipt over the
exact local checkpoint digest, opaque tenant reference, monotonic sequence,
UTC anchoring time, external service identity, external key id/fingerprint,
receipt id, and predecessor receipt digest.  It uses only configured pinned
Ed25519 public keys.  It has no private key, no signing function, no anchor
transport, and no API endpoint; it cannot manufacture or claim an external
anchor.

`ExternalAuditReceiptStore` persists only an already verified next receipt in
a SQLite transaction.  It rejects a duplicate, an old sequence, a gap, a
wrong predecessor, a different checkpoint at the expected sequence, malformed
stored JSON, and a receipt that fails configured-key verification.  Records
are canonical, source-safe metadata; payload bytes and audit event contents
are not accepted.

This is a foundation, not evidence that an external system has anchored any
production audit history.  The application must obtain a receipt from an
independently operated service, provision its public key out of band, verify
it here, and retain the resulting head digest outside this SQLite database.
Restoring the *entire* database (including its WAL) to an older valid snapshot
cannot be detected solely by this local store; comparing its head to that
independently retained value is required.  Production additionally needs
durable multi-process coordination, trusted time, key rotation/revocation,
backup/WAL protection, service availability monitoring, retention controls,
and independent security review.  No release authority follows from a receipt.
