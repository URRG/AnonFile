# M23 local checkpoint / external receipt bridge

`app.audit_receipt_bridge.AuditCheckpointReceiptBridge` is a bounded, local
evidence-admission bridge.  It accepts a receipt only after the local
`AuditAnchorAuthority` authenticates the exact active checkpoint and M19's
`ExternalAuditReceiptStore` independently verifies and transactionally persists
the receipt.  The receipt must bind the same opaque tenant reference, exact
checkpoint digest, and sequence; it must not predate checkpoint issuance.

Missing, stale/replayed, forged, malformed, mismatched, or discontinuous
receipts fail closed.  Continuity is enforced by the persisted M19 receipt
ledger, including on reads before a later receipt can use its predecessor.

The bridge does **not** independently prove that a checkpoint's
`audit_chain_commitment` represents repository audit events or the actual audit
head.  That source-to-commitment binding must be authenticated and durably
persisted by the caller before it creates or supplies a checkpoint.  Likewise,
the `at` argument is a trusted caller-supplied clock input; the bridge does not
obtain or establish trusted time itself.

This is a foundation for later production anchoring, not production anchoring
itself.  The bridge has no HTTP client, no external-service implementation, no
receipt-request/submission operation, no key that can issue external receipts,
and no delivery or release authorization.  A caller must obtain a receipt from
an independently operated service and provision its pinned public verification
key out of band.  It also inherits the local-store limits documented for M19:
an independently retained head is needed to identify complete database rollback,
and production requires durable multi-process coordination, trusted time, key
rotation/revocation, secure backup/WAL handling, availability monitoring,
retention controls, and independent security review.
