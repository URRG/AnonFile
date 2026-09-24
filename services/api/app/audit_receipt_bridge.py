"""Local-only verification bridge for signed checkpoints and external receipts.

This module accepts evidence already obtained by a caller.  It has no anchor
transport, no external-service implementation, and no authority to deliver or
release anything.  A successful call says only that a signed local checkpoint
and an independently signed external receipt have been bound and durably
checked by their respective local verifiers.
"""
from __future__ import annotations

from datetime import datetime

from .audit_anchors import AuditAnchorAuthority, AuditAnchorCheckpoint
from .external_audit_receipts import (ExternalAuditReceipt,
                                      ExternalAuditReceiptError,
                                      ExternalAuditReceiptStore)


class AuditReceiptBridgeError(ValueError):
    """Fixed error: supplied receipt or checkpoint details are never reflected."""

    def __init__(self) -> None:
        super().__init__("Invalid audit checkpoint receipt bridge evidence")


def _fail() -> None:
    raise AuditReceiptBridgeError()


class AuditCheckpointReceiptBridge:
    """Bind one authenticated local checkpoint to one persisted receipt.

    ``accept`` is intentionally an evidence-admission operation, not a receipt
    fetch or an anchor submission.  The receipt store's transaction supplies
    durable external-receipt continuity; the bridge additionally requires that
    the independently signed receipt use the exact local tenant, digest, and
    sequence.  A missing, stale, forged, or mismatched receipt fails closed.
    """

    def __init__(self, *, authority: AuditAnchorAuthority,
                 receipt_store: ExternalAuditReceiptStore) -> None:
        if (type(authority) is not AuditAnchorAuthority
                or type(receipt_store) is not ExternalAuditReceiptStore):
            _fail()
        self._authority = authority
        self._receipt_store = receipt_store

    def accept(self, checkpoint: object, receipt: object, *, tenant_ref: str,
               at: datetime) -> ExternalAuditReceipt:
        """Persist a receipt only when it exactly binds an active checkpoint.

        The receipt is never trusted merely because its fields look compatible:
        ``ExternalAuditReceiptStore.accept`` re-verifies its configured pinned
        key and chain continuity inside its SQLite transaction.
        """
        try:
            if (type(checkpoint) is not AuditAnchorCheckpoint
                    or type(receipt) is not ExternalAuditReceipt
                    or not self._authority.verify(checkpoint, tenant_ref=tenant_ref, at=at)
                    or receipt.tenant_ref != checkpoint.tenant_ref
                    or receipt.checkpoint_digest != checkpoint.digest
                    or receipt.sequence != checkpoint.sequence
                    or receipt.anchored_at < checkpoint.issued_at):
                _fail()
            return self._receipt_store.accept(
                receipt, tenant_ref=checkpoint.tenant_ref,
                checkpoint_digest=checkpoint.digest, at=at,
            )
        except (AuditReceiptBridgeError, ExternalAuditReceiptError, TypeError,
                ValueError, OverflowError):
            _fail()
