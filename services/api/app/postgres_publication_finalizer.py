"""One-transaction, claim-fenced publication metadata finalization.

This module deliberately performs no object-store or key-service I/O.  Its
caller must pass the already M38-authenticated encrypted-object reference.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.postgres_metadata import PostgresControlPlaneMetadata
from app.postgres_publication_intents import PublicationIntent, _decode
from app.production_substrate import (ControlPlaneMetadata, EncryptedObjectReference,
                                      LeasedWorkerClaim, TenantMetadataTransaction)


class PostgresPublicationFinalizationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL publication finalization unavailable")


def _fail() -> None:
    raise PostgresPublicationFinalizationError()


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class PublicationFinalization:
    tenant_ref: str
    publication_ref: str
    metadata: ControlPlaneMetadata
    already_finalized: bool = False


class PostgresPublicationFinalizer:
    """Finalize intent, metadata CAS and worker acknowledgement atomically.

    Lock order is intent, completion, worker job, metadata idempotency row,
    then metadata record.  The helper called below owns no transaction boundary.
    """
    def __init__(self, connection_factory: Callable[[], Any],
                 reference_verifier: Callable[[EncryptedObjectReference], EncryptedObjectReference]) -> None:
        if not callable(connection_factory) or not callable(reference_verifier): _fail()
        self._connection_factory = connection_factory
        self._reference_verifier = reference_verifier

    @staticmethod
    def _close(connection: Any) -> None:
        try: connection.close()
        except Exception: pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try: connection.cursor().execute("ROLLBACK")
        except Exception: pass

    def finalize(self, *, claim: LeasedWorkerClaim, reference: EncryptedObjectReference) -> PublicationFinalization:
        if type(claim) is not LeasedWorkerClaim or type(reference) is not EncryptedObjectReference:
            _fail()
        if claim.tenant_ref != reference.tenant_ref: _fail()
        # This occurs before BEGIN: a verifier must use the worker's narrowly
        # scoped M38 recovery/get path to authenticate envelope, AAD and key.
        try:
            verified = self._reference_verifier(reference)
        except Exception:
            _fail()
        if type(verified) is not EncryptedObjectReference or verified != reference:
            _fail()
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not True: _fail()
            cursor = connection.cursor(); cursor.execute("BEGIN")
            # 1. Immutable intent is the authority for every metadata field.
            cursor.execute("SELECT transaction_id, plan_digest, document FROM anonflow_publication_intents "
                           "WHERE tenant_ref=%s AND publication_ref=%s FOR UPDATE",
                           (claim.tenant_ref, reference.publication_ref))
            row = _row(cursor)
            if row is None or len(row) != 3: _fail()
            intent = _decode(row[2], tenant_ref=claim.tenant_ref, publication_ref=reference.publication_ref,
                             transaction_id=row[0], plan_digest=row[1])
            if (intent.work_ref != claim.work_ref or intent.object_ref != reference.object_ref
                    or intent.key_ref != reference.key_ref): _fail()
            completion = {"plan_digest": row[1], "claim_id": claim.claim_id,
                          "lease_epoch": claim.lease_epoch, "reference": {
                              "tenant_ref": reference.tenant_ref, "object_ref": reference.object_ref,
                              "publication_ref": reference.publication_ref, "key_ref": reference.key_ref,
                              "ciphertext_digest": reference.ciphertext_digest,
                              "ciphertext_size_bytes": reference.ciphertext_size_bytes,
                              "encryption_algorithm": reference.encryption_algorithm}}
            completion_digest = hashlib.sha256(_canonical(completion).encode("ascii")).hexdigest()
            # 2. An existing completion is read-only exact replay; it never re-acks a claim.
            cursor.execute("SELECT completion_digest, result_document FROM anonflow_publication_finalizations "
                           "WHERE tenant_ref=%s AND publication_ref=%s FOR UPDATE",
                           (claim.tenant_ref, reference.publication_ref))
            previous = _row(cursor)
            if previous is not None:
                if len(previous) != 2 or previous[0] != completion_digest or previous[1] != completion: _fail()
                cursor.execute("SELECT version, document FROM anonflow_metadata_records WHERE tenant_ref=%s "
                               "AND record_id=%s FOR UPDATE", (intent.tenant_ref, intent.target_ref))
                stored = _row(cursor)
                metadata = ControlPlaneMetadata(intent.tenant_ref, intent.target_ref, intent.metadata_kind,
                                                intent.expected_version + 1, dict(intent.attributes), reference)
                if stored is None or len(stored) != 2 or stored[0] != metadata.version:
                    _fail()
                from app.postgres_metadata import _decode_document
                if _decode_document(stored[1], tenant_ref=intent.tenant_ref, record_id=intent.target_ref,
                                    version=stored[0]) != metadata: _fail()
                cursor.execute("COMMIT")
                return PublicationFinalization(intent.tenant_ref, intent.publication_ref, metadata, True)
            # 3. Fence the current lease immediately before metadata mutation.
            cursor.execute("SELECT claim_id, worker_ref, delivery_attempt, lease_epoch, leased_at, lease_expires_at, "
                           "completed_at, lease_expires_at > clock_timestamp() "
                           "FROM anonflow_worker_jobs WHERE tenant_ref=%s AND work_ref=%s FOR UPDATE",
                           (claim.tenant_ref, claim.work_ref))
            job = _row(cursor)
            if (job is None or len(job) != 8 or job[:6] != (claim.claim_id, claim.worker_ref,
                    claim.delivery_attempt, claim.lease_epoch, claim.leased_at, claim.lease_expires_at)
                    or job[6] is not None or job[7] is not True): _fail()
            metadata = ControlPlaneMetadata(intent.tenant_ref, intent.target_ref, intent.metadata_kind,
                                            intent.expected_version + 1, dict(intent.attributes), reference)
            tx = TenantMetadataTransaction(intent.tenant_ref, intent.transaction_id,
                                           {intent.target_ref: intent.expected_version}, (metadata,))
            digest, documents = PostgresControlPlaneMetadata._transaction_document(tx)
            result = PostgresControlPlaneMetadata._apply_prepared_transaction(cursor, tx, digest, documents)
            if result != (metadata,): _fail()
            cursor.execute("UPDATE anonflow_worker_jobs SET completed_at=date_trunc('second', clock_timestamp()) "
                           "WHERE tenant_ref=%s AND work_ref=%s AND claim_id=%s AND lease_epoch=%s "
                           "AND completed_at IS NULL AND lease_expires_at > clock_timestamp()",
                           (claim.tenant_ref, claim.work_ref, claim.claim_id, claim.lease_epoch))
            if cursor.rowcount != 1: _fail()
            cursor.execute("INSERT INTO anonflow_publication_finalizations "
                           "(tenant_ref, publication_ref, completion_digest, result_document) VALUES (%s,%s,%s,%s::jsonb)",
                           (intent.tenant_ref, intent.publication_ref, completion_digest, _canonical(completion)))
            if cursor.rowcount != 1: _fail()
            cursor.execute("COMMIT")
            return PublicationFinalization(intent.tenant_ref, intent.publication_ref, metadata)
        except PostgresPublicationFinalizationError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            raise PostgresPublicationFinalizationError() from None
        finally:
            if connection is not None: self._close(connection)
