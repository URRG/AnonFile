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
from app.postgres_publication_intents import (_MAX_ROW_BYTES, _decode, _decode_binding)
from app.publication_payload_binding import PublicationPayloadBinding
from app.production_substrate import (ControlPlaneMetadata, EncryptedObjectReference,
                                      LeasedWorkerClaim, TenantMetadataTransaction)
from app.worker_encrypted_objects import WorkerEncryptedObjects


class PostgresPublicationFinalizationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL publication finalization unavailable")


def _fail() -> None:
    raise PostgresPublicationFinalizationError() from None


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


def _binding_fields(binding: PublicationPayloadBinding) -> dict[str, object]:
    """The complete non-secret authorization carried into the receipt."""
    if type(binding) is not PublicationPayloadBinding:
        _fail()
    return {
        "tenant_ref": binding.tenant_ref, "publication_ref": binding.publication_ref,
        "object_ref": binding.object_ref, "key_ref": binding.key_ref,
        "plan_digest": binding.plan_digest, "payload_digest": binding.payload_digest,
        "payload_size_bytes": binding.payload_size_bytes,
        "serialization_id": binding.serialization_id, "binding_digest": binding.binding_digest,
    }


@dataclass(frozen=True, slots=True)
class PublicationFinalization:
    tenant_ref: str
    publication_ref: str
    metadata: ControlPlaneMetadata
    already_finalized: bool = False


class PostgresPublicationFinalizer:
    """Finalize intent, metadata CAS and worker acknowledgement atomically.

    Lock order is intent, immutable payload binding, reconciliation observation,
    completion, worker job, metadata idempotency row, then metadata record.  Object and key service I/O
    happens only in the preflight read/recovery phase, before the write locks.
    """
    def __init__(self, connection_factory: Callable[[], Any],
                 encrypted_objects: WorkerEncryptedObjects) -> None:
        if not callable(connection_factory) or type(encrypted_objects) is not WorkerEncryptedObjects: _fail()
        self._connection_factory = connection_factory
        self._encrypted_objects = encrypted_objects

    @staticmethod
    def _close(connection: Any) -> None:
        try: connection.close()
        except Exception: pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try: connection.cursor().execute("ROLLBACK")
        except Exception: pass

    def _preflight_binding(self, *, tenant_ref: str, publication_ref: str,
                           claim: LeasedWorkerClaim,
                           reference: EncryptedObjectReference) -> PublicationPayloadBinding:
        """Load a coherent immutable authorization before object-store recovery.

        An M39-only row has no commitment to the bytes that were authorized,
        and is therefore deliberately not eligible for finalization.
        """
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not True:
                _fail()
            cursor = connection.cursor()
            cursor.execute("BEGIN READ ONLY")
            cursor.execute(
                "SELECT transaction_id, plan_digest, "
                "CASE WHEN octet_length(document::text) <= %s THEN document ELSE NULL END "
                "FROM anonflow_publication_intents WHERE tenant_ref=%s AND publication_ref=%s",
                (_MAX_ROW_BYTES, tenant_ref, publication_ref))
            row = _row(cursor)
            if row is None or len(row) != 3:
                _fail()
            intent = _decode(row[2], tenant_ref=tenant_ref, publication_ref=publication_ref,
                             transaction_id=row[0], plan_digest=row[1])
            cursor.execute(
                "SELECT object_ref, key_ref, plan_digest, payload_digest, payload_size_bytes, "
                "serialization_id, binding_digest FROM anonflow_publication_payload_bindings "
                "WHERE tenant_ref=%s AND publication_ref=%s",
                (tenant_ref, publication_ref))
            binding = _decode_binding(_row(cursor), intent=intent, plan_digest=row[1])
            if (intent.work_ref != claim.work_ref or binding.tenant_ref != tenant_ref
                    or binding.publication_ref != publication_ref
                    or reference.object_ref != binding.object_ref
                    or reference.key_ref != binding.key_ref
                    or reference.binding_digest != binding.binding_digest):
                _fail()
            cursor.execute("COMMIT")
            return binding
        except PostgresPublicationFinalizationError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def finalize(self, *, claim: LeasedWorkerClaim, reference: EncryptedObjectReference,
                 openbao_token: str) -> PublicationFinalization:
        if type(claim) is not LeasedWorkerClaim or type(reference) is not EncryptedObjectReference:
            _fail()
        if claim.tenant_ref != reference.tenant_ref: _fail()
        binding = self._preflight_binding(tenant_ref=claim.tenant_ref,
                                          publication_ref=reference.publication_ref,
                                          claim=claim, reference=reference)
        # Authenticate the exact S3 object and OpenBao-wrapped key before the
        # write transaction.  Never keep DB row locks across remote I/O.
        # The token remains call-scoped; the finalizer never stores it.
        try:
            verified = self._encrypted_objects.recover(
                tenant_ref=reference.tenant_ref, object_ref=reference.object_ref,
                publication_ref=reference.publication_ref, key_ref=reference.key_ref,
                binding=binding, openbao_token=openbao_token)
        except Exception:
            _fail()
        if type(verified) is not EncryptedObjectReference or verified != reference:
            _fail()
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not True: _fail()
            cursor = connection.cursor(); cursor.execute("BEGIN")
            # 1. Re-lock and re-decode every authorization element after the
            # preflight.  A row changed/corrupted between phases cannot be used.
            cursor.execute("SELECT transaction_id, plan_digest, "
                           "CASE WHEN octet_length(document::text) <= %s THEN document ELSE NULL END "
                           "FROM anonflow_publication_intents "
                           "WHERE tenant_ref=%s AND publication_ref=%s FOR UPDATE",
                           (_MAX_ROW_BYTES, claim.tenant_ref, reference.publication_ref))
            row = _row(cursor)
            if row is None or len(row) != 3: _fail()
            intent = _decode(row[2], tenant_ref=claim.tenant_ref, publication_ref=reference.publication_ref,
                             transaction_id=row[0], plan_digest=row[1])
            if (intent.work_ref != claim.work_ref or intent.object_ref != reference.object_ref
                    or intent.key_ref != reference.key_ref): _fail()
            cursor.execute("SELECT object_ref, key_ref, plan_digest, payload_digest, payload_size_bytes, "
                           "serialization_id, binding_digest FROM anonflow_publication_payload_bindings "
                           "WHERE tenant_ref=%s AND publication_ref=%s FOR UPDATE",
                           (claim.tenant_ref, reference.publication_ref))
            locked_binding = _decode_binding(_row(cursor), intent=intent, plan_digest=row[1])
            if locked_binding != binding or reference.binding_digest != locked_binding.binding_digest:
                _fail()
            # An explicit M41 operator quarantine is terminal for this
            # publication.  Take the same row lock used by quarantine after
            # the intent/binding lock order, so a quarantine racing recovery
            # either commits first and fences finalization, or observes this
            # committed completion and declines to quarantine.
            cursor.execute("SELECT state FROM anonflow_publication_observations "
                           "WHERE tenant_ref=%s AND publication_ref=%s FOR UPDATE",
                           (claim.tenant_ref, reference.publication_ref))
            observation = _row(cursor)
            if observation is not None:
                if len(observation) != 1 or observation[0] not in ("OBSERVED", "QUARANTINED"):
                    _fail()
                if observation[0] == "QUARANTINED":
                    _fail()
            completion = {"plan_digest": row[1], "claim_id": claim.claim_id,
                          "worker_ref": claim.worker_ref,
                          "delivery_attempt": claim.delivery_attempt,
                          "lease_epoch": claim.lease_epoch,
                          "leased_at": claim.leased_at.isoformat(),
                          "lease_expires_at": claim.lease_expires_at.isoformat(),
                          "binding": _binding_fields(locked_binding),
                          "reference": {
                              "tenant_ref": reference.tenant_ref, "object_ref": reference.object_ref,
                              "publication_ref": reference.publication_ref, "key_ref": reference.key_ref,
                              "ciphertext_digest": reference.ciphertext_digest,
                              "ciphertext_size_bytes": reference.ciphertext_size_bytes,
                              "binding_digest": reference.binding_digest,
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
