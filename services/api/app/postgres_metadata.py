"""PostgreSQL persistence for the deliberately narrow M22 metadata contract.

This module persists only :class:`ControlPlaneMetadata`.  It deliberately has
no object-store client, ciphertext handling, KMS integration, queue, worker,
credential configuration, or HTTP registration.  Callers must run the SQL
migration before constructing an adapter.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from app.production_substrate import (ControlPlaneMetadata, EncryptedObjectReference,
    MAX_METADATA_BYTES, ProductionSubstrateContractError, TenantMetadataTransaction)


MAX_TRANSACTION_RESULT_BYTES = MAX_METADATA_BYTES * 128 + 1024


class PostgresMetadataError(RuntimeError):
    """Fixed fail-closed result for unavailable, conflicting, or corrupt metadata."""

    def __init__(self) -> None:
        super().__init__("PostgreSQL metadata persistence unavailable")


def _fail() -> None:
    raise PostgresMetadataError()


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _record_document(record: ControlPlaneMetadata) -> dict[str, object]:
    if type(record) is not ControlPlaneMetadata:
        _fail()
    encrypted = record.encrypted_object
    reference = None if encrypted is None else {
        "tenant_ref": encrypted.tenant_ref,
        "object_ref": encrypted.object_ref,
        "key_ref": encrypted.key_ref,
        "ciphertext_digest": encrypted.ciphertext_digest,
        "ciphertext_size_bytes": encrypted.ciphertext_size_bytes,
        "encryption_algorithm": encrypted.encryption_algorithm,
    }
    document = {"tenant_ref": record.tenant_ref, "record_id": record.record_id,
                "kind": record.kind, "version": record.version,
                "attributes": dict(record.attributes), "encrypted_object": reference}
    encoded = _canonical(document)
    if len(encoded.encode("ascii")) > MAX_METADATA_BYTES:
        _fail()
    return document


def _decode_document(value: object, *, tenant_ref: str, record_id: str,
                     version: object) -> ControlPlaneMetadata:
    """Accept only the exact JSON shape emitted by this adapter."""
    if type(value) is str:
        try:
            value = json.loads(value)
        except (TypeError, ValueError, UnicodeError):
            _fail()
    if type(value) is not dict or set(value) != {
            "tenant_ref", "record_id", "kind", "version", "attributes", "encrypted_object"}:
        _fail()
    if (value["tenant_ref"] != tenant_ref or value["record_id"] != record_id
            or type(version) is not int or isinstance(version, bool)
            or value["version"] != version):
        _fail()
    encrypted = value["encrypted_object"]
    if encrypted is not None:
        if type(encrypted) is not dict or set(encrypted) != {
                "tenant_ref", "object_ref", "key_ref", "ciphertext_digest",
                "ciphertext_size_bytes", "encryption_algorithm"}:
            _fail()
        try:
            encrypted = EncryptedObjectReference(**encrypted)
        except (ProductionSubstrateContractError, TypeError):
            _fail()
    try:
        return ControlPlaneMetadata(tenant_ref=value["tenant_ref"], record_id=value["record_id"],
                                    kind=value["kind"], version=value["version"],
                                    attributes=value["attributes"], encrypted_object=encrypted)
    except (ProductionSubstrateContractError, TypeError):
        _fail()


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


class PostgresControlPlaneMetadata:
    """Small DB-API PostgreSQL adapter with transaction-id idempotency and CAS.

    ``connection_factory`` must return a fresh DB-API-style PostgreSQL
    connection with ``autocommit`` set to literal ``True``. The adapter starts
    and completes its own explicit transaction, so an accidentally supplied
    already-transactional connection cannot weaken the atomicity boundary or
    emit nested-transaction warnings. Connection creation, secrets, pooling
    and infrastructure lifecycle stay outside this metadata-only substrate.
    """

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    @staticmethod
    def _transaction_document(transaction: TenantMetadataTransaction) -> tuple[str, list[dict[str, object]]]:
        if type(transaction) is not TenantMetadataTransaction:
            _fail()
        documents = [_record_document(write) for write in transaction.writes]
        # An adapter-level invariant makes stored versions a contiguous CAS
        # history, even though the M22 value object only requires positivity.
        if any(document["version"] != transaction.expected_versions[document["record_id"]] + 1
               for document in documents):
            _fail()
        request = {"tenant_ref": transaction.tenant_ref,
                   "expected_versions": dict(transaction.expected_versions),
                   "writes": documents}
        return hashlib.sha256(_canonical(request).encode("ascii")).hexdigest(), documents

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.cursor().execute("ROLLBACK")
        except Exception:
            pass

    @staticmethod
    def _commit(connection: Any) -> None:
        try:
            connection.cursor().execute("COMMIT")
        except Exception:
            _fail()

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _apply_prepared_transaction(cursor: Any, transaction: TenantMetadataTransaction,
                                    request_digest: str,
                                    documents: list[dict[str, object]]) -> tuple[ControlPlaneMetadata, ...]:
        """Apply one prepared M26 commit through a caller-owned transaction.

        This deliberately performs neither ``BEGIN``/``COMMIT`` nor rollback.
        The public :meth:`commit` method remains the only public transaction
        owner.  A later bounded orchestration adapter can use this private seam
        with a locked worker claim without splitting metadata CAS and job
        acknowledgement across database transactions.

        ``request_digest`` and ``documents`` must be produced by
        :meth:`_transaction_document` for this exact ``transaction`` before
        opening the caller-owned transaction.  Keeping preparation separate
        preserves ``commit``'s existing fail-before-connect behavior.
        """
        if (cursor is None or type(transaction) is not TenantMetadataTransaction
                or type(request_digest) is not str or type(documents) is not list):
            _fail()
        # Recompute only the small metadata representation to ensure a future
        # internal caller cannot pair a valid transaction with another plan.
        # This is validation, not a transaction operation.
        expected_digest, expected_documents = PostgresControlPlaneMetadata._transaction_document(transaction)
        if request_digest != expected_digest or documents != expected_documents:
            _fail()
        if not callable(getattr(cursor, "execute", None)):
            _fail()
        cursor.execute(
            "INSERT INTO anonflow_metadata_transactions "
            "(tenant_ref, transaction_id, request_digest, result_document) "
            "VALUES (%s, %s, %s, NULL) ON CONFLICT DO NOTHING RETURNING transaction_id",
            (transaction.tenant_ref, transaction.transaction_id, request_digest))
        claimed = _row(cursor)
        if claimed is None:
            cursor.execute(
                "SELECT request_digest, CASE WHEN octet_length(result_document::text) <= %s "
                "THEN result_document ELSE NULL END, result_document IS NOT NULL "
                "FROM anonflow_metadata_transactions "
                "WHERE tenant_ref=%s AND transaction_id=%s FOR UPDATE",
                (MAX_TRANSACTION_RESULT_BYTES, transaction.tenant_ref, transaction.transaction_id))
            prior = _row(cursor)
            if (prior is None or len(prior) != 3 or prior[0] != request_digest
                    or prior[1] is None or prior[2] is not True):
                _fail()
            if type(prior[1]) is str:
                prior_document = json.loads(prior[1])
            else:
                prior_document = prior[1]
            if (type(prior_document) is not list or len(prior_document) != len(documents)
                    or _canonical(prior_document) != _canonical(documents)):
                _fail()
            return tuple(_decode_document(item, tenant_ref=transaction.tenant_ref,
                                          record_id=write.record_id, version=write.version)
                         for item, write in zip(prior_document, transaction.writes, strict=True))
        if len(claimed) != 1 or claimed[0] != transaction.transaction_id:
            _fail()
        for write, document in zip(transaction.writes, documents, strict=True):
            expected = transaction.expected_versions[write.record_id]
            cursor.execute(
                "SELECT version FROM anonflow_metadata_records "
                "WHERE tenant_ref=%s AND record_id=%s FOR UPDATE",
                (transaction.tenant_ref, write.record_id))
            existing = _row(cursor)
            if expected == 0:
                if existing is not None:
                    _fail()
                cursor.execute(
                    "INSERT INTO anonflow_metadata_records (tenant_ref, record_id, version, document) "
                    "VALUES (%s, %s, %s, %s::jsonb) ON CONFLICT DO NOTHING",
                    (transaction.tenant_ref, write.record_id, write.version, _canonical(document)))
            else:
                if (existing is None or len(existing) != 1 or existing[0] != expected):
                    _fail()
                cursor.execute(
                    "UPDATE anonflow_metadata_records SET version=%s, document=%s::jsonb "
                    "WHERE tenant_ref=%s AND record_id=%s AND version=%s",
                    (write.version, _canonical(document), transaction.tenant_ref,
                     write.record_id, expected))
            if cursor.rowcount != 1:
                _fail()
        result_document = _canonical(documents)
        cursor.execute(
            "UPDATE anonflow_metadata_transactions SET result_document=%s::jsonb "
            "WHERE tenant_ref=%s AND transaction_id=%s AND request_digest=%s AND result_document IS NULL",
            (result_document, transaction.tenant_ref, transaction.transaction_id, request_digest))
        if cursor.rowcount != 1:
            _fail()
        return tuple(transaction.writes)

    def commit(self, transaction: TenantMetadataTransaction) -> tuple[ControlPlaneMetadata, ...]:
        """Atomically apply exact-version writes, or return the prior same-ID commit.

        ``0`` is create-only.  A reused transaction ID is accepted only when
        its canonical request digest is identical; otherwise it fails closed.
        """
        request_digest, documents = self._transaction_document(transaction)
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not True:
                _fail()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            result = self._apply_prepared_transaction(cursor, transaction, request_digest, documents)
            self._commit(connection)
            return result
        except PostgresMetadataError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresMetadataError() from None
        finally:
            if connection is not None:
                self._close(connection)

    def read(self, tenant_ref: str, record_id: str) -> ControlPlaneMetadata | None:
        """Return a newly reconstructed frozen record scoped to exactly one tenant."""
        # Reuse the contract validator rather than accepting arbitrary key text,
        # including when an absent record would otherwise hide malformed input.
        try:
            ControlPlaneMetadata(tenant_ref=tenant_ref, record_id=record_id,
                                 kind="metadata", version=1, attributes={})
        except ProductionSubstrateContractError:
            _fail()
        connection = None
        try:
            connection = self._connection_factory()
            if connection is None or getattr(connection, "autocommit", None) is not True:
                _fail()
            cursor = connection.cursor()
            cursor.execute("BEGIN READ ONLY")
            cursor.execute(
                "SELECT version, CASE WHEN octet_length(document::text) <= %s THEN document ELSE NULL END, "
                "document IS NOT NULL FROM anonflow_metadata_records "
                "WHERE tenant_ref=%s AND record_id=%s",
                (MAX_METADATA_BYTES, tenant_ref, record_id))
            stored = _row(cursor)
            if stored is None:
                self._commit(connection)
                return None
            if len(stored) != 3 or stored[1] is None or stored[2] is not True:
                _fail()
            record = _decode_document(stored[1], tenant_ref=tenant_ref, record_id=record_id,
                                      version=stored[0])
            self._commit(connection)
            return record
        except PostgresMetadataError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresMetadataError() from None
        finally:
            if connection is not None:
                self._close(connection)
