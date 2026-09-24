"""Durable, metadata-only PostgreSQL publication-intent ledger.

This adapter records an immutable ``PENDING`` intent *before* a later worker
can attempt object publication.  It deliberately has no object store, key
material, worker claim, recovery, or finalization operation.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_OBJECT = re.compile(r"objectref:v1:" + _OPAQUE + r"\Z")
_KEY = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_WORK = re.compile(r"workref:v1:" + _OPAQUE + r"\Z")
_RECORD = re.compile(r"metarecord:v1:" + _OPAQUE + r"\Z")
_TX = re.compile(r"metatx:v1:" + _OPAQUE + r"\Z")
_PUBLICATION = re.compile(r"publicationref:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_MAX_ATTRIBUTES = 16
_MAX_ROW_BYTES = 16_384
_SAFE_ATTRIBUTE_REFS = frozenset({"authorization_ref", "release_case_ref"})


class PostgresPublicationIntentError(RuntimeError):
    """Fixed fail-closed result for invalid, unavailable, or conflicting intent."""

    def __init__(self) -> None:
        super().__init__("PostgreSQL publication intent persistence unavailable")


def _fail() -> None:
    raise PostgresPublicationIntentError()


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _positive(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= 2**63 - 1:
        _fail()
    return value


def _expected_version(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _attributes(value: object) -> Mapping[str, object]:
    """Freeze the small allowlist; arbitrary text could be source data."""
    if type(value) is not dict or len(value) > _MAX_ATTRIBUTES:
        _fail()
    result: dict[str, object] = {}
    for key, item in value.items():
        if key in _SAFE_ATTRIBUTE_REFS:
            result[key] = _text(item, _RECORD)
        elif key == "sequence":
            result[key] = _positive(item)
        else:
            _fail()
    return MappingProxyType(result)


def _canonical(value: object) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                             separators=(",", ":"))
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    if len(encoded.encode("ascii")) > _MAX_ROW_BYTES:
        _fail()
    return encoded


@dataclass(frozen=True, slots=True)
class PublicationIntent:
    """The immutable, metadata-only plan for one future publication attempt."""

    tenant_ref: str
    publication_ref: str
    transaction_id: str
    object_ref: str
    key_ref: str
    work_ref: str
    target_ref: str
    metadata_kind: str
    request_digest: str
    policy_digest: str
    expected_version: int
    attributes: Mapping[str, object]
    state: str = "PENDING"

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.publication_ref, _PUBLICATION)
        _text(self.transaction_id, _TX)
        _text(self.object_ref, _OBJECT)
        _text(self.key_ref, _KEY)
        _text(self.work_ref, _WORK)
        _text(self.target_ref, _RECORD)
        _text(self.metadata_kind, _KIND)
        _text(self.request_digest, _DIGEST)
        _text(self.policy_digest, _DIGEST)
        _expected_version(self.expected_version)
        if self.state != "PENDING":
            _fail()
        frozen = _attributes(self.attributes)
        object.__setattr__(self, "attributes", frozen)
        _canonical(_document(self))


def _document(intent: PublicationIntent) -> dict[str, object]:
    return {
        "attributes": dict(intent.attributes), "expected_version": intent.expected_version,
        "key_ref": intent.key_ref, "object_ref": intent.object_ref,
        "metadata_kind": intent.metadata_kind, "policy_digest": intent.policy_digest,
        "publication_ref": intent.publication_ref,
        "request_digest": intent.request_digest, "state": intent.state,
        "target_ref": intent.target_ref, "tenant_ref": intent.tenant_ref,
        "transaction_id": intent.transaction_id, "work_ref": intent.work_ref,
    }


def _plan_digest(intent: PublicationIntent) -> str:
    return "sha256:" + hashlib.sha256(_canonical(_document(intent)).encode("ascii")).hexdigest()


def _row(cursor: Any) -> tuple[object, ...] | None:
    result = cursor.fetchone()
    if result is None:
        return None
    if type(result) is not tuple:
        _fail()
    return result


def _rows(cursor: Any) -> tuple[tuple[object, ...], ...]:
    try:
        result = cursor.fetchall()
    except Exception:
        _fail()
    if type(result) not in (list, tuple) or any(type(item) is not tuple for item in result):
        _fail()
    return tuple(result)


def _decode(document: object, *, tenant_ref: str, publication_ref: str,
            transaction_id: str, plan_digest: str) -> PublicationIntent:
    if type(document) is str:
        try:
            document = json.loads(document)
        except (TypeError, ValueError, UnicodeError):
            _fail()
    expected = {"attributes", "expected_version", "key_ref", "metadata_kind", "object_ref", "policy_digest",
                "publication_ref", "request_digest", "state", "target_ref", "tenant_ref",
                "transaction_id", "work_ref"}
    if type(document) is not dict or set(document) != expected:
        _fail()
    try:
        intent = PublicationIntent(**document)
    except (PostgresPublicationIntentError, TypeError):
        _fail()
    if (intent.tenant_ref != tenant_ref or intent.publication_ref != publication_ref
            or intent.transaction_id != transaction_id or _plan_digest(intent) != plan_digest):
        _fail()
    return intent


class PostgresPublicationIntents:
    """Atomic create-or-return ledger for immutable PENDING publication plans.

    The injected factory must return a fresh DB-API PostgreSQL connection with
    literal ``autocommit=True``.  This adapter owns its explicit transaction.
    """

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

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

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    def begin(self, intent: PublicationIntent) -> PublicationIntent:
        """Atomically create or return the exact original PENDING plan.

        Reusing either immutable identity (publication ref or tenant-scoped
        transaction id) with any altered canonical plan fails closed.
        """
        if type(intent) is not PublicationIntent:
            _fail()
        document, digest = _canonical(_document(intent)), _plan_digest(intent)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "INSERT INTO anonflow_publication_intents "
                "(publication_ref, tenant_ref, transaction_id, object_ref, plan_digest, document) "
                "VALUES (%s, %s, %s, %s, %s, %s::jsonb) ON CONFLICT DO NOTHING "
                "RETURNING publication_ref, tenant_ref, transaction_id, plan_digest, document",
                (intent.publication_ref, intent.tenant_ref, intent.transaction_id, intent.object_ref,
                 digest, document))
            stored = _row(cursor)
            if stored is None:
                if cursor.rowcount != 0:
                    _fail()
                cursor.execute(
                    "SELECT publication_ref, tenant_ref, transaction_id, plan_digest, "
                    "CASE WHEN octet_length(document::text) <= %s THEN document ELSE NULL END "
                    "FROM anonflow_publication_intents WHERE publication_ref=%s "
                    "OR (tenant_ref=%s AND transaction_id=%s) FOR UPDATE",
                    (_MAX_ROW_BYTES, intent.publication_ref, intent.tenant_ref, intent.transaction_id))
                candidates = _rows(cursor)
                if len(candidates) != 1:
                    _fail()
                stored = candidates[0]
            if stored is None or len(stored) != 5:
                _fail()
            publication_ref, tenant_ref, transaction_id, stored_digest, stored_document = stored
            loaded = _decode(stored_document, tenant_ref=intent.tenant_ref,
                             publication_ref=intent.publication_ref,
                             transaction_id=intent.transaction_id, plan_digest=digest)
            if (publication_ref != intent.publication_ref or tenant_ref != intent.tenant_ref
                    or transaction_id != intent.transaction_id or stored_digest != digest
                    or loaded != intent):
                _fail()
            self._commit(connection)
            return loaded
        except PostgresPublicationIntentError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresPublicationIntentError() from None
        finally:
            if connection is not None:
                self._close(connection)

    def read(self, tenant_ref: str, publication_ref: str) -> PublicationIntent | None:
        """Read one immutable intent only through its owning tenant scope."""
        _text(tenant_ref, _TENANT)
        _text(publication_ref, _PUBLICATION)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN READ ONLY")
            cursor.execute(
                "SELECT transaction_id, plan_digest, "
                "CASE WHEN octet_length(document::text) <= %s THEN document ELSE NULL END "
                "FROM anonflow_publication_intents WHERE tenant_ref=%s AND publication_ref=%s",
                (_MAX_ROW_BYTES, tenant_ref, publication_ref))
            stored = _row(cursor)
            if stored is None:
                self._commit(connection)
                return None
            if len(stored) != 3:
                _fail()
            result = _decode(stored[2], tenant_ref=tenant_ref, publication_ref=publication_ref,
                             transaction_id=stored[0], plan_digest=stored[1])
            self._commit(connection)
            return result
        except PostgresPublicationIntentError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresPublicationIntentError() from None
        finally:
            if connection is not None:
                self._close(connection)
