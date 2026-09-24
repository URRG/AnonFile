"""M45b1 inert PostgreSQL candidate-custody intent and terminal fence ledger."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_CUSTODY = re.compile(r"custodyref:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVENT = re.compile(r"custodyfence:v1:" + _OPAQUE + r"\Z")
_TERMINAL = frozenset({"QUARANTINED", "REVOKED", "EXPIRED"})
_DOMAIN = b"anonflow-candidate-custody-intent:v1\0"


class PostgresCandidateCustodyError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL candidate custody unavailable")


def _fail() -> None:
    raise PostgresCandidateCustodyError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        result = value.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail()
    if result.microsecond:
        _fail()
    return result


def _positive_bytes(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= 2**63 - 1:
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _row(cursor: Any) -> tuple[object, ...] | None:
    result = cursor.fetchone()
    if result is None:
        return None
    if type(result) is not tuple:
        _fail()
    return result


def _now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    row = _row(cursor)
    if row is None or len(row) != 1:
        _fail()
    return _time(row[0])


def _read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    row = _row(cursor)
    if row is None or len(row) != 1 or row[0] != "read committed":
        _fail()


def _canonical(intent: "CandidateCustodyIntent") -> bytes:
    record = {
        "artifact_digest": intent.artifact_digest,
        "byte_count": intent.byte_count,
        "custody_ref": intent.custody_ref,
        "expires_at": intent.expires_at.isoformat().replace("+00:00", "Z"),
        "policy_digest": intent.policy_digest,
        "provenance_digest": intent.provenance_digest,
        "run_digest": intent.run_digest,
        "schema_digest": intent.schema_digest,
        "tenant_ref": intent.tenant_ref,
    }
    try:
        return _DOMAIN + json.dumps(record, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


@dataclass(frozen=True, slots=True)
class CandidateCustodyIntent:
    """Immutable metadata-only statement for an as-yet-unuploaded candidate."""
    tenant_ref: str
    custody_ref: str
    artifact_digest: str
    run_digest: str
    policy_digest: str
    schema_digest: str
    provenance_digest: str
    byte_count: int
    expires_at: datetime
    intent_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.custody_ref, _CUSTODY)
        for value in (self.artifact_digest, self.run_digest, self.policy_digest,
                      self.schema_digest, self.provenance_digest):
            _text(value, _DIGEST)
        _positive_bytes(self.byte_count)
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        object.__setattr__(self, "intent_digest", "sha256:" + hashlib.sha256(_canonical(self)).hexdigest())


@dataclass(frozen=True, slots=True)
class CandidateCustodyFence:
    intent: CandidateCustodyIntent
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.intent) is not CandidateCustodyIntent or type(self.state) is not str:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "PENDING_UPLOAD" or self.event_ref is not None:
                _fail()
        elif self.state not in _TERMINAL or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode_intent(row: tuple[object, ...] | None) -> CandidateCustodyIntent | None:
    if row is None:
        return None
    if len(row) != 9:
        _fail()
    return CandidateCustodyIntent(*row)


class PostgresCandidateCustodyAuthority:
    """Durable inert intent and terminal-fence authority; never storage or release access."""
    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    @staticmethod
    def _close(connection: Any) -> None:
        try: connection.close()
        except Exception: pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try: connection.rollback()
        except Exception: pass

    @staticmethod
    def _lock(cursor: Any, *, tenant_ref: str, custody_ref: str) -> CandidateCustodyIntent | None:
        cursor.execute(
            "SELECT tenant_ref,custody_ref,artifact_digest,run_digest,policy_digest,schema_digest,"
            "provenance_digest,byte_count,expires_at FROM anonflow_candidate_custody_intents "
            "WHERE tenant_ref=%s AND custody_ref=%s FOR UPDATE", (tenant_ref, custody_ref))
        return _decode_intent(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, intent: CandidateCustodyIntent) -> CandidateCustodyFence | None:
        cursor.execute("SELECT generation,state,event_ref,changed_at FROM anonflow_candidate_custody_fences "
                       "WHERE tenant_ref=%s AND custody_ref=%s ORDER BY generation DESC LIMIT 1",
                       (intent.tenant_ref, intent.custody_ref))
        row = _row(cursor)
        if row is None:
            return None
        if len(row) != 4:
            _fail()
        return CandidateCustodyFence(intent, *row)

    def create(self, intent: CandidateCustodyIntent) -> CandidateCustodyFence:
        if type(intent) is not CandidateCustodyIntent:
            _fail()
        connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN")
            _read_committed(cursor)
            if intent.expires_at <= _now(cursor):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_candidate_custody_intents "
                "(tenant_ref,custody_ref,artifact_digest,run_digest,policy_digest,schema_digest,provenance_digest,byte_count,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING custody_ref",
                (intent.tenant_ref, intent.custody_ref, intent.artifact_digest, intent.run_digest,
                 intent.policy_digest, intent.schema_digest, intent.provenance_digest, intent.byte_count, intent.expires_at))
            inserted = _row(cursor) is not None
            locked = self._lock(cursor, tenant_ref=intent.tenant_ref, custody_ref=intent.custody_ref)
            if locked != intent:
                _fail()
            if inserted:
                moment = _now(cursor)
                cursor.execute("INSERT INTO anonflow_candidate_custody_fences "
                               "(tenant_ref,custody_ref,generation,state,event_ref,changed_at) "
                               "VALUES (%s,%s,0,'PENDING_UPLOAD',NULL,%s)",
                               (intent.tenant_ref, intent.custody_ref, moment))
                result = CandidateCustodyFence(intent, 0, "PENDING_UPLOAD", None, moment)
                if intent.expires_at <= _now(cursor):
                    _fail()
            else:
                result = self._latest(cursor, intent)
                if result is None:
                    _fail()
            connection.commit(); return result
        except PostgresCandidateCustodyError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def lock_pending(self, cursor: Any, *, tenant_ref: str, custody_ref: str,
                     expected_generation: int, expected_intent_digest: str) -> CandidateCustodyFence:
        _text(tenant_ref, _TENANT); _text(custody_ref, _CUSTODY); _generation(expected_generation)
        _text(expected_intent_digest, _DIGEST)
        try:
            _read_committed(cursor)
            intent = self._lock(cursor, tenant_ref=tenant_ref, custody_ref=custody_ref)
            latest = None if intent is None else self._latest(cursor, intent)
            if (latest is None or intent.intent_digest != expected_intent_digest
                    or latest.generation != expected_generation or latest.state != "PENDING_UPLOAD"
                    or intent.expires_at <= _now(cursor)):
                _fail()
            return latest
        except PostgresCandidateCustodyError: raise
        except Exception: _fail()

    def fence(self, *, tenant_ref: str, custody_ref: str, expected_generation: int,
              expected_intent_digest: str) -> CandidateCustodyFence:
        connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN")
            result = self.lock_pending(cursor, tenant_ref=tenant_ref, custody_ref=custody_ref,
                                       expected_generation=expected_generation, expected_intent_digest=expected_intent_digest)
            connection.commit(); return result
        except PostgresCandidateCustodyError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def terminal(self, *, tenant_ref: str, custody_ref: str, expected_generation: int,
                 state: str, event_ref: str) -> CandidateCustodyFence:
        _text(tenant_ref, _TENANT); _text(custody_ref, _CUSTODY); _generation(expected_generation)
        if type(state) is not str or state not in _TERMINAL: _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN")
            _read_committed(cursor)
            intent = self._lock(cursor, tenant_ref=tenant_ref, custody_ref=custody_ref)
            latest = None if intent is None else self._latest(cursor, intent)
            if latest is None: _fail()
            if latest.generation == expected_generation + 1 and latest.state == state and latest.event_ref == event_ref:
                connection.commit(); return latest
            moment = _now(cursor)
            if (latest.generation != expected_generation or latest.state != "PENDING_UPLOAD"
                    or (state == "EXPIRED" and moment < intent.expires_at)):
                _fail()
            cursor.execute("INSERT INTO anonflow_candidate_custody_fences "
                           "(tenant_ref,custody_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,%s,%s,%s)",
                           (tenant_ref, custody_ref, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1: _fail()
            result = CandidateCustodyFence(intent, expected_generation + 1, state, event_ref, moment)
            connection.commit(); return result
        except PostgresCandidateCustodyError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)
