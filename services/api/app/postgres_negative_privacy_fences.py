"""M47a1 PostgreSQL-native negative privacy fence foundation.

This is deliberately a denial-only primitive. Its initial ``NONE`` row means
only that this ledger has no recorded negative privacy state; it is not consent,
lawful basis, eligibility, or permission to process or publish any data.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_SUBJECT = re.compile(r"privacysubjectref:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"privacyfence:v1:" + _OPAQUE + r"\Z")
_TERMINAL = frozenset({"OPT_OUT", "WITHDRAWN", "QUARANTINED"})


class PostgresNegativePrivacyFenceError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL negative privacy fence authority unavailable")


def _fail() -> None:
    raise PostgresNegativePrivacyFenceError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
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


def _row(cursor: Any) -> tuple[object, ...] | None:
    result = cursor.fetchone()
    if result is None:
        return None
    if type(result) is not tuple:
        _fail()
    return result


def _require_read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    result = _row(cursor)
    if result is None or len(result) != 1 or result[0] != "read committed":
        _fail()


def _require_active_transaction(cursor: Any) -> None:
    """Reject cursors that cannot retain the subject lock for a finalizer."""
    connection = getattr(cursor, "connection", None)
    info = getattr(connection, "info", None)
    status = getattr(info, "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS":
        _fail()


@dataclass(frozen=True, slots=True)
class PrivacySubject:
    """Opaque subject reference scoped to precisely one opaque tenant."""

    tenant_ref: str
    subject_ref: str

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.subject_ref, _SUBJECT)


@dataclass(frozen=True, slots=True)
class NegativePrivacyFence:
    """Immutable observation of a denial-only privacy state."""

    subject: PrivacySubject
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.subject) is not PrivacySubject or type(self.state) is not str:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "NONE" or self.event_ref is not None:
                _fail()
        elif self.state not in _TERMINAL or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


class PostgresNegativePrivacyFenceAuthority:
    """Append-only negative states guarded by a stable subject-row lock.

    ``lock_none`` only proves this small denial ledger has no terminal fence at
    the instant it is locked. A future finalizer must retain that READ COMMITTED
    transaction through its own mutation and independently establish every
    positive legal/privacy requirement.
    """

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
    def _rollback(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            pass

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _lock_subject(cursor: Any, *, tenant_ref: str,
                      subject_ref: str) -> PrivacySubject | None:
        cursor.execute(
            "SELECT tenant_ref,subject_ref FROM anonflow_privacy_subjects "
            "WHERE tenant_ref=%s AND subject_ref=%s FOR UPDATE",
            (tenant_ref, subject_ref),
        )
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 2:
            _fail()
        return PrivacySubject(*value)

    @staticmethod
    def _latest(cursor: Any, subject: PrivacySubject) -> NegativePrivacyFence | None:
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at FROM anonflow_negative_privacy_fences "
            "WHERE tenant_ref=%s AND subject_ref=%s ORDER BY generation DESC LIMIT 1",
            (subject.tenant_ref, subject.subject_ref),
        )
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 4:
            _fail()
        return NegativePrivacyFence(subject, *value)

    def create(self, subject: PrivacySubject) -> NegativePrivacyFence:
        """Create the immutable ``NONE`` baseline or return its exact replay."""
        if type(subject) is not PrivacySubject:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            cursor.execute(
                "INSERT INTO anonflow_privacy_subjects (tenant_ref,subject_ref) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING subject_ref",
                (subject.tenant_ref, subject.subject_ref),
            )
            inserted = _row(cursor) is not None
            locked = self._lock_subject(cursor, tenant_ref=subject.tenant_ref,
                                        subject_ref=subject.subject_ref)
            if locked != subject:
                _fail()
            current = self._latest(cursor, locked)
            if inserted:
                cursor.execute(
                    "INSERT INTO anonflow_negative_privacy_fences "
                    "(tenant_ref,subject_ref,generation,state,event_ref) "
                    "VALUES (%s,%s,0,'NONE',NULL) RETURNING changed_at",
                    (subject.tenant_ref, subject.subject_ref),
                )
                created_at = _row(cursor)
                if created_at is None or len(created_at) != 1:
                    _fail()
                current = NegativePrivacyFence(subject, 0, "NONE", None, created_at[0])
            if current is None:
                _fail()
            connection.commit()
            return current
        except PostgresNegativePrivacyFenceError:
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

    def lock_none(self, cursor: Any, *, tenant_ref: str, subject_ref: str,
                  expected_generation: int) -> NegativePrivacyFence:
        """Retain a subject lock only if its latest state is initial ``NONE``.

        The caller owns an already-active READ COMMITTED transaction. It must
        keep that transaction open through its own mutation and call this
        method immediately before commit, so the post-lock fence query gets a
        fresh statement snapshot after any concurrent terminal writer.
        """
        _text(tenant_ref, _TENANT)
        _text(subject_ref, _SUBJECT)
        _generation(expected_generation)
        try:
            _require_active_transaction(cursor)
            _require_read_committed(cursor)
            subject = self._lock_subject(cursor, tenant_ref=tenant_ref, subject_ref=subject_ref)
            fence = None if subject is None else self._latest(cursor, subject)
            if (subject is None or fence is None or fence.generation != expected_generation
                    or fence.state != "NONE"):
                _fail()
            return fence
        except PostgresNegativePrivacyFenceError:
            raise
        except Exception:
            _fail()

    def fence_none(self, *, tenant_ref: str, subject_ref: str,
                   expected_generation: int) -> NegativePrivacyFence:
        """Inspect a current ``NONE`` state; never treat it as permission."""
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            value = self.lock_none(cursor, tenant_ref=tenant_ref, subject_ref=subject_ref,
                                   expected_generation=expected_generation)
            connection.commit()
            return value
        except PostgresNegativePrivacyFenceError:
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

    def terminal(self, *, tenant_ref: str, subject_ref: str, expected_generation: int,
                 state: str, event_ref: str) -> NegativePrivacyFence:
        """Append one idempotent terminal negative state; it cannot be cleared."""
        _text(tenant_ref, _TENANT)
        _text(subject_ref, _SUBJECT)
        _generation(expected_generation)
        if type(state) is not str or state not in _TERMINAL:
            _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            subject = self._lock_subject(cursor, tenant_ref=tenant_ref, subject_ref=subject_ref)
            latest = None if subject is None else self._latest(cursor, subject)
            if latest is None:
                _fail()
            if (latest.generation == expected_generation + 1 and latest.state == state
                    and latest.event_ref == event_ref):
                connection.commit()
                return latest
            if latest.generation != expected_generation or latest.state != "NONE":
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_negative_privacy_fences "
                "(tenant_ref,subject_ref,generation,state,event_ref) "
                "VALUES (%s,%s,%s,%s,%s) RETURNING changed_at",
                (tenant_ref, subject_ref, expected_generation + 1, state, event_ref),
            )
            changed_at = _row(cursor)
            if changed_at is None or len(changed_at) != 1:
                _fail()
            result = NegativePrivacyFence(subject, expected_generation + 1, state, event_ref,
                                          changed_at[0])
            connection.commit()
            return result
        except PostgresNegativePrivacyFenceError:
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
