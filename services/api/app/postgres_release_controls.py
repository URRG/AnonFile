"""M45a1 PostgreSQL release-control snapshot and revocation fence foundation.

This is intentionally not an adapter for the development M14--M21 store and
does not authorize issuance, object creation, or finalization.  It provides a
small durable authority which a later issuer may populate only after the
relevant controls are made authoritative in this same database.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_SNAPSHOT = re.compile(r"releasectrlref:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"controlfence:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATES = frozenset({"ACTIVE", "REVOKED", "QUARANTINED"})


class PostgresReleaseControlError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL release-control authority unavailable")


def _fail() -> None:
    raise PostgresReleaseControlError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        value = value.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail()
    if value.microsecond:
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


def _database_now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    value = _row(cursor)
    if value is None or len(value) != 1:
        _fail()
    return _time(value[0])


def _require_read_committed(cursor: Any) -> None:
    """Reject snapshot isolation: fence visibility relies on fresh statements."""
    cursor.execute("SHOW transaction_isolation")
    value = _row(cursor)
    if value is None or len(value) != 1 or value[0] != "read committed":
        _fail()


@dataclass(frozen=True, slots=True)
class ReleaseControlSnapshot:
    """Immutable identity for one future, server-owned release-control view.

    ``control_digest`` is an opaque exact commitment.  This foundation does
    not infer what it represents and therefore cannot turn a development-store
    case, approval, or readiness record into a production authorization.
    """
    tenant_ref: str
    snapshot_ref: str
    control_digest: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.snapshot_ref, _SNAPSHOT)
        _text(self.control_digest, _DIGEST)
        object.__setattr__(self, "expires_at", _time(self.expires_at))


@dataclass(frozen=True, slots=True)
class ReleaseControlFence:
    """The latest monotonic state for an immutable snapshot identity."""
    snapshot: ReleaseControlSnapshot
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if (type(self.snapshot) is not ReleaseControlSnapshot or type(self.state) is not str
                or self.state not in _STATES):
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.state == "ACTIVE" or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode(row: tuple[object, ...] | None) -> ReleaseControlFence:
    if row is None or len(row) != 8:
        _fail()
    snapshot = ReleaseControlSnapshot(row[0], row[1], row[2], row[3])
    return ReleaseControlFence(snapshot, row[4], row[5], row[6], row[7])


class PostgresReleaseControlAuthority:
    """Durable identity ledger with terminal, generation-fenced holds.

    ``lock_active`` is the primitive for a future issuer/finalizer: callers
    must invoke it using a READ COMMITTED PostgreSQL transaction, retain that
    transaction through their own mutation, and recheck the DB clock just
    before their commit. ``fence`` is only inspection; its lock ends on return.
    """
    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory): _fail()
        self._connection_factory = connection_factory

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True: _fail()
        return connection

    @staticmethod
    def _rollback(connection: Any) -> None:
        try: connection.rollback()
        except Exception: pass

    @staticmethod
    def _close(connection: Any) -> None:
        try: connection.close()
        except Exception: pass

    @staticmethod
    def _lock_snapshot(cursor: Any, tenant_ref: str, snapshot_ref: str) -> ReleaseControlSnapshot | None:
        """Take the single per-snapshot serialization lock before reading fences.

        PostgreSQL's statement snapshot could otherwise select an old maximum
        fence generation while another transaction is inserting a terminal
        generation.  Every writer and active reader takes this immutable-row
        lock first, then obtains a fresh statement snapshot for the fence.
        """
        cursor.execute(
            "SELECT tenant_ref, snapshot_ref, control_digest, expires_at "
            "FROM anonflow_release_control_snapshots WHERE tenant_ref=%s AND snapshot_ref=%s FOR UPDATE",
            (tenant_ref, snapshot_ref))
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 4:
            _fail()
        return ReleaseControlSnapshot(value[0], value[1], value[2], value[3])

    @staticmethod
    def _latest_after_snapshot_lock(cursor: Any, snapshot: ReleaseControlSnapshot) -> ReleaseControlFence | None:
        cursor.execute(
            "SELECT generation, state, event_ref, changed_at FROM anonflow_release_control_fences "
            "WHERE tenant_ref=%s AND snapshot_ref=%s ORDER BY generation DESC LIMIT 1",
            (snapshot.tenant_ref, snapshot.snapshot_ref))
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 4:
            _fail()
        return ReleaseControlFence(snapshot, value[0], value[1], value[2], value[3])

    def create(self, snapshot: ReleaseControlSnapshot) -> ReleaseControlFence:
        if type(snapshot) is not ReleaseControlSnapshot: _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            moment = _database_now(cursor)
            if snapshot.expires_at <= moment: _fail()
            cursor.execute("INSERT INTO anonflow_release_control_snapshots "
                "(tenant_ref,snapshot_ref,control_digest,expires_at) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING snapshot_ref", (snapshot.tenant_ref, snapshot.snapshot_ref,
                snapshot.control_digest, snapshot.expires_at))
            inserted = _row(cursor) is not None
            locked_snapshot = self._lock_snapshot(cursor, snapshot.tenant_ref, snapshot.snapshot_ref)
            if locked_snapshot is not None and locked_snapshot != snapshot: _fail()
            current = None if locked_snapshot is None else self._latest_after_snapshot_lock(cursor, locked_snapshot)
            if inserted:
                cursor.execute("INSERT INTO anonflow_release_control_fences "
                    "(tenant_ref,snapshot_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,0,'ACTIVE',NULL,%s)",
                    (snapshot.tenant_ref, snapshot.snapshot_ref, moment))
                current = ReleaseControlFence(snapshot, 0, "ACTIVE", None, moment)
            if current is None: _fail()
            # A fresh identity cannot become active while waiting for an
            # insert/row lock past its expiry. Exact existing replays remain
            # readable history and do not reactivate anything.
            if inserted and snapshot.expires_at <= _database_now(cursor):
                _fail()
            connection.commit()
            return current
        except PostgresReleaseControlError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def lock_active(self, cursor: Any, *, tenant_ref: str, snapshot_ref: str,
                    expected_generation: int) -> ReleaseControlFence:
        """Lock and validate one active snapshot within the caller's transaction."""
        _text(tenant_ref, _TENANT)
        _text(snapshot_ref, _SNAPSHOT)
        _generation(expected_generation)
        try:
            _require_read_committed(cursor)
            snapshot = self._lock_snapshot(cursor, tenant_ref, snapshot_ref)
            fence = None if snapshot is None else self._latest_after_snapshot_lock(cursor, snapshot)
            if (fence is None or fence.generation != expected_generation or fence.state != "ACTIVE"
                    or fence.snapshot.expires_at <= _database_now(cursor)):
                _fail()
            return fence
        except PostgresReleaseControlError: raise
        except Exception: _fail()

    def fence(self, *, tenant_ref: str, snapshot_ref: str,
              expected_generation: int) -> ReleaseControlFence:
        """Read a currently active generation; this does not retain the lock.

        A future mutation must instead retain the ``lock_active`` transaction
        and recheck the database clock immediately before its own commit.
        """
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            value = self.lock_active(cursor, tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                                     expected_generation=expected_generation)
            connection.commit()
            return value
        except PostgresReleaseControlError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def terminal(self, *, tenant_ref: str, snapshot_ref: str, expected_generation: int,
                 state: str, event_ref: str) -> ReleaseControlFence:
        """Append one terminal revocation/quarantine generation, exactly once."""
        _text(tenant_ref, _TENANT)
        _text(snapshot_ref, _SNAPSHOT)
        _generation(expected_generation)
        if type(state) is not str or state not in {"REVOKED", "QUARANTINED"}:
            _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            snapshot = self._lock_snapshot(cursor, tenant_ref, snapshot_ref)
            latest = None if snapshot is None else self._latest_after_snapshot_lock(cursor, snapshot)
            if latest is None: _fail()
            if (latest.generation == expected_generation + 1 and latest.state == state
                    and latest.event_ref == event_ref):
                connection.commit()
                return latest
            if (latest.generation != expected_generation or latest.state != "ACTIVE"
                    or latest.snapshot.expires_at <= _database_now(cursor)):
                _fail()
            moment = _database_now(cursor)
            cursor.execute("INSERT INTO anonflow_release_control_fences "
                "(tenant_ref,snapshot_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,%s,%s,%s)",
                (tenant_ref, snapshot_ref, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1: _fail()
            result = ReleaseControlFence(latest.snapshot, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresReleaseControlError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)
