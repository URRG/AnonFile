"""M45a2 PostgreSQL destination-profile identity and terminal fence ledger.

This deliberately stores only the M44b profile digest and opaque references.
It is not a provisioning endpoint, a buyer directory, or an authorization.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_DESTINATION = re.compile(r"destinationref:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EVENT = re.compile(r"destinationfence:v1:" + _OPAQUE + r"\Z")
_TERMINAL = frozenset({"DEACTIVATED", "REVOKED"})


class PostgresDestinationProfileError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL destination profile unavailable")


def _fail() -> None:
    raise PostgresDestinationProfileError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _version(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= 2**63 - 1:
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


def _database_now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    result = _row(cursor)
    if result is None or len(result) != 1:
        _fail()
    return _time(result[0])


def _require_read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    result = _row(cursor)
    if result is None or len(result) != 1 or result[0] != "read committed":
        _fail()


@dataclass(frozen=True, slots=True)
class DestinationProfile:
    """An immutable, tenant-bound M44b profile-digest version.

    No recipient label, application tenant, purpose, key, or contract is
    stored here. Those fields remain behind a future trusted provisioning
    boundary; this ledger can only fence a supplied opaque digest.
    """
    tenant_ref: str
    destination_ref: str
    version: int
    profile_digest: str
    not_before: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.destination_ref, _DESTINATION)
        _version(self.version)
        _text(self.profile_digest, _DIGEST)
        object.__setattr__(self, "not_before", _time(self.not_before))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if self.expires_at <= self.not_before:
            _fail()


@dataclass(frozen=True, slots=True)
class DestinationProfileFence:
    profile: DestinationProfile
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.profile) is not DestinationProfile or type(self.state) is not str:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.state not in _TERMINAL or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode_profile(row: tuple[object, ...] | None) -> DestinationProfile | None:
    if row is None:
        return None
    if len(row) != 6:
        _fail()
    return DestinationProfile(*row)


class PostgresDestinationProfileAuthority:
    """Append-only per-profile terminal fence authority.

    The profile row is the stable lock. Every terminal writer and active reader
    locks it before reading the latest fence under READ COMMITTED, so a reader
    that waits for a revocation observes the revocation in its next statement.
    A caller using ``lock_active`` must retain its transaction and recheck its
    database clock immediately before its own mutation commits.
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
    def _lock_profile(cursor: Any, *, tenant_ref: str, destination_ref: str,
                      version: int) -> DestinationProfile | None:
        cursor.execute(
            "SELECT tenant_ref,destination_ref,version,profile_digest,not_before,expires_at "
            "FROM anonflow_destination_profiles WHERE tenant_ref=%s AND destination_ref=%s "
            "AND version=%s FOR UPDATE", (tenant_ref, destination_ref, version))
        return _decode_profile(_row(cursor))

    @staticmethod
    def _lock_identity(cursor: Any, *, tenant_ref: str,
                       destination_ref: str) -> None:
        """Lock the destination's single global ownership row first.

        All profile readers and writers use this lock before the profile row.
        Besides making cross-tenant collisions fail closed, it makes a newly
        committed version immediately supersede every earlier version.
        """
        cursor.execute("SELECT tenant_ref,destination_ref FROM anonflow_destination_identities "
                       "WHERE destination_ref=%s FOR UPDATE", (destination_ref,))
        identity = _row(cursor)
        if identity != (tenant_ref, destination_ref):
            _fail()

    @staticmethod
    def _current_profile(cursor: Any, *, tenant_ref: str,
                         destination_ref: str) -> DestinationProfile | None:
        cursor.execute(
            "SELECT tenant_ref,destination_ref,version,profile_digest,not_before,expires_at "
            "FROM anonflow_destination_profiles WHERE tenant_ref=%s AND destination_ref=%s "
            "ORDER BY version DESC LIMIT 1", (tenant_ref, destination_ref))
        return _decode_profile(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, profile: DestinationProfile) -> DestinationProfileFence | None:
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at FROM anonflow_destination_profile_fences "
            "WHERE tenant_ref=%s AND destination_ref=%s AND version=%s "
            "ORDER BY generation DESC LIMIT 1",
            (profile.tenant_ref, profile.destination_ref, profile.version))
        row = _row(cursor)
        if row is None:
            return None
        if len(row) != 4:
            _fail()
        return DestinationProfileFence(profile, *row)

    def create(self, profile: DestinationProfile) -> DestinationProfileFence:
        if type(profile) is not DestinationProfile:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            if profile.expires_at <= _database_now(cursor):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_destination_identities (tenant_ref,destination_ref) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING destination_ref",
                (profile.tenant_ref, profile.destination_ref))
            _row(cursor)  # Consume the bounded INSERT ... RETURNING result.
            self._lock_identity(cursor, tenant_ref=profile.tenant_ref,
                                destination_ref=profile.destination_ref)
            current_profile = self._current_profile(cursor, tenant_ref=profile.tenant_ref,
                                                    destination_ref=profile.destination_ref)
            if current_profile is None:
                if profile.version != 1:
                    _fail()
            elif current_profile.version > profile.version:
                # Old exact create retries are durable history, never a path
                # to reactivate a superseded profile.
                historical = self._lock_profile(cursor, tenant_ref=profile.tenant_ref,
                                                destination_ref=profile.destination_ref,
                                                version=profile.version)
                if historical != profile:
                    _fail()
                historical_fence = self._latest(cursor, profile)
                if historical_fence is None:
                    _fail()
                connection.commit()
                return historical_fence
            elif current_profile.version < profile.version:
                # Rotation is an explicit, one-at-a-time replacement. An
                # operator cannot silently supersede an active profile and a
                # revoked destination identity is permanently closed.
                previous = self._latest(cursor, current_profile)
                if (profile.version != current_profile.version + 1 or previous is None
                        or previous.state != "DEACTIVATED"):
                    _fail()
            cursor.execute(
                "INSERT INTO anonflow_destination_profiles "
                "(tenant_ref,destination_ref,version,profile_digest,not_before,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING version",
                (profile.tenant_ref, profile.destination_ref, profile.version, profile.profile_digest,
                 profile.not_before, profile.expires_at))
            inserted = _row(cursor) is not None
            locked = self._lock_profile(cursor, tenant_ref=profile.tenant_ref,
                                        destination_ref=profile.destination_ref, version=profile.version)
            if locked is None or locked != profile:
                _fail()
            if inserted:
                moment = _database_now(cursor)
                cursor.execute(
                    "INSERT INTO anonflow_destination_profile_fences "
                    "(tenant_ref,destination_ref,version,generation,state,event_ref,changed_at) "
                    "VALUES (%s,%s,%s,0,'ACTIVE',NULL,%s)",
                    (profile.tenant_ref, profile.destination_ref, profile.version, moment))
                current = DestinationProfileFence(profile, 0, "ACTIVE", None, moment)
            else:
                current = self._latest(cursor, profile)
                if current is None:
                    _fail()
            # New profiles must not become active merely because lock waits
            # carried the transaction past expiry. Exact replay is history.
            if inserted and profile.expires_at <= _database_now(cursor):
                _fail()
            connection.commit()
            return current
        except PostgresDestinationProfileError:
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

    def lock_active(self, cursor: Any, *, tenant_ref: str, destination_ref: str,
                    version: int, expected_generation: int,
                    expected_profile_digest: str) -> DestinationProfileFence:
        """Hold the stable profile-row lock for a future transaction mutation."""
        _text(tenant_ref, _TENANT)
        _text(destination_ref, _DESTINATION)
        _version(version)
        _generation(expected_generation)
        _text(expected_profile_digest, _DIGEST)
        try:
            _require_read_committed(cursor)
            self._lock_identity(cursor, tenant_ref=tenant_ref, destination_ref=destination_ref)
            profile = self._lock_profile(cursor, tenant_ref=tenant_ref,
                                         destination_ref=destination_ref, version=version)
            current_profile = self._current_profile(cursor, tenant_ref=tenant_ref,
                                                    destination_ref=destination_ref)
            fence = None if profile is None else self._latest(cursor, profile)
            if (current_profile is None or current_profile.version != version or fence is None
                    or profile.profile_digest != expected_profile_digest
                    or fence.generation != expected_generation or fence.state != "ACTIVE"):
                _fail()
            moment = _database_now(cursor)
            if not profile.not_before <= moment < profile.expires_at:
                _fail()
            return fence
        except PostgresDestinationProfileError:
            raise
        except Exception:
            _fail()

    def fence(self, *, tenant_ref: str, destination_ref: str, version: int,
              expected_generation: int, expected_profile_digest: str) -> DestinationProfileFence:
        """Inspect a live profile; callers that mutate must use ``lock_active``."""
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            value = self.lock_active(cursor, tenant_ref=tenant_ref, destination_ref=destination_ref,
                                     version=version, expected_generation=expected_generation,
                                     expected_profile_digest=expected_profile_digest)
            connection.commit()
            return value
        except PostgresDestinationProfileError:
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

    def terminal(self, *, tenant_ref: str, destination_ref: str, version: int,
                 expected_generation: int, state: str, event_ref: str) -> DestinationProfileFence:
        """Append one DEACTIVATED or REVOKED generation; expiry never blocks a hold."""
        _text(tenant_ref, _TENANT)
        _text(destination_ref, _DESTINATION)
        _version(version)
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
            self._lock_identity(cursor, tenant_ref=tenant_ref, destination_ref=destination_ref)
            profile = self._lock_profile(cursor, tenant_ref=tenant_ref,
                                         destination_ref=destination_ref, version=version)
            latest = None if profile is None else self._latest(cursor, profile)
            if latest is None:
                _fail()
            if (latest.generation == expected_generation + 1 and latest.state == state
                    and latest.event_ref == event_ref):
                connection.commit()
                return latest
            current_profile = self._current_profile(cursor, tenant_ref=tenant_ref,
                                                    destination_ref=destination_ref)
            if (current_profile is None or current_profile.version != version
                    or latest.generation != expected_generation or latest.state != "ACTIVE"):
                _fail()
            moment = _database_now(cursor)
            cursor.execute(
                "INSERT INTO anonflow_destination_profile_fences "
                "(tenant_ref,destination_ref,version,generation,state,event_ref,changed_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (tenant_ref, destination_ref, version, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1:
                _fail()
            result = DestinationProfileFence(profile, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresDestinationProfileError:
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
