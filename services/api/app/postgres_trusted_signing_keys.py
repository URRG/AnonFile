"""M47 PostgreSQL-native trusted Ed25519 public-key registry.

This authority intentionally owns only immutable public-key metadata and a
terminal revocation fence.  It cannot sign, verify an approval, provision an
actor, authorize a release, or expose an HTTP route.  A later issuer must keep
``lock_active``'s transaction open through its own mutation.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import base64
import binascii
import re
from typing import Any

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_ACTOR = re.compile(r"actorref:v1:" + _OPAQUE + r"\Z")
_KEY = re.compile(r"signingkeyref:v1:" + _OPAQUE + r"\Z")
_PUBLIC_KEY = re.compile(r"ed25519pub:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"signingkeyfence:v1:" + _OPAQUE + r"\Z")
_ROLES = frozenset({
    "PRIVACY_REVIEWER",
    "RELEASE_AUTHORIZER",
    "SERVICE_ISSUER",
    "SUPPLIER_RIGHTS_ATTESTER",
})


class PostgresTrustedSigningKeyError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL trusted signing key authority unavailable")


def _fail() -> None:
    raise PostgresTrustedSigningKeyError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _public_key(value: object) -> str:
    """Accept one canonical unpadded base64url encoding of 32 public bytes."""
    text = _text(value, _PUBLIC_KEY)
    payload = text.removeprefix("ed25519pub:v1:")
    try:
        raw = base64.urlsafe_b64decode(payload + "=")
    except (binascii.Error, ValueError, UnicodeError):
        _fail()
    if (len(raw) != 32
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != payload):
        _fail()
    return text


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
    cursor.execute("SHOW transaction_isolation")
    value = _row(cursor)
    if value is None or len(value) != 1 or value[0] != "read committed":
        _fail()


def _require_active_transaction(cursor: Any) -> None:
    """Reject idle/autocommit cursors that cannot retain a ``FOR UPDATE`` lock.

    Future issuers need this registry's stable-row lock to outlive validation
    through their own database mutation.  Unknown driver shapes fail closed.
    """
    connection = getattr(cursor, "connection", None)
    info = getattr(connection, "info", None)
    status = getattr(info, "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS":
        _fail()


@dataclass(frozen=True, slots=True)
class TrustedSigningKey:
    """A tenant-bound, opaque identity for one Ed25519 public key."""

    tenant_ref: str
    actor_ref: str
    key_ref: str
    role: str
    public_key: str
    not_before: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.actor_ref, _ACTOR)
        _text(self.key_ref, _KEY)
        if type(self.role) is not str or self.role not in _ROLES:
            _fail()
        _public_key(self.public_key)
        object.__setattr__(self, "not_before", _time(self.not_before))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if self.expires_at <= self.not_before:
            _fail()


@dataclass(frozen=True, slots=True)
class TrustedSigningKeyFence:
    key: TrustedSigningKey
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.key) is not TrustedSigningKey or type(self.state) is not str:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.state != "REVOKED" or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode_key(row: tuple[object, ...] | None) -> TrustedSigningKey | None:
    if row is None:
        return None
    if len(row) != 7:
        _fail()
    return TrustedSigningKey(*row)


class PostgresTrustedSigningKeyAuthority:
    """Immutable trusted-key records with append-only, terminal revocations."""

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
    def _lock_key(cursor: Any, tenant_ref: str, key_ref: str) -> TrustedSigningKey | None:
        cursor.execute(
            "SELECT tenant_ref,actor_ref,key_ref,role,public_key,not_before,expires_at "
            "FROM anonflow_trusted_signing_keys WHERE tenant_ref=%s AND key_ref=%s FOR UPDATE",
            (tenant_ref, key_ref))
        return _decode_key(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, key: TrustedSigningKey) -> TrustedSigningKeyFence | None:
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at FROM anonflow_trusted_signing_key_fences "
            "WHERE tenant_ref=%s AND key_ref=%s ORDER BY generation DESC LIMIT 1",
            (key.tenant_ref, key.key_ref))
        row = _row(cursor)
        if row is None:
            return None
        if len(row) != 4:
            _fail()
        return TrustedSigningKeyFence(key, *row)

    def create(self, key: TrustedSigningKey) -> TrustedSigningKeyFence:
        """Create an immutable key record; exact replay returns durable state."""
        if type(key) is not TrustedSigningKey:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            if key.expires_at <= _database_now(cursor):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_trusted_signing_keys "
                "(tenant_ref,actor_ref,key_ref,role,public_key,not_before,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING key_ref",
                (key.tenant_ref, key.actor_ref, key.key_ref, key.role, key.public_key,
                 key.not_before, key.expires_at))
            inserted = _row(cursor) is not None
            locked = self._lock_key(cursor, key.tenant_ref, key.key_ref)
            if locked != key:
                _fail()
            if inserted:
                moment = _database_now(cursor)
                cursor.execute(
                    "INSERT INTO anonflow_trusted_signing_key_fences "
                    "(tenant_ref,key_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,0,'ACTIVE',NULL,%s)",
                    (key.tenant_ref, key.key_ref, moment))
                if cursor.rowcount != 1:
                    _fail()
                result = TrustedSigningKeyFence(key, 0, "ACTIVE", None, moment)
                # A lock wait cannot turn an originally future-valid key into
                # an expired, active record.
                if key.expires_at <= _database_now(cursor):
                    _fail()
            else:
                result = self._latest(cursor, key)
                if result is None:
                    _fail()
            connection.commit()
            return result
        except PostgresTrustedSigningKeyError:
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

    def lock_active(self, cursor: Any, *, tenant_ref: str, actor_ref: str,
                    key_ref: str, role: str, expected_generation: int,
                    expected_public_key: str) -> TrustedSigningKeyFence:
        """Lock and freshly recheck an active key inside a caller transaction.

        The stable key row is locked before the latest fence is read.  Under
        READ COMMITTED, a caller blocked behind a revocation sees that newly
        committed terminal fence in its next statement.
        """
        _text(tenant_ref, _TENANT)
        _text(actor_ref, _ACTOR)
        _text(key_ref, _KEY)
        if type(role) is not str or role not in _ROLES:
            _fail()
        _generation(expected_generation)
        _text(expected_public_key, _PUBLIC_KEY)
        try:
            _require_active_transaction(cursor)
            _require_read_committed(cursor)
            key = self._lock_key(cursor, tenant_ref, key_ref)
            fence = None if key is None else self._latest(cursor, key)
            if (key is None or key.tenant_ref != tenant_ref or key.actor_ref != actor_ref
                    or key.role != role or key.public_key != expected_public_key
                    or fence is None or fence.generation != expected_generation
                    or fence.state != "ACTIVE"):
                _fail()
            moment = _database_now(cursor)
            if not key.not_before <= moment < key.expires_at:
                _fail()
            return fence
        except PostgresTrustedSigningKeyError:
            raise
        except Exception:
            _fail()

    def fence(self, *, tenant_ref: str, actor_ref: str, key_ref: str,
              role: str, expected_generation: int,
              expected_public_key: str) -> TrustedSigningKeyFence:
        """Inspect a live key; issuers must instead retain ``lock_active``'s lock."""
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            value = self.lock_active(cursor, tenant_ref=tenant_ref, actor_ref=actor_ref,
                                     key_ref=key_ref, role=role,
                                     expected_generation=expected_generation,
                                     expected_public_key=expected_public_key)
            connection.commit()
            return value
        except PostgresTrustedSigningKeyError:
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

    def revoke(self, *, tenant_ref: str, actor_ref: str, key_ref: str,
               role: str, expected_generation: int,
               event_ref: str) -> TrustedSigningKeyFence:
        """Append one terminal REVOKED fence; identical retries are idempotent."""
        _text(tenant_ref, _TENANT)
        _text(actor_ref, _ACTOR)
        _text(key_ref, _KEY)
        if type(role) is not str or role not in _ROLES:
            _fail()
        _generation(expected_generation)
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            key = self._lock_key(cursor, tenant_ref, key_ref)
            latest = None if key is None else self._latest(cursor, key)
            if (key is None or key.tenant_ref != tenant_ref or key.actor_ref != actor_ref
                    or key.role != role or latest is None):
                _fail()
            if (latest.generation == expected_generation + 1 and latest.state == "REVOKED"
                    and latest.event_ref == event_ref):
                connection.commit()
                return latest
            if latest.generation != expected_generation or latest.state != "ACTIVE":
                _fail()
            moment = _database_now(cursor)
            cursor.execute(
                "INSERT INTO anonflow_trusted_signing_key_fences "
                "(tenant_ref,key_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,'REVOKED',%s,%s)",
                (tenant_ref, key_ref, expected_generation + 1, event_ref, moment))
            if cursor.rowcount != 1:
                _fail()
            result = TrustedSigningKeyFence(key, expected_generation + 1, "REVOKED", event_ref, moment)
            connection.commit()
            return result
        except PostgresTrustedSigningKeyError:
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
