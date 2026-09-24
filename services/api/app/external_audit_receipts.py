"""Verification and durable continuity checks for *externally issued* audit receipts.

This module deliberately has no private key, signing method, HTTP client, or
local-checkpoint issuer.  A caller may describe a checkpoint as externally
anchored only after it has received a receipt signed by a separately operated
anchor service and this verifier accepts it using a configured public key.

Records contain commitments and fixed metadata only: never audit events,
payload bytes, object identifiers, actors, paths, or URLs.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_SEQUENCE = 9_223_372_036_854_775_807
_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_CHECKPOINT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RECEIPT_ID = re.compile(r"auditreceipt:v1:" + _OPAQUE + r"\Z")
_SERVICE_ID = re.compile(r"external-audit-anchor:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,95}\Z")
_FINGERPRINT = _CHECKPOINT_DIGEST
_SIGNATURE = re.compile(r"external-audit-receipt-sig:v1:[A-Za-z0-9_-]{86}\Z")
_SCHEMA = "external-audit-receipt-v1"


class ExternalAuditReceiptError(ValueError):
    """Fixed error: untrusted receipt text is never reflected to callers."""

    def __init__(self) -> None:
        super().__init__("Invalid external audit receipt")


def _fail() -> None:
    raise ExternalAuditReceiptError()


def _match(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    result = value.astimezone(UTC)
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _signature(value: object) -> bytes:
    value = _match(value, _SIGNATURE)
    try:
        result = base64.urlsafe_b64decode(value.rsplit(":", 1)[1] + "==")
    except (ValueError, UnicodeError):
        _fail()
    if len(result) != 64:
        _fail()
    return result


@dataclass(frozen=True, slots=True)
class AnchorServiceKey:
    """One pinned, independently provisioned external service verification key."""

    service_id: str
    key_id: str
    public_key_b64: str = field(repr=False)
    public_key_fingerprint: str = field(init=False)
    _public_key: Ed25519PublicKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _match(self.service_id, _SERVICE_ID)
        _match(self.key_id, _KEY_ID)
        if type(self.public_key_b64) is not str or len(self.public_key_b64) != 44:
            _fail()
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
            if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != self.public_key_b64:
                _fail()
            object.__setattr__(self, "_public_key", Ed25519PublicKey.from_public_bytes(raw))
            object.__setattr__(self, "public_key_fingerprint", "sha256:" + hashlib.sha256(raw).hexdigest())
        except (ValueError, UnicodeError):
            _fail()


@dataclass(frozen=True, slots=True)
class ExternalAuditReceipt:
    """An untrusted external-service assertion until verified by a pinned key."""

    tenant_ref: str
    checkpoint_digest: str
    sequence: int
    anchored_at: datetime
    service_id: str
    key_id: str
    public_key_fingerprint: str
    receipt_id: str
    previous_receipt_digest: str | None
    signature: str = field(repr=False)

    def __post_init__(self) -> None:
        _match(self.tenant_ref, _TENANT)
        _match(self.checkpoint_digest, _CHECKPOINT_DIGEST)
        if type(self.sequence) is not int or isinstance(self.sequence, bool) or not 1 <= self.sequence <= MAX_SEQUENCE:
            _fail()
        object.__setattr__(self, "anchored_at", _time(self.anchored_at))
        _match(self.service_id, _SERVICE_ID)
        _match(self.key_id, _KEY_ID)
        _match(self.public_key_fingerprint, _FINGERPRINT)
        _match(self.receipt_id, _RECEIPT_ID)
        if self.previous_receipt_digest is not None:
            _match(self.previous_receipt_digest, _CHECKPOINT_DIGEST)
        _signature(self.signature)

    def canonical(self) -> dict[str, object]:
        return {"anchored_at": _instant(self.anchored_at), "checkpoint_digest": self.checkpoint_digest,
                "key_id": self.key_id, "previous_receipt_digest": self.previous_receipt_digest,
                "public_key_fingerprint": self.public_key_fingerprint, "receipt_id": self.receipt_id,
                "schema": _SCHEMA, "sequence": self.sequence, "service_id": self.service_id,
                "tenant_ref": self.tenant_ref}

    @property
    def digest(self) -> str:
        return _digest({**self.canonical(), "signature": self.signature})

    def to_record(self) -> dict[str, object]:
        return {**self.canonical(), "signature": self.signature, "digest": self.digest}

    @classmethod
    def from_record(cls, value: object) -> "ExternalAuditReceipt":
        expected = {"anchored_at", "checkpoint_digest", "digest", "key_id", "previous_receipt_digest",
                    "public_key_fingerprint", "receipt_id", "schema", "sequence", "service_id",
                    "signature", "tenant_ref"}
        if not isinstance(value, dict) or set(value) != expected:
            _fail()
        try:
            if value["schema"] != _SCHEMA or type(value["anchored_at"]) is not str:
                _fail()
            receipt = cls(tenant_ref=value["tenant_ref"], checkpoint_digest=value["checkpoint_digest"],
                          sequence=value["sequence"], anchored_at=datetime.fromisoformat(value["anchored_at"].replace("Z", "+00:00")),
                          service_id=value["service_id"], key_id=value["key_id"],
                          public_key_fingerprint=value["public_key_fingerprint"], receipt_id=value["receipt_id"],
                          previous_receipt_digest=value["previous_receipt_digest"], signature=value["signature"])
            if value["digest"] != receipt.digest:
                _fail()
            return receipt
        except (TypeError, ValueError, KeyError, OverflowError, ExternalAuditReceiptError):
            _fail()


class ExternalAuditReceiptVerifier:
    """Strict verifier with no signing capability and no implicit trust roots."""

    def __init__(self, keys: Iterable[AnchorServiceKey]) -> None:
        if isinstance(keys, (str, bytes)):
            _fail()
        items = tuple(keys)
        if (not items or any(type(item) is not AnchorServiceKey for item in items)
                or len({(item.service_id, item.key_id) for item in items}) != len(items)):
            _fail()
        self._keys = {(item.service_id, item.key_id): item for item in items}

    def verify(self, receipt: object, *, tenant_ref: str, checkpoint_digest: str,
               at: datetime, previous: ExternalAuditReceipt | None = None) -> bool:
        try:
            _match(tenant_ref, _TENANT)
            _match(checkpoint_digest, _CHECKPOINT_DIGEST)
            moment = _time(at)
            if (type(receipt) is not ExternalAuditReceipt or receipt.tenant_ref != tenant_ref
                    or receipt.checkpoint_digest != checkpoint_digest or receipt.anchored_at > moment):
                return False
            key = self._keys.get((receipt.service_id, receipt.key_id))
            if key is None or receipt.public_key_fingerprint != key.public_key_fingerprint:
                return False
            if previous is None:
                if receipt.sequence != 1 or receipt.previous_receipt_digest is not None:
                    return False
            elif (type(previous) is not ExternalAuditReceipt or receipt.sequence != previous.sequence + 1
                  or receipt.previous_receipt_digest != previous.digest or receipt.tenant_ref != previous.tenant_ref):
                return False
            key._public_key.verify(_signature(receipt.signature), b"external-audit-receipt-v1:" + _canonical(receipt.canonical()))
            return True
        except (InvalidSignature, ValueError, UnicodeError, ExternalAuditReceiptError):
            return False


class ExternalAuditReceiptStore:
    """SQLite continuity ledger; accepts only verified, next-in-chain receipts.

    The database protects against duplicate/replayed and lower-sequence receipts
    across restarts.  It cannot detect an attacker who restores the *entire*
    database to an older valid snapshot; callers should retain the returned head
    digest in an independent system and compare it via ``head`` before trusting
    a restored store.
    """

    def __init__(self, path: str | Path, verifier: ExternalAuditReceiptVerifier) -> None:
        if type(verifier) is not ExternalAuditReceiptVerifier:
            _fail()
        self._verifier = verifier
        target = Path(path)
        if not target.name or target.is_symlink():
            _fail()
        target.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(target), isolation_level=None, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("CREATE TABLE IF NOT EXISTS external_audit_receipts (tenant TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL UNIQUE, record BLOB NOT NULL, PRIMARY KEY(tenant, sequence))")
        if os.name != "nt" and target.exists():
            os.chmod(target, 0o600)

    def close(self) -> None:
        self._connection.close()

    def _chain(self, tenant_ref: str, *, at: datetime) -> tuple[ExternalAuditReceipt, ...]:
        """Load and re-verify every persisted link before it becomes a parent."""
        rows = self._connection.execute("SELECT record FROM external_audit_receipts WHERE tenant=? ORDER BY sequence", (tenant_ref,)).fetchall()
        prior = None
        result = []
        for (encoded,) in rows:
            try:
                item = ExternalAuditReceipt.from_record(json.loads(encoded))
            except (TypeError, ValueError, UnicodeError, ExternalAuditReceiptError):
                _fail()
            if not self._verifier.verify(item, tenant_ref=tenant_ref, checkpoint_digest=item.checkpoint_digest,
                                         at=at, previous=prior):
                _fail()
            result.append(item)
            prior = item
        return tuple(result)

    def head(self, tenant_ref: str, *, at: datetime | None = None) -> ExternalAuditReceipt | None:
        _match(tenant_ref, _TENANT)
        moment = _time(at) if at is not None else datetime.now(UTC).replace(microsecond=0)
        chain = self._chain(tenant_ref, at=moment)
        return chain[-1] if chain else None

    def accept(self, receipt: object, *, tenant_ref: str, checkpoint_digest: str, at: datetime) -> ExternalAuditReceipt:
        _match(tenant_ref, _TENANT)
        _match(checkpoint_digest, _CHECKPOINT_DIGEST)
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            chain = self._chain(tenant_ref, at=_time(at))
            previous = chain[-1] if chain else None
            if not self._verifier.verify(receipt, tenant_ref=tenant_ref, checkpoint_digest=checkpoint_digest,
                                         at=at, previous=previous):
                _fail()
            assert type(receipt) is ExternalAuditReceipt
            encoded = _canonical(receipt.to_record())
            self._connection.execute("INSERT INTO external_audit_receipts(tenant,sequence,digest,record) VALUES(?,?,?,?)", (tenant_ref, receipt.sequence, receipt.digest, encoded))
            if self._connection.execute("SELECT changes()").fetchone()[0] != 1:
                _fail()
            self._connection.execute("COMMIT")
            return receipt
        except Exception:
            self._connection.execute("ROLLBACK")
            raise ExternalAuditReceiptError() from None
