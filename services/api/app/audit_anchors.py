"""Source-safe signed checkpoints for a future externally anchored audit trail.

This module does *not* perform an external anchor operation.  It makes the
local hand-off to one well-defined: a private authority signs only opaque audit
chain heads and bounded control metadata.  A later connector must retain and
verify an independent external receipt before it may truthfully describe a
checkpoint as externally anchored.

No source content, object identifiers, event bodies, actor/subject values,
paths, URLs, or raw audit MACs are accepted or emitted here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import re
import threading


MAX_SEQUENCE = 9_223_372_036_854_775_807
MAX_LEASE = timedelta(hours=24)
_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT_REF = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_CHAIN_COMMITMENT = re.compile(r"audithead:v1:" + _OPAQUE + r"\Z")
_CHECKPOINT_ID = re.compile(r"auditcp:v1:" + _OPAQUE + r"\Z")
_AUTHORITY_ID = re.compile(r"audit-authority-v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"auditsig:v1:" + _OPAQUE + r"\Z")

CHECKPOINT_STATE = "SIGNED_CHECKPOINT_ONLY"
LIMITATIONS = (
    "NO_EXTERNAL_ANCHOR_RECORD",
    "NO_RELEASE_AUTHORIZATION",
    "NON_PRODUCTION_KEY_CUSTODY",
)


class AuditAnchorError(ValueError):
    """Fixed validation error that never interpolates supplied metadata."""

    def __init__(self) -> None:
        super().__init__("Invalid audit anchor checkpoint")


def _fail() -> None:
    raise AuditAnchorError()


def _opaque(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        _fail()
    return value


def _sequence(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= MAX_SEQUENCE:
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    normalised = value.astimezone(UTC)
    # Milliseconds can be an accidental source of distinct serialization across
    # systems.  Require an already-canonical whole-second instant instead.
    if normalised.microsecond:
        _fail()
    return normalised


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _encoded_signature(value: bytes) -> str:
    return "auditsig:v1:" + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _signature_bytes(value: object) -> bytes | None:
    if type(value) is not str or not _SIGNATURE.fullmatch(value):
        return None
    try:
        decoded = base64.urlsafe_b64decode(value.rsplit(":", 1)[1] + "=")
    except (ValueError, UnicodeError):
        return None
    return decoded if len(decoded) == 32 else None


@dataclass(frozen=True, slots=True)
class AuditAnchorCheckpoint:
    """One signed local checkpoint, explicitly not an external anchor receipt."""

    tenant_ref: str
    checkpoint_id: str
    sequence: int
    audit_chain_commitment: str
    previous_checkpoint_digest: str | None
    issued_at: datetime
    expires_at: datetime
    authority_id: str
    signature: str
    checkpoint_state: str = CHECKPOINT_STATE
    limitations: tuple[str, ...] = LIMITATIONS
    _authority_verified: bool = field(init=False, default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _opaque(self.tenant_ref, _TENANT_REF)
        _opaque(self.checkpoint_id, _CHECKPOINT_ID)
        _sequence(self.sequence)
        _opaque(self.audit_chain_commitment, _CHAIN_COMMITMENT)
        if self.previous_checkpoint_digest is not None:
            _opaque(self.previous_checkpoint_digest, _DIGEST)
        issued = _time(self.issued_at)
        expires = _time(self.expires_at)
        if not issued < expires <= issued + MAX_LEASE:
            _fail()
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        _opaque(self.authority_id, _AUTHORITY_ID)
        if _signature_bytes(self.signature) is None:
            _fail()
        if (self.checkpoint_state != CHECKPOINT_STATE or type(self.limitations) is not tuple
                or self.limitations != LIMITATIONS):
            _fail()

    def _signed_fields(self) -> dict[str, object]:
        return {
            "audit_chain_commitment": self.audit_chain_commitment,
            "authority_id": self.authority_id,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_state": self.checkpoint_state,
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "issued_at": self.issued_at.isoformat().replace("+00:00", "Z"),
            "limitations": list(self.limitations),
            "previous_checkpoint_digest": self.previous_checkpoint_digest,
            "schema": "audit-anchor-checkpoint-v1",
            "sequence": self.sequence,
            "tenant_ref": self.tenant_ref,
        }

    @property
    def digest(self) -> str:
        """Opaque digest of the exact source-safe signed checkpoint record."""
        return _digest({**self._signed_fields(), "signature": self.signature})

    def to_record(self) -> dict[str, object]:
        """Return only a verified record; unsigned lookalikes cannot be persisted."""
        if not self._authority_verified:
            _fail()
        return {**self._signed_fields(), "signature": self.signature, "digest": self.digest}


class AuditAnchorAuthority:
    """Private issuer/verifier with in-memory replay protection for one tenant.

    The authority is intentionally small and ephemeral.  ``claim`` is for an
    external-anchor adapter to consume a particular checkpoint once; ``verify``
    remains repeatable for later audit inspection.
    """

    def __init__(self, *, tenant_ref: str, authority_id: str, key: bytes) -> None:
        self.tenant_ref = _opaque(tenant_ref, _TENANT_REF)
        self.authority_id = _opaque(authority_id, _AUTHORITY_ID)
        if type(key) is not bytes or not 32 <= len(key) <= 64:
            _fail()
        self._key = key
        self._last_sequence = 0
        self._last_digest: str | None = None
        self._seen_checkpoint_ids: set[str] = set()
        self._seen_chain_commitments: set[str] = set()
        self._claimed_digests: set[str] = set()
        # This protects the atomic state transitions below.  It intentionally
        # provides no cross-process coordination; production needs durable,
        # shared compare-and-swap semantics at the external anchor boundary.
        self._lock = threading.RLock()

    def _message(self, checkpoint: AuditAnchorCheckpoint) -> bytes:
        return _canonical(checkpoint._signed_fields())

    def _mark_verified(self, checkpoint: AuditAnchorCheckpoint) -> AuditAnchorCheckpoint:
        object.__setattr__(checkpoint, "_authority_verified", True)
        return checkpoint

    def issue(self, *, checkpoint_id: str, sequence: int, audit_chain_commitment: str,
              previous_checkpoint_digest: str | None, issued_at: datetime,
              expires_at: datetime) -> AuditAnchorCheckpoint:
        """Issue the next exact head checkpoint or fail closed on replay/fork."""
        # All validation, parent/head checks, signing and state mutation share
        # one critical section.  Otherwise two workers can both observe the
        # same head and issue competing checkpoints.
        with self._lock:
            checkpoint_id = _opaque(checkpoint_id, _CHECKPOINT_ID)
            audit_chain_commitment = _opaque(audit_chain_commitment, _CHAIN_COMMITMENT)
            sequence = _sequence(sequence)
            if previous_checkpoint_digest is not None:
                _opaque(previous_checkpoint_digest, _DIGEST)
            # Sequential parent binding prevents a caller from silently anchoring a
            # different local history branch.  A repeated head cannot create a new
            # checkpoint either.
            if (checkpoint_id in self._seen_checkpoint_ids
                    or audit_chain_commitment in self._seen_chain_commitments
                    or sequence != self._last_sequence + 1
                    or previous_checkpoint_digest != self._last_digest):
                _fail()
            unsigned = AuditAnchorCheckpoint(
                tenant_ref=self.tenant_ref, checkpoint_id=checkpoint_id, sequence=sequence,
                audit_chain_commitment=audit_chain_commitment,
                previous_checkpoint_digest=previous_checkpoint_digest, issued_at=issued_at,
                expires_at=expires_at, authority_id=self.authority_id,
                signature=_encoded_signature(b"\0" * 32),
            )
            signature = _encoded_signature(hmac.new(self._key, self._message(unsigned), hashlib.sha256).digest())
            result = AuditAnchorCheckpoint(
                tenant_ref=unsigned.tenant_ref, checkpoint_id=unsigned.checkpoint_id,
                sequence=unsigned.sequence, audit_chain_commitment=unsigned.audit_chain_commitment,
                previous_checkpoint_digest=unsigned.previous_checkpoint_digest, issued_at=unsigned.issued_at,
                expires_at=unsigned.expires_at, authority_id=unsigned.authority_id, signature=signature,
            )
            self._seen_checkpoint_ids.add(checkpoint_id)
            self._seen_chain_commitments.add(audit_chain_commitment)
            self._last_sequence = sequence
            self._last_digest = result.digest
            return self._mark_verified(result)

    def verify(self, checkpoint: object, *, tenant_ref: str, at: datetime) -> bool:
        """Verify exact authority, tenant, canonical signature and time window."""
        try:
            _opaque(tenant_ref, _TENANT_REF)
            now = _time(at)
            # A subclass could override the private canonicalizer.  Evidence
            # verification is a trust boundary, so admit the exact immutable
            # record type only.
            if (type(checkpoint) is not AuditAnchorCheckpoint
                    or checkpoint.tenant_ref != self.tenant_ref or tenant_ref != self.tenant_ref
                    or checkpoint.authority_id != self.authority_id
                    or now < checkpoint.issued_at or now >= checkpoint.expires_at):
                return False
            supplied = _signature_bytes(checkpoint.signature)
            if supplied is None:
                return False
            expected = hmac.new(self._key, self._message(checkpoint), hashlib.sha256).digest()
            return hmac.compare_digest(supplied, expected)
        except AuditAnchorError:
            return False

    def restore(self, value: object, *, tenant_ref: str, at: datetime) -> AuditAnchorCheckpoint:
        """Parse a stored record only after strict, tenant-bound verification."""
        expected = {"audit_chain_commitment", "authority_id", "checkpoint_id", "checkpoint_state",
                    "digest", "expires_at", "issued_at", "limitations", "previous_checkpoint_digest",
                    "schema", "sequence", "signature", "tenant_ref"}
        if not isinstance(value, dict) or set(value) != expected:
            _fail()
        try:
            if value["schema"] != "audit-anchor-checkpoint-v1" or type(value["issued_at"]) is not str or type(value["expires_at"]) is not str:
                _fail()
            limitations = value["limitations"]
            if type(limitations) is not list:
                _fail()
            checkpoint = AuditAnchorCheckpoint(
                tenant_ref=value["tenant_ref"], checkpoint_id=value["checkpoint_id"], sequence=value["sequence"],
                audit_chain_commitment=value["audit_chain_commitment"], previous_checkpoint_digest=value["previous_checkpoint_digest"],
                issued_at=datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00")),
                expires_at=datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")),
                authority_id=value["authority_id"], signature=value["signature"],
                checkpoint_state=value["checkpoint_state"], limitations=tuple(limitations),
            )
            if value["digest"] != checkpoint.digest or not self.verify(checkpoint, tenant_ref=tenant_ref, at=at):
                _fail()
            return self._mark_verified(checkpoint)
        except (TypeError, ValueError, KeyError, OverflowError, AuditAnchorError):
            _fail()

    def claim(self, checkpoint: object, *, tenant_ref: str, at: datetime) -> bool:
        """Consume a verified checkpoint once for an external-anchor adapter.

        This is deliberately separate from ``verify``: replay-resistant anchor
        submission is a state transition, whereas later evidence inspection is
        expected to be repeatable.
        """
        with self._lock:
            if not self.verify(checkpoint, tenant_ref=tenant_ref, at=at):
                return False
            assert type(checkpoint) is AuditAnchorCheckpoint
            digest = checkpoint.digest
            if digest in self._claimed_digests:
                return False
            self._claimed_digests.add(digest)
            return True
