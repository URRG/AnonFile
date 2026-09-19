"""Fail-closed rights and buyer-purpose gating domain primitives.

This module deliberately does *not* approve, export, or otherwise release an
artifact.  It records a request which is either denied immediately or remains
pending for a separate, independent review workflow.  Identifiers are policy
labels, never free-form descriptions or source-data values.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Iterable, Mapping


_TOKEN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class RightsError(ValueError):
    """A deliberately fixed-message validation failure for rights metadata."""


class GateReason(StrEnum):
    ALLOWED = "allowed"
    RIGHTS_UNKNOWN = "rights_unknown"
    RIGHTS_EXPIRED = "rights_expired"
    PURPOSE_DENIED = "purpose_denied"
    RECIPIENT_DENIED = "recipient_denied"
    RESALE_DENIED = "resale_denied"


class AuthorizationStatus(StrEnum):
    """There is intentionally no approved/exportable status in this layer."""

    PENDING = "PENDING"
    DENIED = "DENIED"


def _token(value: object, *, message: str = "Invalid rights metadata") -> str:
    if type(value) is not str:
        raise RightsError(message)
    normalized = value.strip().lower()
    if normalized != value or not _TOKEN.fullmatch(normalized) or "*" in normalized:
        raise RightsError(message)
    return normalized


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise RightsError("Invalid digest")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RightsError("Invalid rights expiry")
    return value.astimezone(UTC).replace(microsecond=0)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _profile_payload(profile_id: str, version: str, purposes: frozenset[str], recipients: frozenset[str], expires_at: datetime, resale_allowed: bool) -> dict[str, object]:
    return {
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "permitted_purposes": sorted(purposes),
        "permitted_recipients": sorted(recipients),
        "profile_id": profile_id,
        "resale_allowed": resale_allowed,
        "version": version,
    }


def _labels(values: Iterable[str], *, message: str) -> frozenset[str]:
    # Strings are iterable, but accepting one would make a typo silently turn
    # into a collection of one-character policy labels.
    if isinstance(values, (str, bytes)):
        raise RightsError(message)
    try:
        received = tuple(values)
    except TypeError:
        raise RightsError(message) from None
    normalized = tuple(_token(item, message=message) for item in received)
    if len(normalized) != len(set(normalized)):
        raise RightsError(message)
    return frozenset(normalized)


@dataclass(frozen=True, slots=True)
class RightsProfile:
    """A normalized, immutable policy assertion supplied by the data owner."""

    profile_id: str
    version: str
    permitted_purposes: frozenset[str]
    permitted_recipients: frozenset[str]
    expires_at: datetime
    resale_allowed: bool
    _digest: str = field(init=False, repr=False, compare=True)

    @classmethod
    def create(
        cls,
        *,
        profile_id: str,
        version: str,
        permitted_purposes: Iterable[str],
        permitted_recipients: Iterable[str],
        expires_at: datetime,
        resale_allowed: bool,
    ) -> "RightsProfile":
        if type(resale_allowed) is not bool:
            raise RightsError("Invalid rights metadata")
        return cls(
            profile_id=_token(profile_id),
            version=_token(version),
            permitted_purposes=_labels(permitted_purposes, message="Invalid permitted purposes"),
            permitted_recipients=_labels(permitted_recipients, message="Invalid permitted recipients"),
            expires_at=_timestamp(expires_at),
            resale_allowed=resale_allowed,
        )

    def __post_init__(self) -> None:
        # Validate the direct dataclass constructor too.  This closes the easy
        # bypass around ``create`` while retaining a simple serializable type.
        object.__setattr__(self, "profile_id", _token(self.profile_id))
        object.__setattr__(self, "version", _token(self.version))
        if type(self.resale_allowed) is not bool:
            raise RightsError("Invalid rights metadata")
        purposes = _labels(self.permitted_purposes, message="Invalid permitted purposes")
        recipients = _labels(self.permitted_recipients, message="Invalid permitted recipients")
        object.__setattr__(self, "permitted_purposes", purposes)
        object.__setattr__(self, "permitted_recipients", recipients)
        expires_at = _timestamp(self.expires_at)
        object.__setattr__(self, "expires_at", expires_at)
        digest = hashlib.sha256(_canonical(_profile_payload(self.profile_id, self.version, purposes, recipients, expires_at, self.resale_allowed))).hexdigest()
        object.__setattr__(self, "_digest", digest)

    @property
    def digest(self) -> str:
        return self._digest

    def to_record(self) -> dict[str, object]:
        return {**_profile_payload(self.profile_id, self.version, self.permitted_purposes, self.permitted_recipients, self.expires_at, self.resale_allowed), "digest": self.digest}

    @classmethod
    def from_record(cls, value: object) -> "RightsProfile":
        if not isinstance(value, dict) or set(value) != {
            "profile_id", "version", "permitted_purposes", "permitted_recipients", "expires_at", "resale_allowed", "digest"
        }:
            raise RightsError("Invalid rights record")
        try:
            if type(value["expires_at"]) is not str or type(value["permitted_purposes"]) is not list or type(value["permitted_recipients"]) is not list:
                raise ValueError
            expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
            profile = cls.create(
                profile_id=value["profile_id"], version=value["version"],
                permitted_purposes=value["permitted_purposes"], permitted_recipients=value["permitted_recipients"],
                expires_at=expiry, resale_allowed=value["resale_allowed"],
            )
            provided = _digest(value["digest"])
        except (TypeError, ValueError, OverflowError):
            raise RightsError("Invalid rights record") from None
        if provided != profile.digest:
            raise RightsError("Rights record integrity failure")
        return profile


@dataclass(frozen=True, slots=True)
class RightsGate:
    allowed: bool
    reason: GateReason
    rights_digest: str | None = None


def evaluate_rights(profile: RightsProfile, *, purpose: str, recipient: str, at: datetime | None = None, for_resale: bool = True) -> RightsGate:
    """Check an exact purpose/recipient request without wildcard semantics."""
    if not isinstance(profile, RightsProfile) or type(for_resale) is not bool:
        raise RightsError("Invalid rights request")
    purpose_label = _token(purpose, message="Invalid rights request")
    recipient_label = _token(recipient, message="Invalid rights request")
    instant = _timestamp(datetime.now(UTC) if at is None else at)
    if instant >= profile.expires_at:
        return RightsGate(False, GateReason.RIGHTS_EXPIRED, profile.digest)
    if purpose_label not in profile.permitted_purposes:
        return RightsGate(False, GateReason.PURPOSE_DENIED, profile.digest)
    if recipient_label not in profile.permitted_recipients:
        return RightsGate(False, GateReason.RECIPIENT_DENIED, profile.digest)
    if for_resale and not profile.resale_allowed:
        return RightsGate(False, GateReason.RESALE_DENIED, profile.digest)
    return RightsGate(True, GateReason.ALLOWED, profile.digest)


def resolve_rights(profiles: Mapping[str, RightsProfile], *, profile_id: str, purpose: str, recipient: str, at: datetime | None = None, for_resale: bool = True) -> RightsGate:
    """Resolve by exact ID and deny unknown/malformed registry entries safely."""
    identifier = _token(profile_id, message="Invalid rights request")
    profile = profiles.get(identifier)
    if not isinstance(profile, RightsProfile) or profile.profile_id != identifier:
        return RightsGate(False, GateReason.RIGHTS_UNKNOWN)
    return evaluate_rights(profile, purpose=purpose, recipient=recipient, at=at, for_resale=for_resale)


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """An immutable, non-authorizing request tied to the exact evaluated inputs."""

    request_id: str
    artifact_digest: str
    policy_digest: str
    rights_digest: str | None
    buyer: str
    purpose: str
    requested_at: datetime
    status: AuthorizationStatus
    reason: GateReason

    def to_record(self) -> dict[str, str | None]:
        return {
            "request_id": self.request_id, "artifact_digest": self.artifact_digest,
            "policy_digest": self.policy_digest, "rights_digest": self.rights_digest,
            "buyer": self.buyer, "purpose": self.purpose,
            "requested_at": self.requested_at.isoformat().replace("+00:00", "Z"),
            "status": self.status.value, "reason": self.reason.value,
        }


def request_authorization(
    profiles: Mapping[str, RightsProfile], *, request_id: str, profile_id: str,
    artifact_digest: str, policy_digest: str, rights_digest: str | None,
    buyer: str, purpose: str, at: datetime | None = None, for_resale: bool = True,
) -> AuthorizationRequest:
    """Create only PENDING or DENIED state; never a release authorization."""
    identifier = _token(request_id, message="Invalid authorization request")
    artifact = _digest(artifact_digest)
    policy = _digest(policy_digest)
    buyer_label = _token(buyer, message="Invalid authorization request")
    purpose_label = _token(purpose, message="Invalid authorization request")
    instant = _timestamp(datetime.now(UTC) if at is None else at)
    gate = resolve_rights(profiles, profile_id=profile_id, purpose=purpose_label, recipient=buyer_label, at=instant, for_resale=for_resale)
    # A caller cannot pin a stale or substituted rights revision while the
    # profile permits the request.  Unknown rights have no expected digest.
    supplied = None if rights_digest is None else _digest(rights_digest)
    if gate.rights_digest is not None and supplied != gate.rights_digest:
        gate = RightsGate(False, GateReason.RIGHTS_UNKNOWN, gate.rights_digest)
    status = AuthorizationStatus.PENDING if gate.allowed else AuthorizationStatus.DENIED
    return AuthorizationRequest(identifier, artifact, policy, gate.rights_digest, buyer_label, purpose_label, instant, status, gate.reason)


def require_independent_reviewer(*, creator_subject: str, reviewer_subject: str) -> None:
    """Reject self-review without exposing either subject in an error message."""
    creator = _token(creator_subject, message="Invalid reviewer")
    reviewer = _token(reviewer_subject, message="Invalid reviewer")
    if creator == reviewer:
        raise RightsError("Independent reviewer required")
