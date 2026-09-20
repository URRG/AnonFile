"""Bounded, source-safe linkage and re-identification risk evidence.

This trusted-worker primitive compares a private structured candidate with an
external reference *representation*.  The representation contains HMAC tokens
only; source reference records, selected field names, paths, values and raw
hashes never enter an output report.  The result is observational evidence,
not a privacy guarantee, release decision, or delivery authorization.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
import base64
import hashlib
import hmac
import json
import math
import re
from typing import Any, Iterable

from .candidate import CandidateArtifact, CandidateError, PayloadKind


MAX_RECORDS = 10_000
MAX_LINKAGE_KEYS = 32
MAX_FIELD_NAME_BYTES = 128
MAX_TOKEN_INPUT_BYTES = 65_536
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_KEY_COMMITMENT = re.compile(r"linkcfg:v1:[A-Za-z0-9_-]{43}\Z")
_REFERENCE_COMMITMENT = re.compile(r"linkref:v1:[A-Za-z0-9_-]{43}\Z")
_PERCENT_SCALE = 100
_METHODOLOGY = {
    "algorithm": "hmac-token-one-to-one-linkage",
    "revision": "m11-v1",
    "version": 1,
}


class LinkageRiskError(ValueError):
    """Fixed error surface; private data is never reflected."""

    MESSAGE = "Invalid linkage-risk assessment."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class LinkageRiskStatus(StrEnum):
    ASSESSED = "ASSESSED"
    ABSTAINED = "ABSTAINED"


class LinkageRiskAbstention(StrEnum):
    REFERENCE_COMMITMENT_UNVERIFIED = "REFERENCE_COMMITMENT_UNVERIFIED"
    TEXT_PAYLOAD = "TEXT_PAYLOAD"
    UNSUPPORTED_RECORD_SHAPE = "UNSUPPORTED_RECORD_SHAPE"
    EMPTY_CANDIDATE = "EMPTY_CANDIDATE"
    CANDIDATE_RECORD_LIMIT_EXCEEDED = "CANDIDATE_RECORD_LIMIT_EXCEEDED"
    EMPTY_REFERENCE = "EMPTY_REFERENCE"
    LINKAGE_KEYS_NOT_APPLICABLE = "LINKAGE_KEYS_NOT_APPLICABLE"


def _fail() -> None:
    raise LinkageRiskError()


def _canonical(value: object, *, maximum: int = MAX_TOKEN_INPUT_BYTES) -> bytes:
    try:
        rendered = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                              separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    if len(rendered) > maximum:
        _fail()
    return rendered


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _opaque(prefix: str, value: bytes) -> str:
    return prefix + base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _is_scalar(value: object) -> bool:
    return (value is None or type(value) in (str, int, bool)
            or (type(value) is float and math.isfinite(value)))


def _normalise_fields(fields: Iterable[str]) -> tuple[str, ...]:
    if isinstance(fields, (str, bytes)):
        _fail()
    try:
        selected = tuple(fields)
    except TypeError:
        _fail()
    if (not 1 <= len(selected) <= MAX_LINKAGE_KEYS
            or any(type(item) is not str or not _FIELD.fullmatch(item) for item in selected)
            or len(set(selected)) != len(selected)):
        _fail()
    try:
        if any(len(item.encode("utf-8")) > MAX_FIELD_NAME_BYTES for item in selected):
            _fail()
    except UnicodeError:
        _fail()
    return tuple(sorted(selected))


@dataclass(frozen=True, slots=True)
class LinkageCommitmentAuthority:
    """Private HMAC issuer for linkage keys and reference representations.

    The caller owns this 32--64 byte secret.  It is never generated,
    persisted, serialized, or exposed by this module.  HMAC record tokens are
    deliberately scoped to this authority and cannot be replaced by raw
    hashes, so a public report does not permit a value dictionary attack.
    """

    _secret: bytes = field(repr=False, compare=False)

    @classmethod
    def from_secret(cls, secret: bytes) -> "LinkageCommitmentAuthority":
        return cls(_secret=secret)

    def __post_init__(self) -> None:
        if type(self._secret) is not bytes or not 32 <= len(self._secret) <= 64:
            _fail()

    def _mac(self, purpose: str, payload: object, *, prefix: str) -> str:
        message = _canonical({"purpose": purpose, "payload": payload, "version": 1}, maximum=1_500_000)
        return _opaque(prefix, hmac.new(self._secret, message, hashlib.sha256).digest())

    def issue_key_config(self, fields: Iterable[str]) -> "LinkageKeyConfig":
        normalised = _normalise_fields(fields)
        return LinkageKeyConfig(_fields=normalised,
                                _public_commitment=self._mac("linkage-key-config", list(normalised),
                                                             prefix="linkcfg:v1:"))

    def verifies_key_config(self, config: "LinkageKeyConfig") -> bool:
        # This is a trust boundary.  A subclass could override a public
        # property after its private fields have been checked, so only the
        # exact immutable record type is admitted.
        if type(config) is not LinkageKeyConfig:
            return False
        try:
            expected = self._mac("linkage-key-config", list(config._fields), prefix="linkcfg:v1:")
            return hmac.compare_digest(expected, config._public_commitment)
        except LinkageRiskError:
            return False

    def _record_token(self, values: tuple[object, ...]) -> bytes:
        if not all(_is_scalar(value) for value in values):
            _fail()
        message = _canonical({"purpose": "linkage-record", "values": values, "version": 1})
        return hmac.new(self._secret, message, hashlib.sha256).digest()

    def create_reference(self, records: object, *, linkage_keys: "LinkageKeyConfig") -> "LinkageReference":
        """Create a HMAC-token-only reference representation from private rows.

        Invalid raw reference input is rejected at construction.  The
        assessment function later turns a missing, forged, wrong-key, or
        malformed representation into an explicit no-metrics abstention.
        """
        if not self.verifies_key_config(linkage_keys):
            _fail()
        tokens = _tokenise_records(records, linkage_keys, self)
        token_text = [base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii") for token in tokens]
        commitment = self._mac("linkage-reference", {
            "key_commitment": linkage_keys.public_commitment,
            "tokens": token_text,
        }, prefix="linkref:v1:")
        return LinkageReference(_tokens=tokens, _key_commitment=linkage_keys.public_commitment,
                                _public_commitment=commitment)

    def verifies_reference(self, reference: "LinkageReference", *, linkage_keys: "LinkageKeyConfig") -> bool:
        if (type(reference) is not LinkageReference or not self.verifies_key_config(linkage_keys)
                or reference._key_commitment != linkage_keys._public_commitment):
            return False
        try:
            token_text = [base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii") for token in reference._tokens]
            expected = self._mac("linkage-reference", {
                "key_commitment": linkage_keys._public_commitment,
                "tokens": token_text,
            }, prefix="linkref:v1:")
            return hmac.compare_digest(expected, reference.public_commitment)
        except (LinkageRiskError, TypeError, ValueError, UnicodeError):
            return False


@dataclass(frozen=True, slots=True)
class LinkageKeyConfig:
    """Private top-level linkage-key selection with an opaque HMAC token."""

    _fields: tuple[str, ...] = field(repr=False, compare=True)
    _public_commitment: str = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        if (type(self._fields) is not tuple or type(self._public_commitment) is not str
                or not _KEY_COMMITMENT.fullmatch(self._public_commitment)
                or _normalise_fields(self._fields) != self._fields):
            _fail()

    @property
    def field_count(self) -> int:
        return len(self._fields)

    @property
    def public_commitment(self) -> str:
        return self._public_commitment


@dataclass(frozen=True, slots=True)
class LinkageReference:
    """Private external reference representation containing only HMAC tokens."""

    _tokens: tuple[bytes, ...] = field(repr=False, compare=True)
    _key_commitment: str = field(repr=False, compare=True)
    _public_commitment: str = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        if (type(self._tokens) is not tuple or not 0 <= len(self._tokens) <= MAX_RECORDS
                or any(type(token) is not bytes or len(token) != 32 for token in self._tokens)
                or tuple(sorted(self._tokens)) != self._tokens
                or type(self._key_commitment) is not str or not _KEY_COMMITMENT.fullmatch(self._key_commitment)
                or type(self._public_commitment) is not str or not _REFERENCE_COMMITMENT.fullmatch(self._public_commitment)):
            _fail()

    @property
    def record_count(self) -> int:
        return len(self._tokens)

    @property
    def public_commitment(self) -> str:
        return self._public_commitment


def _tokenise_records(records: object, linkage_keys: LinkageKeyConfig,
                      authority: LinkageCommitmentAuthority) -> tuple[bytes, ...]:
    if type(records) is not list:
        _fail()
    if len(records) > MAX_RECORDS or any(type(record) is not dict for record in records):
        _fail()
    tokens: list[bytes] = []
    for record in records:
        try:
            values = tuple(record[name] for name in linkage_keys._fields)
        except KeyError:
            _fail()
        tokens.append(authority._record_token(values))
    return tuple(sorted(tokens))


@dataclass(frozen=True, slots=True)
class LinkageRiskReport:
    """Digest-bound aggregate linkage evidence without any key/value output."""

    candidate_artifact_digest: str
    candidate_schema_digest: str
    linkage_key_commitment: str
    reference_commitment: str
    linkage_key_count: int
    methodology_digest: str
    status: LinkageRiskStatus
    abstention_reason: LinkageRiskAbstention | None
    candidate_record_count: int | None
    reference_record_count: int | None
    matched_record_count: int | None
    unique_match_count: int | None
    ambiguous_match_count: int | None
    match_coverage_percent: str | None
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        for value in (self.candidate_artifact_digest, self.candidate_schema_digest, self.methodology_digest):
            if type(value) is not str or not _DIGEST.fullmatch(value):
                _fail()
        if (type(self.linkage_key_commitment) is not str or not _KEY_COMMITMENT.fullmatch(self.linkage_key_commitment)
                or type(self.reference_commitment) is not str or not _REFERENCE_COMMITMENT.fullmatch(self.reference_commitment)
                or type(self.linkage_key_count) is not int or not 1 <= self.linkage_key_count <= MAX_LINKAGE_KEYS
                or not isinstance(self.status, LinkageRiskStatus)):
            _fail()
        metrics = (self.candidate_record_count, self.reference_record_count, self.matched_record_count,
                   self.unique_match_count, self.ambiguous_match_count, self.match_coverage_percent)
        if self.status is LinkageRiskStatus.ABSTAINED:
            if not isinstance(self.abstention_reason, LinkageRiskAbstention) or any(value is not None for value in metrics):
                _fail()
        elif (self.abstention_reason is not None
              or any(type(value) is not int or value < 0 for value in metrics[:5])
              or type(self.candidate_record_count) is not int or not 1 <= self.candidate_record_count <= MAX_RECORDS
              or type(self.reference_record_count) is not int or not 1 <= self.reference_record_count <= MAX_RECORDS
              or type(self.matched_record_count) is not int or self.matched_record_count > self.candidate_record_count
              or type(self.unique_match_count) is not int or self.unique_match_count > self.matched_record_count
              or type(self.ambiguous_match_count) is not int
              or self.ambiguous_match_count + self.unique_match_count != self.matched_record_count
              or type(self.match_coverage_percent) is not str
              or not re.fullmatch(r"(?:0|[1-9][0-9]?|100)\.[0-9]{2}", self.match_coverage_percent)
              or self.match_coverage_percent != _percent(self.matched_record_count, self.candidate_record_count)):
            _fail()
        object.__setattr__(self, "digest", _digest(_canonical(self._record_without_digest(), maximum=65_536)))

    def _record_without_digest(self) -> dict[str, object]:
        return {
            "abstention_reason": self.abstention_reason.value if self.abstention_reason else None,
            "ambiguous_match_count": self.ambiguous_match_count,
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_record_count": self.candidate_record_count,
            "candidate_schema_digest": self.candidate_schema_digest,
            "linkage_key_commitment": self.linkage_key_commitment,
            "linkage_key_count": self.linkage_key_count,
            "match_coverage_percent": self.match_coverage_percent,
            "matched_record_count": self.matched_record_count,
            "methodology_digest": self.methodology_digest,
            "reference_commitment": self.reference_commitment,
            "reference_record_count": self.reference_record_count,
            "status": self.status.value,
            "unique_match_count": self.unique_match_count,
            "version": 1,
        }

    def to_record(self) -> dict[str, object]:
        """Return only opaque commitments and deterministic aggregate evidence."""
        return {**self._record_without_digest(), "digest": self.digest}

    @classmethod
    def from_record(cls, value: object) -> "LinkageRiskReport":
        if not isinstance(value, dict):
            _fail()
        expected = set(cls.__dataclass_fields__) - {"digest"}
        expected.update({"digest", "version"})
        if set(value) != expected or value.get("version") != 1 or type(value.get("digest")) is not str:
            _fail()
        try:
            report = cls(
                candidate_artifact_digest=value["candidate_artifact_digest"], candidate_schema_digest=value["candidate_schema_digest"],
                linkage_key_commitment=value["linkage_key_commitment"], reference_commitment=value["reference_commitment"],
                linkage_key_count=value["linkage_key_count"], methodology_digest=value["methodology_digest"],
                status=LinkageRiskStatus(value["status"]),
                abstention_reason=None if value["abstention_reason"] is None else LinkageRiskAbstention(value["abstention_reason"]),
                candidate_record_count=value["candidate_record_count"], reference_record_count=value["reference_record_count"],
                matched_record_count=value["matched_record_count"], unique_match_count=value["unique_match_count"],
                ambiguous_match_count=value["ambiguous_match_count"], match_coverage_percent=value["match_coverage_percent"],
            )
        except (KeyError, TypeError, ValueError, LinkageRiskError):
            _fail()
        if not hmac.compare_digest(value["digest"], report.digest):
            _fail()
        return report


METHODOLOGY_DIGEST = _digest(_canonical(_METHODOLOGY))


def _percent(numerator: int, denominator: int) -> str:
    scaled = (numerator * 100 * _PERCENT_SCALE + denominator // 2) // denominator
    whole, fraction = divmod(scaled, _PERCENT_SCALE)
    return f"{whole}.{fraction:02d}"


def _abstain(candidate: CandidateArtifact, linkage_keys: LinkageKeyConfig,
             reference: LinkageReference, reason: LinkageRiskAbstention) -> LinkageRiskReport:
    metadata = candidate.metadata
    return LinkageRiskReport(
        candidate_artifact_digest=metadata.artifact_digest, candidate_schema_digest=metadata.schema_digest,
        linkage_key_commitment=linkage_keys._public_commitment, reference_commitment=reference._public_commitment,
        linkage_key_count=len(linkage_keys._fields), methodology_digest=METHODOLOGY_DIGEST,
        status=LinkageRiskStatus.ABSTAINED, abstention_reason=reason,
        candidate_record_count=None, reference_record_count=None, matched_record_count=None,
        unique_match_count=None, ambiguous_match_count=None, match_coverage_percent=None,
    )


def assess_linkage_risk(*, candidate: CandidateArtifact, reference: LinkageReference,
                        linkage_keys: LinkageKeyConfig,
                        commitment_verifier: LinkageCommitmentAuthority | None = None) -> LinkageRiskReport:
    """Measure HMAC-token linkage possibilities for one exact candidate.

    A one-to-one match means a candidate token appears once in both the
    candidate and the external representation.  Any match with duplicate
    candidate or reference token occurrences is counted as ambiguous.  These
    are deterministic aggregate attack-surface measurements only; they do not
    establish anonymity, real-world identity correctness, or release safety.
    """
    if (type(candidate) is not CandidateArtifact or type(reference) is not LinkageReference
            or type(linkage_keys) is not LinkageKeyConfig):
        _fail()
    if (type(commitment_verifier) is not LinkageCommitmentAuthority
            or not commitment_verifier.verifies_reference(reference, linkage_keys=linkage_keys)):
        return _abstain(candidate, linkage_keys, reference,
                         LinkageRiskAbstention.REFERENCE_COMMITMENT_UNVERIFIED)
    if candidate.metadata.payload_kind is PayloadKind.TEXT:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.TEXT_PAYLOAD)
    try:
        payload = candidate.materialize_for_private_worker()
    except CandidateError:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.UNSUPPORTED_RECORD_SHAPE)
    if type(payload) is not list or any(type(record) is not dict for record in payload):
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.UNSUPPORTED_RECORD_SHAPE)
    if not payload:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.EMPTY_CANDIDATE)
    if len(payload) > MAX_RECORDS:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.CANDIDATE_RECORD_LIMIT_EXCEEDED)
    reference_record_count = len(reference._tokens)
    if reference_record_count == 0:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.EMPTY_REFERENCE)
    try:
        candidate_tokens = _tokenise_records(payload, linkage_keys, commitment_verifier)
    except LinkageRiskError:
        return _abstain(candidate, linkage_keys, reference, LinkageRiskAbstention.LINKAGE_KEYS_NOT_APPLICABLE)
    candidate_counts, reference_counts = Counter(candidate_tokens), Counter(reference._tokens)
    matched = sum(count for token, count in candidate_counts.items() if reference_counts[token])
    unique = sum(count for token, count in candidate_counts.items()
                 if count == 1 and reference_counts[token] == 1)
    metadata = candidate.metadata
    return LinkageRiskReport(
        candidate_artifact_digest=metadata.artifact_digest, candidate_schema_digest=metadata.schema_digest,
        linkage_key_commitment=linkage_keys._public_commitment, reference_commitment=reference._public_commitment,
        linkage_key_count=len(linkage_keys._fields), methodology_digest=METHODOLOGY_DIGEST,
        status=LinkageRiskStatus.ASSESSED, abstention_reason=None,
        candidate_record_count=len(payload), reference_record_count=reference_record_count,
        matched_record_count=matched, unique_match_count=unique, ambiguous_match_count=matched - unique,
        match_coverage_percent=_percent(matched, len(payload)),
    )
