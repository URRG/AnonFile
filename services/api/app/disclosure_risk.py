"""Bounded, source-safe equivalence-class disclosure-risk measurements.

This is deliberately an evidence primitive, not a release decision.  It works
only on a private :class:`CandidateArtifact` whose structured payload is a
bounded list of object records.  The public record contains aggregate class
sizes and commitments only: it never contains a quasi-identifier path, value,
record, or equivalence-class key.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Iterable

from .candidate import CandidateArtifact, PayloadKind


MAX_RECORDS = 10_000
MAX_QUASI_IDENTIFIERS = 32
MAX_FIELD_NAME_BYTES = 128
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
# An opaque 32-64 byte URL-safe token supplied by the trusted caller.  It is
# deliberately not a digest generated from a qid field name/path here.
_OPAQUE_COMMITMENT = re.compile(r"qidcfg:v1:[A-Za-z0-9_-]{43,86}\Z")
_PERCENT_SCALE = 100  # fixed two decimal places for a percentage value


class DisclosureRiskError(ValueError):
    """Fixed error surface; candidate content is never included in errors."""

    MESSAGE = "Invalid disclosure-risk assessment."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class DisclosureRiskStatus(StrEnum):
    ASSESSED = "ASSESSED"
    ABSTAINED = "ABSTAINED"


class DisclosureRiskAbstention(StrEnum):
    TEXT_PAYLOAD = "TEXT_PAYLOAD"
    UNSUPPORTED_RECORD_SHAPE = "UNSUPPORTED_RECORD_SHAPE"
    EMPTY_RECORD_SET = "EMPTY_RECORD_SET"
    RECORD_LIMIT_EXCEEDED = "RECORD_LIMIT_EXCEEDED"
    QUASI_IDENTIFIER_NOT_APPLICABLE = "QUASI_IDENTIFIER_NOT_APPLICABLE"


def _fail() -> None:
    raise DisclosureRiskError()


def _canonical(value: object) -> bytes:
    """Canonical, bounded bytes for private grouping and public commitments."""
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    # The CandidateArtifact already enforces 2 MiB, but risk configuration and
    # individual scalar keys get their own small, predictable ceilings.
    if len(encoded) > 65_536:
        _fail()
    return encoded


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _is_scalar(value: object) -> bool:
    return (value is None or type(value) in (str, int, bool)
            or (type(value) is float and math.isfinite(value)))


@dataclass(frozen=True, slots=True)
class QuasiIdentifierConfig:
    """Private top-level quasi-identifier selection.

    Nested paths are intentionally unsupported in this first bounded primitive.
    The caller must bind this selection to a high-entropy opaque commitment
    created in its protected control plane (for example, from a per-run secret
    or a signed configuration record).  This module never derives a public
    commitment by hashing field names, because such hashes are dictionary
    reversible for common schema names.
    """

    _fields: tuple[str, ...] = field(repr=False, compare=True)
    _public_commitment: str = field(repr=False, compare=True)

    @classmethod
    def from_fields(cls, fields: Iterable[str], *, public_commitment: str) -> "QuasiIdentifierConfig":
        if isinstance(fields, (str, bytes)):
            _fail()
        try:
            selected = tuple(fields)
        except TypeError:
            _fail()
        return cls(_fields=selected, _public_commitment=public_commitment)

    def __post_init__(self) -> None:
        if (type(self._fields) is not tuple or not 1 <= len(self._fields) <= MAX_QUASI_IDENTIFIERS
                or any(type(item) is not str or not _FIELD.fullmatch(item) for item in self._fields)
                or len(set(self._fields)) != len(self._fields)
                or type(self._public_commitment) is not str
                or not _OPAQUE_COMMITMENT.fullmatch(self._public_commitment)):
            _fail()
        try:
            if any(len(item.encode("utf-8")) > MAX_FIELD_NAME_BYTES for item in self._fields):
                _fail()
        except UnicodeError:
            _fail()
        normalised = tuple(sorted(self._fields))
        object.__setattr__(self, "_fields", normalised)

    @property
    def field_count(self) -> int:
        return len(self._fields)

    @property
    def public_commitment(self) -> str:
        """Opaque caller-supplied commitment safe for a public report."""
        return self._public_commitment


@dataclass(frozen=True, slots=True)
class EquivalenceClassSize:
    """A safe histogram entry; no class key or record identity is retained."""

    size: int
    class_count: int
    record_count: int

    def __post_init__(self) -> None:
        if (type(self.size) is not int or type(self.class_count) is not int or type(self.record_count) is not int
                or not 1 <= self.size <= MAX_RECORDS or not 1 <= self.class_count <= MAX_RECORDS
                or self.record_count != self.size * self.class_count or self.record_count > MAX_RECORDS):
            _fail()


@dataclass(frozen=True, slots=True)
class DisclosureRiskReport:
    """Digest-bound, aggregate-only disclosure-risk evidence.

    ``ASSESSED`` reports describe a concrete record set and qid configuration.
    ``ABSTAINED`` reports retain only an explicit reason plus the same immutable
    artifact/config bindings.  Neither outcome is a qualification or approval.
    """

    candidate_artifact_digest: str
    candidate_schema_digest: str
    quasi_identifier_commitment: str
    quasi_identifier_count: int
    status: DisclosureRiskStatus
    abstention_reason: DisclosureRiskAbstention | None
    record_count: int | None
    minimum_equivalence_class_size: int | None
    unique_record_count: int | None
    unique_record_percent: str | None
    equivalence_class_sizes: tuple[EquivalenceClassSize, ...]
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        for item in (self.candidate_artifact_digest, self.candidate_schema_digest):
            if type(item) is not str or not _DIGEST.fullmatch(item):
                _fail()
        if (type(self.quasi_identifier_commitment) is not str
                or not _OPAQUE_COMMITMENT.fullmatch(self.quasi_identifier_commitment)):
            _fail()
        if type(self.quasi_identifier_count) is not int or not 1 <= self.quasi_identifier_count <= MAX_QUASI_IDENTIFIERS:
            _fail()
        if not isinstance(self.status, DisclosureRiskStatus):
            _fail()
        if not isinstance(self.equivalence_class_sizes, tuple):
            _fail()
        if self.status is DisclosureRiskStatus.ABSTAINED:
            if (not isinstance(self.abstention_reason, DisclosureRiskAbstention)
                    or any(value is not None for value in (self.record_count, self.minimum_equivalence_class_size,
                                                            self.unique_record_count, self.unique_record_percent))
                    or self.equivalence_class_sizes):
                _fail()
        else:
            classes = self.equivalence_class_sizes
            if (self.abstention_reason is not None or type(self.record_count) is not int
                    or not 1 <= self.record_count <= MAX_RECORDS
                    or type(self.minimum_equivalence_class_size) is not int
                    or not 1 <= self.minimum_equivalence_class_size <= self.record_count
                    or type(self.unique_record_count) is not int or not 0 <= self.unique_record_count <= self.record_count
                    or type(self.unique_record_percent) is not str or not re.fullmatch(r"(?:0|[1-9][0-9]?|100)\.[0-9]{2}", self.unique_record_percent)
                    or not classes or any(not isinstance(item, EquivalenceClassSize) for item in classes)
                    or tuple(sorted(classes, key=lambda item: item.size)) != classes
                    or len({item.size for item in classes}) != len(classes)
                    or sum(item.record_count for item in classes) != self.record_count
                    or min(item.size for item in classes) != self.minimum_equivalence_class_size
                    or sum(item.record_count for item in classes if item.size == 1) != self.unique_record_count
                    or self.unique_record_percent != _percent(self.unique_record_count, self.record_count)):
                _fail()
        object.__setattr__(self, "digest", _digest(_canonical(self._canonical())))

    def _canonical(self) -> dict[str, object]:
        return {
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_schema_digest": self.candidate_schema_digest,
            "equivalence_class_sizes": [
                {"class_count": item.class_count, "record_count": item.record_count, "size": item.size}
                for item in self.equivalence_class_sizes
            ],
            "minimum_equivalence_class_size": self.minimum_equivalence_class_size,
            "quasi_identifier_commitment": self.quasi_identifier_commitment,
            "quasi_identifier_count": self.quasi_identifier_count,
            "record_count": self.record_count,
            "status": self.status.value,
            "abstention_reason": self.abstention_reason.value if self.abstention_reason else None,
            "unique_record_count": self.unique_record_count,
            "unique_record_percent": self.unique_record_percent,
            "version": 1,
        }

    def to_record(self) -> dict[str, object]:
        """Return a detached public/persistable record with aggregate data only."""
        return {**self._canonical(), "digest": self.digest}


def _percent(numerator: int, denominator: int) -> str:
    # Integer half-up rounding gives an unambiguous, locale-independent 2dp
    # percentage without floating-point instability.
    scaled = (numerator * 100 * _PERCENT_SCALE + denominator // 2) // denominator
    whole, fraction = divmod(scaled, _PERCENT_SCALE)
    return f"{whole}.{fraction:02d}"


def _abstain(candidate: CandidateArtifact, config: QuasiIdentifierConfig,
             reason: DisclosureRiskAbstention) -> DisclosureRiskReport:
    metadata = candidate.metadata
    return DisclosureRiskReport(
        candidate_artifact_digest=metadata.artifact_digest, candidate_schema_digest=metadata.schema_digest,
        quasi_identifier_commitment=config.public_commitment, quasi_identifier_count=config.field_count,
        status=DisclosureRiskStatus.ABSTAINED, abstention_reason=reason,
        record_count=None, minimum_equivalence_class_size=None, unique_record_count=None,
        unique_record_percent=None, equivalence_class_sizes=(),
    )


def assess_disclosure_risk(*, candidate: CandidateArtifact,
                           quasi_identifiers: QuasiIdentifierConfig) -> DisclosureRiskReport:
    """Assess bounded record-level equivalence classes for one exact candidate.

    This function intentionally performs no policy decision and does not
    change candidate state.  A caller must use an independent policy/evidence
    process to decide whether this measurement is sufficient for any release.
    """
    if not isinstance(candidate, CandidateArtifact) or not isinstance(quasi_identifiers, QuasiIdentifierConfig):
        _fail()
    if candidate.metadata.payload_kind is PayloadKind.TEXT:
        return _abstain(candidate, quasi_identifiers, DisclosureRiskAbstention.TEXT_PAYLOAD)
    payload = candidate.materialize_for_private_worker()
    if type(payload) is not list or any(type(record) is not dict for record in payload):
        return _abstain(candidate, quasi_identifiers, DisclosureRiskAbstention.UNSUPPORTED_RECORD_SHAPE)
    if not payload:
        return _abstain(candidate, quasi_identifiers, DisclosureRiskAbstention.EMPTY_RECORD_SET)
    if len(payload) > MAX_RECORDS:
        return _abstain(candidate, quasi_identifiers, DisclosureRiskAbstention.RECORD_LIMIT_EXCEEDED)

    classes: Counter[bytes] = Counter()
    for record in payload:
        try:
            values = tuple(record[name] for name in quasi_identifiers._fields)
        except KeyError:
            return _abstain(candidate, quasi_identifiers,
                            DisclosureRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE)
        if not all(_is_scalar(value) for value in values):
            return _abstain(candidate, quasi_identifiers,
                            DisclosureRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE)
        # A private canonical representation is enough for equality; no key is
        # retained in the output or carried over into the report object.
        classes[_canonical(values)] += 1

    histogram = Counter(classes.values())
    sizes = tuple(EquivalenceClassSize(size=size, class_count=count,
                                       record_count=size * count)
                  for size, count in sorted(histogram.items()))
    unique_count = histogram.get(1, 0)
    metadata = candidate.metadata
    return DisclosureRiskReport(
        candidate_artifact_digest=metadata.artifact_digest, candidate_schema_digest=metadata.schema_digest,
        quasi_identifier_commitment=quasi_identifiers.public_commitment,
        quasi_identifier_count=quasi_identifiers.field_count,
        status=DisclosureRiskStatus.ASSESSED, abstention_reason=None,
        record_count=len(payload), minimum_equivalence_class_size=sizes[0].size,
        unique_record_count=unique_count, unique_record_percent=_percent(unique_count, len(payload)),
        equivalence_class_sizes=sizes,
    )
