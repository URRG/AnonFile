"""Fail-closed qualification decisions for metadata-only candidate artifacts.

This is deliberately a gate, not an approval engine.  Even a complete,
within-threshold measurement returns ``INSUFFICIENT_EVIDENCE``: it proves only
the supplied bounded measurements and cannot authorize buyer delivery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Iterable, Mapping

from app.policies import TAXONOMY_CATEGORIES


class QualificationError(ValueError):
    """Fixed, source-independent failure for invalid qualification metadata."""

    def __init__(self) -> None:
        super().__init__("Invalid qualification input")


class QualificationOutcome(StrEnum):
    QUARANTINED = "QUARANTINED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class QualificationReason(StrEnum):
    BINDING_MISMATCH = "BINDING_MISMATCH"
    CANDIDATE_EXPIRED = "CANDIDATE_EXPIRED"
    EVALUATION_STALE = "EVALUATION_STALE"
    EVALUATION_TIME_INVALID = "EVALUATION_TIME_INVALID"
    MISSING_CATEGORY_MEASUREMENT = "MISSING_CATEGORY_MEASUREMENT"
    EMPTY_CATEGORY_SAMPLE = "EMPTY_CATEGORY_SAMPLE"
    THRESHOLD_EXCEEDED = "THRESHOLD_EXCEEDED"
    INDEPENDENT_APPROVAL_REQUIRED = "INDEPENDENT_APPROVAL_REQUIRED"


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RIGHTS_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_MAX_AGE_SECONDS = 31 * 24 * 60 * 60
_PPM = 1_000_000


def _fail() -> None:
    raise QualificationError()


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _rights_digest(value: object) -> str:
    if type(value) is not str or not _RIGHTS_DIGEST.fullmatch(value):
        _fail()
    return value


def _label(value: object) -> str:
    if type(value) is not str or not _LABEL.fullmatch(value):
        _fail()
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(UTC).replace(microsecond=0)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail()


@dataclass(frozen=True, slots=True)
class CategoryThreshold:
    """Maximum observed residual rate, as integer parts-per-million."""

    category: str
    maximum_residual_ppm: int

    def __post_init__(self) -> None:
        if (self.category not in TAXONOMY_CATEGORIES
                or type(self.maximum_residual_ppm) is not int
                or not 0 <= self.maximum_residual_ppm <= _PPM):
            _fail()


@dataclass(frozen=True, slots=True)
class CategoryMeasurement:
    """A source-free category result from an independently retained report."""

    category: str
    observed_residuals: int
    examined_items: int

    def __post_init__(self) -> None:
        if (self.category not in TAXONOMY_CATEGORIES
                or type(self.observed_residuals) is not int
                or type(self.examined_items) is not int
                or self.observed_residuals < 0 or self.examined_items < 0
                or self.observed_residuals > self.examined_items
                or self.examined_items > 1_000_000_000):
            _fail()


@dataclass(frozen=True, slots=True)
class QualificationCriteria:
    """All taxonomy categories require an explicit threshold; no defaults exist."""

    thresholds: tuple[CategoryThreshold, ...]
    max_evaluation_age_seconds: int

    def __post_init__(self) -> None:
        if (not isinstance(self.thresholds, tuple)
                or any(not isinstance(item, CategoryThreshold) for item in self.thresholds)
                or {item.category for item in self.thresholds} != TAXONOMY_CATEGORIES
                or len(self.thresholds) != len(TAXONOMY_CATEGORIES)
                or type(self.max_evaluation_age_seconds) is not int
                or not 1 <= self.max_evaluation_age_seconds <= _MAX_AGE_SECONDS):
            _fail()
        object.__setattr__(self, "thresholds", tuple(sorted(self.thresholds, key=lambda item: item.category)))

    @property
    def digest(self) -> str:
        return "sha256:" + sha256(_canonical({
            "max_evaluation_age_seconds": self.max_evaluation_age_seconds,
            "thresholds": [{"category": item.category, "maximum_residual_ppm": item.maximum_residual_ppm}
                           for item in self.thresholds],
        })).hexdigest()


@dataclass(frozen=True, slots=True)
class CandidateBinding:
    """The exact metadata identity of one bounded candidate artifact."""

    artifact_digest: str
    policy_digest: str
    rights_digest: str
    buyer: str
    purpose: str
    expires_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_digest", _digest(self.artifact_digest))
        object.__setattr__(self, "policy_digest", _digest(self.policy_digest))
        object.__setattr__(self, "rights_digest", _rights_digest(self.rights_digest))
        object.__setattr__(self, "buyer", _label(self.buyer))
        object.__setattr__(self, "purpose", _label(self.purpose))
        object.__setattr__(self, "expires_at", _timestamp(self.expires_at))


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """A metadata-only report assertion; report bytes remain outside this domain."""

    report_digest: str
    candidate_artifact_digest: str
    policy_digest: str
    rights_digest: str
    buyer: str
    purpose: str
    evaluated_at: datetime
    measurements: tuple[CategoryMeasurement, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "report_digest", _digest(self.report_digest))
        object.__setattr__(self, "candidate_artifact_digest", _digest(self.candidate_artifact_digest))
        object.__setattr__(self, "policy_digest", _digest(self.policy_digest))
        object.__setattr__(self, "rights_digest", _rights_digest(self.rights_digest))
        object.__setattr__(self, "buyer", _label(self.buyer))
        object.__setattr__(self, "purpose", _label(self.purpose))
        object.__setattr__(self, "evaluated_at", _timestamp(self.evaluated_at))
        if (not isinstance(self.measurements, tuple)
                or any(not isinstance(item, CategoryMeasurement) for item in self.measurements)
                or len(self.measurements) > len(TAXONOMY_CATEGORIES)
                or len({item.category for item in self.measurements}) != len(self.measurements)):
            _fail()
        object.__setattr__(self, "measurements", tuple(sorted(self.measurements, key=lambda item: item.category)))


@dataclass(frozen=True, slots=True)
class QualificationDecision:
    """Immutable, non-authorizing qualification snapshot."""

    qualification_id: str
    outcome: QualificationOutcome
    reasons: tuple[QualificationReason, ...]
    candidate: CandidateBinding
    report: EvaluationReport
    criteria_digest: str
    decided_at: datetime
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "qualification_id", _label(self.qualification_id))
        if (not isinstance(self.outcome, QualificationOutcome)
                or not isinstance(self.candidate, CandidateBinding)
                or not isinstance(self.report, EvaluationReport)
                or not isinstance(self.reasons, tuple) or not self.reasons
                or any(not isinstance(reason, QualificationReason) for reason in self.reasons)
                or len(set(self.reasons)) != len(self.reasons)):
            _fail()
        object.__setattr__(self, "criteria_digest", _digest(self.criteria_digest))
        object.__setattr__(self, "decided_at", _timestamp(self.decided_at))
        object.__setattr__(self, "reasons", tuple(sorted(self.reasons, key=str)))
        object.__setattr__(self, "digest", "sha256:" + sha256(_canonical(self._canonical())).hexdigest())

    def _canonical(self) -> dict[str, object]:
        return {
            "buyer": self.candidate.buyer,
            "candidate_artifact_digest": self.candidate.artifact_digest,
            "candidate_expires_at": self.candidate.expires_at.isoformat().replace("+00:00", "Z"),
            "category_measurements": [
                {"category": item.category, "examined_items": item.examined_items,
                 "observed_residuals": item.observed_residuals}
                for item in self.report.measurements
            ],
            "criteria_digest": self.criteria_digest,
            "evaluation_report_digest": self.report.report_digest,
            "evaluated_at": self.report.evaluated_at.isoformat().replace("+00:00", "Z"),
            "outcome": self.outcome.value,
            "policy_digest": self.candidate.policy_digest,
            "purpose": self.candidate.purpose,
            "qualification_id": self.qualification_id,
            "reasons": [reason.value for reason in self.reasons],
            "rights_digest": self.candidate.rights_digest,
        }

    def snapshot(self) -> Mapping[str, object]:
        """Detached-safe immutable metadata for a protected control record."""
        return MappingProxyType({**self._canonical(), "digest": self.digest})

    def audit_event(self, *, sequence: int) -> Mapping[str, object]:
        """Public-audit-safe event: no buyer, purpose, source or report content."""
        if type(sequence) is not int or not 1 <= sequence <= 1_000_000_000:
            _fail()
        return MappingProxyType({
            "action": "qualification.decided",
            "object_id": self.qualification_id,
            "outcome": self.outcome.value,
            "qualification_digest": self.digest,
            "sequence": sequence,
        })


def _bindings_match(candidate: CandidateBinding, report: EvaluationReport) -> bool:
    return (candidate.artifact_digest == report.candidate_artifact_digest
            and candidate.policy_digest == report.policy_digest
            and candidate.rights_digest == report.rights_digest
            and candidate.buyer == report.buyer
            and candidate.purpose == report.purpose)


def qualify(*, qualification_id: str, candidate: CandidateBinding, report: EvaluationReport,
            criteria: QualificationCriteria, at: datetime) -> QualificationDecision:
    """Create a non-authorizing decision from exact, bounded evidence bindings.

    Missing or stale measurements cannot fall through to success.  No branch
    returns an approved, exportable, or sale-ready state.
    """
    if not isinstance(candidate, CandidateBinding) or not isinstance(report, EvaluationReport) or not isinstance(criteria, QualificationCriteria):
        _fail()
    instant = _timestamp(at)
    if not _bindings_match(candidate, report):
        outcome, reasons = QualificationOutcome.QUARANTINED, (QualificationReason.BINDING_MISMATCH,)
    elif instant >= candidate.expires_at:
        outcome, reasons = QualificationOutcome.QUARANTINED, (QualificationReason.CANDIDATE_EXPIRED,)
    elif report.evaluated_at > instant:
        outcome, reasons = QualificationOutcome.INSUFFICIENT_EVIDENCE, (QualificationReason.EVALUATION_TIME_INVALID,)
    elif (instant - report.evaluated_at).total_seconds() > criteria.max_evaluation_age_seconds:
        outcome, reasons = QualificationOutcome.INSUFFICIENT_EVIDENCE, (QualificationReason.EVALUATION_STALE,)
    else:
        measurements = {item.category: item for item in report.measurements}
        missing = [threshold.category for threshold in criteria.thresholds if threshold.category not in measurements]
        empty = [item.category for item in measurements.values() if item.examined_items == 0]
        exceeded = [threshold.category for threshold in criteria.thresholds
                    if threshold.category in measurements and measurements[threshold.category].examined_items > 0
                    and measurements[threshold.category].observed_residuals * _PPM
                    > threshold.maximum_residual_ppm * measurements[threshold.category].examined_items]
        if missing:
            outcome, reasons = QualificationOutcome.INSUFFICIENT_EVIDENCE, (QualificationReason.MISSING_CATEGORY_MEASUREMENT,)
        elif empty:
            outcome, reasons = QualificationOutcome.INSUFFICIENT_EVIDENCE, (QualificationReason.EMPTY_CATEGORY_SAMPLE,)
        elif exceeded:
            outcome, reasons = QualificationOutcome.QUARANTINED, (QualificationReason.THRESHOLD_EXCEEDED,)
        else:
            # Measurements are necessary evidence, but no currently supported
            # suite establishes a deliverable external release.
            outcome, reasons = QualificationOutcome.INSUFFICIENT_EVIDENCE, (QualificationReason.INDEPENDENT_APPROVAL_REQUIRED,)
    return QualificationDecision(qualification_id=qualification_id, outcome=outcome, reasons=reasons,
                                 candidate=candidate, report=report,
                                 criteria_digest=criteria.digest, decided_at=instant)
