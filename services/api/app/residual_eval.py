"""Fail-closed, exact-candidate residual evaluation primitives.

The evaluator receives a *candidate* representation, its already-known artifact
metadata, and a detector callable.  It never accepts an original source or
returns candidate values, snippets, detector errors, or object representations.
An empty detector result is evidence of neither anonymity nor fitness: the best
non-failing outcome is always ``INSUFFICIENT_EVIDENCE``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Callable, Iterable, Mapping


MAX_CANDIDATE_BYTES = 2_000_000
MAX_RECORDS = 10_000
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_CATEGORIES = 64
_TOKEN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_IDENTITY = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MEDIA_TYPES = frozenset({"text/plain", "text/csv", "application/json", "application/jsonl"})


class EvaluationError(ValueError):
    """Fixed-message evaluation error: candidate values must never be echoed."""


class EvidenceStatus(StrEnum):
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FAILS_PROFILE = "FAILS_PROFILE"


class UtilityCheckCode(StrEnum):
    RECORD_COUNT_MATCH = "RECORD_COUNT_MATCH"
    SCHEMA_MATCH = "SCHEMA_MATCH"
    REPRESENTATION_SUPPORTED = "REPRESENTATION_SUPPORTED"


def _error(message: str = "Invalid evaluation request") -> None:
    raise EvaluationError(message)


def _identity(value: object) -> str:
    if type(value) is not str or not _IDENTITY.fullmatch(value):
        _error()
    return value


def _category(value: object) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        _error()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _error()
    return value


def _canonical(value: object) -> bytes:
    try:
        result = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                            separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _error("Invalid candidate representation")
    if len(result) > MAX_CANDIDATE_BYTES:
        _error("Candidate representation exceeds evaluation limit")
    return result


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _validate_graph(value: object) -> None:
    """Validate a JSON candidate without serializing an unbounded/cyclic graph."""
    nodes = 0
    active: set[int] = set()
    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active.remove(id(current))
            continue
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            _error("Invalid candidate representation")
        kind = type(current)
        if kind in (dict, list):
            if id(current) in active:
                _error("Invalid candidate representation")
            active.add(id(current))
            stack.append((current, depth, True))
            if kind is dict:
                for key, child in current.items():
                    if type(key) is not str:
                        _error("Invalid candidate representation")
                    try:
                        if len(key.encode("utf-8")) > 16_384:
                            _error("Invalid candidate representation")
                    except UnicodeError:
                        _error("Invalid candidate representation")
                    stack.append((child, depth + 1, False))
            else:
                stack.extend((child, depth + 1, False) for child in current)
        elif kind is str:
            try:
                if len(current.encode("utf-8")) > 1_000_000:
                    _error("Invalid candidate representation")
            except UnicodeError:
                _error("Invalid candidate representation")
        elif kind is float and not math.isfinite(current):
            _error("Invalid candidate representation")
        elif kind not in (int, float, bool) and current is not None:
            _error("Invalid candidate representation")


def _shape(value: object) -> object:
    """Return only key/type structure; values never influence utility digest."""
    if type(value) is dict:
        return {key: _shape(child) for key, child in sorted(value.items())}
    if type(value) is list:
        # Array element order is a potential utility signal, so keep each shape
        # but no candidate values.
        return [_shape(child) for child in value]
    if value is None:
        return "null"
    return type(value).__name__


def candidate_digest(candidate: str | list[dict[str, Any]]) -> str:
    """Digest exact candidate bytes/structure without retaining them in a report."""
    if type(candidate) is str:
        try:
            raw = candidate.encode("utf-8")
        except UnicodeError:
            _error("Invalid candidate representation")
        if not raw or len(raw) > MAX_CANDIDATE_BYTES:
            _error("Invalid candidate representation")
        return _digest_bytes(raw)
    if type(candidate) is not list or not candidate or len(candidate) > MAX_RECORDS:
        _error("Invalid candidate representation")
    if any(type(record) is not dict for record in candidate):
        _error("Invalid candidate representation")
    _validate_graph(candidate)
    return _digest_bytes(_canonical(candidate))


def candidate_schema_digest(candidate: str | list[dict[str, Any]]) -> str | None:
    if type(candidate) is str:
        return None
    # candidate_digest supplies all validation and remains deliberately called
    # before this helper by ``evaluate_candidate``.
    return _digest_bytes(_canonical(_shape(candidate)))


@dataclass(frozen=True, slots=True)
class CandidateMetadata:
    """Metadata about exactly one candidate artifact, never its source dataset."""

    artifact_digest: str
    media_type: str
    expected_record_count: int
    expected_schema_digest: str | None = None

    def __post_init__(self) -> None:
        _digest(self.artifact_digest)
        if self.media_type not in _MEDIA_TYPES:
            _error()
        if type(self.expected_record_count) is not int or isinstance(self.expected_record_count, bool) or not 1 <= self.expected_record_count <= MAX_RECORDS:
            _error()
        if self.expected_schema_digest is not None:
            _digest(self.expected_schema_digest)
        if self.media_type in {"application/json", "application/jsonl"} and self.expected_schema_digest is None:
            _error()
        if self.media_type in {"text/plain", "text/csv"} and self.expected_schema_digest is not None:
            _error()


@dataclass(frozen=True, slots=True)
class DetectorIdentity:
    detector_id: str
    config_digest: str

    def __post_init__(self) -> None:
        _identity(self.detector_id)
        _digest(self.config_digest)


@dataclass(frozen=True, slots=True)
class DetectorResult:
    """Detector output accepted by this module: aggregate counts only."""

    residual_counts: Mapping[str, int]
    scanned_units: int
    abstained_units: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.residual_counts, Mapping) or len(self.residual_counts) > MAX_CATEGORIES:
            _error("Invalid detector result")
        normalized: dict[str, int] = {}
        for category, count in self.residual_counts.items():
            key = _category(category)
            if key in normalized or type(count) is not int or isinstance(count, bool) or not 0 <= count <= MAX_NODES:
                _error("Invalid detector result")
            normalized[key] = count
        if type(self.scanned_units) is not int or isinstance(self.scanned_units, bool) or self.scanned_units < 0:
            _error("Invalid detector result")
        if type(self.abstained_units) is not int or isinstance(self.abstained_units, bool) or self.abstained_units < 0:
            _error("Invalid detector result")
        object.__setattr__(self, "residual_counts", normalized)


@dataclass(frozen=True, slots=True)
class EvaluationProfile:
    profile_id: str
    version: str
    required_categories: frozenset[str]
    minimum_coverage_percent: int = 100
    maximum_abstentions: int = 0
    maximum_residuals: int = 0
    _digest: str = field(init=False, repr=False)

    @classmethod
    def create(cls, *, profile_id: str, version: str, required_categories: Iterable[str],
               minimum_coverage_percent: int = 100, maximum_abstentions: int = 0,
               maximum_residuals: int = 0) -> "EvaluationProfile":
        if isinstance(required_categories, (str, bytes)):
            _error()
        try:
            categories = tuple(_category(item) for item in required_categories)
        except TypeError:
            _error()
        if not categories or len(categories) > MAX_CATEGORIES or len(categories) != len(set(categories)):
            _error()
        return cls(profile_id=_identity(profile_id), version=_identity(version), required_categories=frozenset(categories),
                   minimum_coverage_percent=minimum_coverage_percent, maximum_abstentions=maximum_abstentions,
                   maximum_residuals=maximum_residuals)

    def __post_init__(self) -> None:
        _identity(self.profile_id)
        _identity(self.version)
        categories = tuple(self.required_categories)
        if not categories or len(categories) > MAX_CATEGORIES:
            _error()
        object.__setattr__(self, "required_categories", frozenset(_category(value) for value in categories))
        for value, low, high in ((self.minimum_coverage_percent, 0, 100), (self.maximum_abstentions, 0, MAX_RECORDS), (self.maximum_residuals, 0, MAX_NODES)):
            if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
                _error()
        payload = {"profile_id": self.profile_id, "version": self.version,
                   "required_categories": sorted(self.required_categories),
                   "minimum_coverage_percent": self.minimum_coverage_percent,
                   "maximum_abstentions": self.maximum_abstentions,
                   "maximum_residuals": self.maximum_residuals}
        object.__setattr__(self, "_digest", _digest_bytes(_canonical(payload)))

    @property
    def digest(self) -> str:
        return self._digest


@dataclass(frozen=True, slots=True)
class UtilityCheck:
    code: UtilityCheckCode
    passed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.code, UtilityCheckCode) or type(self.passed) is not bool:
            _error("Invalid evaluation report")


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    candidate_digest: str
    detector_id: str
    detector_config_digest: str
    profile_digest: str
    residual_counts: tuple[tuple[str, int], ...]
    total_units: int
    scanned_units: int
    abstained_units: int
    coverage_percent: int
    utility_checks: tuple[UtilityCheck, ...]
    evidence_status: EvidenceStatus
    digest: str

    def to_record(self) -> dict[str, object]:
        """A bounded, aggregate-only public/persistable representation."""
        return {
            "candidate_digest": self.candidate_digest,
            "detector_id": self.detector_id,
            "detector_config_digest": self.detector_config_digest,
            "profile_digest": self.profile_digest,
            "residual_counts": {category: count for category, count in self.residual_counts},
            "total_units": self.total_units, "scanned_units": self.scanned_units,
            "abstained_units": self.abstained_units, "coverage_percent": self.coverage_percent,
            "utility_checks": [{"code": item.code.value, "passed": item.passed} for item in self.utility_checks],
            "evidence_status": self.evidence_status.value, "digest": self.digest,
        }


def _units(candidate: str | list[dict[str, Any]]) -> int:
    return 1 if type(candidate) is str else len(candidate)


def evaluate_candidate(
    candidate: str | list[dict[str, Any]], *, metadata: CandidateMetadata,
    detector: Callable[[str | list[dict[str, Any]]], DetectorResult],
    detector_identity: DetectorIdentity, profile: EvaluationProfile,
) -> EvaluationReport:
    """Evaluate one exact artifact with aggregate-only detector output.

    A detector exception, wrong return type, invalid count, or candidate digest
    mismatch fails before any report is produced.  The exception surface is
    fixed and never includes detector/source/candidate content.
    """
    if not isinstance(metadata, CandidateMetadata) or not callable(detector) or not isinstance(detector_identity, DetectorIdentity) or not isinstance(profile, EvaluationProfile):
        _error()
    calculated = candidate_digest(candidate)
    if calculated != metadata.artifact_digest:
        _error("Candidate integrity verification failed")
    total = _units(candidate)
    actual_schema = candidate_schema_digest(candidate)
    record_count_ok = total == metadata.expected_record_count
    schema_ok = actual_schema == metadata.expected_schema_digest
    representation_ok = ((type(candidate) is str and metadata.media_type in {"text/plain", "text/csv"})
                         or (type(candidate) is list and metadata.media_type in {"application/json", "application/jsonl"}))
    checks = (
        UtilityCheck(UtilityCheckCode.RECORD_COUNT_MATCH, record_count_ok),
        UtilityCheck(UtilityCheckCode.SCHEMA_MATCH, schema_ok),
        UtilityCheck(UtilityCheckCode.REPRESENTATION_SUPPORTED, representation_ok),
    )
    try:
        detected = detector(candidate)
    except BaseException:
        _error("Detector evaluation failed")
    if not isinstance(detected, DetectorResult):
        _error("Invalid detector result")
    if detected.scanned_units > total or detected.abstained_units > detected.scanned_units:
        _error("Invalid detector result")
    # An absent category means no residual finding, but required categories
    # remain visible as zero-count coverage in the report.
    categories = sorted(set(profile.required_categories) | set(detected.residual_counts))
    counts = tuple((category, detected.residual_counts.get(category, 0)) for category in categories)
    assessed = detected.scanned_units - detected.abstained_units
    coverage = (assessed * 100) // total
    residual_total = sum(count for _, count in counts)
    fails = (residual_total > profile.maximum_residuals or coverage < profile.minimum_coverage_percent
             or detected.abstained_units > profile.maximum_abstentions or not all(item.passed for item in checks))
    status = EvidenceStatus.FAILS_PROFILE if fails else EvidenceStatus.INSUFFICIENT_EVIDENCE
    payload = {
        "candidate_digest": calculated, "detector_id": detector_identity.detector_id,
        "detector_config_digest": detector_identity.config_digest, "profile_digest": profile.digest,
        "residual_counts": counts, "total_units": total, "scanned_units": detected.scanned_units,
        "abstained_units": detected.abstained_units, "coverage_percent": coverage,
        "utility_checks": [(item.code.value, item.passed) for item in checks],
        "evidence_status": status.value,
    }
    return EvaluationReport(calculated, detector_identity.detector_id, detector_identity.config_digest,
                            profile.digest, counts, total, detected.scanned_units, detected.abstained_units,
                            coverage, checks, status, _digest_bytes(_canonical(payload)))
