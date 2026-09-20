"""Immutable, aggregate-only detector benchmark evidence.

These records establish which detector/model/configuration was measured against
which versioned benchmark.  They deliberately retain no examples, spans,
labels, fields, or source locations.  A strong score remains observational
evidence only and cannot authorize processing, release, export, or delivery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Iterable

from app.policies import TAXONOMY_CATEGORIES


PPM = 1_000_000
MAX_COUNT = 1_000_000_000
MAX_CATEGORIES = 64
MAX_LIMITATIONS = 64
_IDENTITY = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_CATEGORY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class BenchmarkEvidenceError(ValueError):
    """Fixed-message validation error; it never reflects input values."""

    def __init__(self) -> None:
        super().__init__("Invalid benchmark evidence")


class EvidencePosture(StrEnum):
    """Intentionally excludes approved, qualified, or release-ready states."""

    OBSERVATIONAL_ONLY = "OBSERVATIONAL_ONLY"


def _fail() -> None:
    raise BenchmarkEvidenceError()


def _identity(value: object) -> str:
    if type(value) is not str or not _IDENTITY.fullmatch(value):
        _fail()
    return value


def _category(value: object) -> str:
    if type(value) is not str or not _CATEGORY.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _count(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= MAX_COUNT:
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(UTC).replace(microsecond=0)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _ratio(numerator: int, denominator: int) -> int | None:
    return None if denominator == 0 else (numerator * PPM) // denominator


@dataclass(frozen=True, slots=True)
class BenchmarkBinding:
    """Source-free identity of data, annotations, model and detector revision."""

    benchmark_dataset_id: str = field(repr=False)
    benchmark_dataset_version: str = field(repr=False)
    benchmark_dataset_digest: str = field(repr=False)
    annotation_protocol_digest: str = field(repr=False)
    model_id: str = field(repr=False)
    model_version: str = field(repr=False)
    model_digest: str = field(repr=False)
    detector_id: str = field(repr=False)
    detector_version: str = field(repr=False)
    detector_config_digest: str = field(repr=False)
    taxonomy_mapping_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        for item in (self.benchmark_dataset_id, self.benchmark_dataset_version, self.model_id,
                     self.model_version, self.detector_id, self.detector_version):
            _identity(item)
        for item in (self.benchmark_dataset_digest, self.annotation_protocol_digest, self.model_digest,
                     self.detector_config_digest, self.taxonomy_mapping_digest):
            _digest(item)

    def canonical(self) -> dict[str, str]:
        return {
            "annotation_protocol_digest": self.annotation_protocol_digest,
            "benchmark_dataset_digest": self.benchmark_dataset_digest,
            "benchmark_dataset_id": self.benchmark_dataset_id,
            "benchmark_dataset_version": self.benchmark_dataset_version,
            "detector_config_digest": self.detector_config_digest,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "model_digest": self.model_digest,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "taxonomy_mapping_digest": self.taxonomy_mapping_digest,
        }


@dataclass(frozen=True, slots=True)
class CategoryMetrics:
    """Bounded aggregate entity counts for one taxonomy category."""

    category: str
    true_positives: int
    false_positives: int
    false_negatives: int

    def __post_init__(self) -> None:
        _category(self.category)
        if self.category not in TAXONOMY_CATEGORIES:
            _fail()
        for item in (self.true_positives, self.false_positives, self.false_negatives):
            _count(item)

    @property
    def precision_ppm(self) -> int | None:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall_ppm(self) -> int | None:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1_ppm(self) -> int | None:
        # Derive F1 from the original counts, not from already-rounded
        # fixed-point precision and recall.  Besides avoiding a second rounding
        # error, this correctly reports zero when a detector finds no true
        # positives but does miss annotated entities.
        return _ratio(2 * self.true_positives,
                      2 * self.true_positives + self.false_positives + self.false_negatives)

    def canonical(self) -> dict[str, int | str]:
        return {"category": self.category, "false_negatives": self.false_negatives,
                "false_positives": self.false_positives, "true_positives": self.true_positives}


@dataclass(frozen=True, slots=True)
class Coverage:
    """Evaluation coverage, where abstentions are excluded from assessed units."""

    eligible_units: int
    evaluated_units: int
    abstained_units: int

    def __post_init__(self) -> None:
        for item in (self.eligible_units, self.evaluated_units, self.abstained_units):
            _count(item)
        if self.evaluated_units > self.eligible_units or self.abstained_units > self.evaluated_units:
            _fail()

    @property
    def assessed_units(self) -> int:
        return self.evaluated_units - self.abstained_units

    @property
    def coverage_ppm(self) -> int:
        return 0 if self.eligible_units == 0 else (self.assessed_units * PPM) // self.eligible_units

    def canonical(self) -> dict[str, int]:
        return {"abstained_units": self.abstained_units, "eligible_units": self.eligible_units,
                "evaluated_units": self.evaluated_units}


@dataclass(frozen=True, slots=True)
class BenchmarkEvidence:
    """A source-free, immutable result which has no release authorization."""

    evidence_id: str
    binding: BenchmarkBinding = field(repr=False)
    metrics: tuple[CategoryMetrics, ...] = field(repr=False)
    coverage: Coverage = field(repr=False)
    limitations: tuple[str, ...] = field(repr=False)
    evaluated_at: datetime = field(repr=False)
    posture: EvidencePosture = EvidencePosture.OBSERVATIONAL_ONLY
    digest: str = field(init=False)

    @classmethod
    def create(cls, *, evidence_id: str, binding: BenchmarkBinding, metrics: Iterable[CategoryMetrics],
               coverage: Coverage, limitations: Iterable[str], evaluated_at: datetime) -> "BenchmarkEvidence":
        if isinstance(metrics, (str, bytes)) or isinstance(limitations, (str, bytes)):
            _fail()
        try:
            metric_values = tuple(metrics)
            limitation_values = tuple(limitations)
        except TypeError:
            _fail()
        if (any(not isinstance(item, CategoryMetrics) for item in metric_values)
                or len({item.category for item in metric_values}) != len(metric_values)
                or any(type(item) is not str for item in limitation_values)
                or len(set(limitation_values)) != len(limitation_values)):
            _fail()
        return cls(evidence_id=evidence_id, binding=binding,
                   metrics=tuple(sorted(metric_values, key=lambda item: item.category)), coverage=coverage,
                   limitations=tuple(sorted(limitation_values)), evaluated_at=evaluated_at)

    def __post_init__(self) -> None:
        _identity(self.evidence_id)
        if not isinstance(self.binding, BenchmarkBinding) or not isinstance(self.coverage, Coverage):
            _fail()
        if (not isinstance(self.metrics, tuple) or not self.metrics or len(self.metrics) > MAX_CATEGORIES
                or any(not isinstance(item, CategoryMetrics) for item in self.metrics)):
            _fail()
        ordered = tuple(sorted(self.metrics, key=lambda item: item.category))
        if ordered != self.metrics or len({item.category for item in self.metrics}) != len(self.metrics):
            _fail()
        if not isinstance(self.limitations, tuple) or not 1 <= len(self.limitations) <= MAX_LIMITATIONS:
            _fail()
        for item in self.limitations:
            _category(item)
        if len(set(self.limitations)) != len(self.limitations) or "NO_RELEASE_AUTHORIZATION" not in self.limitations:
            _fail()
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at))
        if self.posture is not EvidencePosture.OBSERVATIONAL_ONLY:
            _fail()
        object.__setattr__(self, "digest", _hash(self._canonical()))

    def _canonical(self) -> dict[str, object]:
        return {
            "binding": self.binding.canonical(), "coverage": self.coverage.canonical(),
            "evaluated_at": self.evaluated_at.isoformat().replace("+00:00", "Z"),
            "evidence_id": self.evidence_id, "limitations": list(self.limitations),
            "metrics": [item.canonical() for item in self.metrics], "posture": self.posture.value,
        }

    def to_record(self) -> dict[str, object]:
        """Persistable aggregate-only evidence; derived scores never authorize release."""
        return {
            **self._canonical(),
            "coverage_ppm": self.coverage.coverage_ppm,
            "metrics": [{**item.canonical(), "precision_ppm": item.precision_ppm,
                         "recall_ppm": item.recall_ppm, "f1_ppm": item.f1_ppm} for item in self.metrics],
            "digest": self.digest,
        }

    @classmethod
    def from_record(cls, value: object) -> "BenchmarkEvidence":
        expected = {"binding", "coverage", "coverage_ppm", "evaluated_at", "evidence_id", "limitations", "metrics", "posture", "digest"}
        if not isinstance(value, dict) or set(value) != expected:
            _fail()
        try:
            binding = BenchmarkBinding(**value["binding"])
            coverage_data = value["coverage"]
            coverage = Coverage(**coverage_data)
            metric_values = value["metrics"]
            if type(metric_values) is not list or not metric_values:
                _fail()
            # Derived fields are recomputed; accepting a forged derived score
            # would make records internally inconsistent.
            metrics = []
            for item in metric_values:
                if not isinstance(item, dict) or set(item) != {"category", "true_positives", "false_positives", "false_negatives", "precision_ppm", "recall_ppm", "f1_ppm"}:
                    _fail()
                metric = CategoryMetrics(item["category"], item["true_positives"], item["false_positives"], item["false_negatives"])
                derived = (item["precision_ppm"], item["recall_ppm"], item["f1_ppm"])
                expected_scores = (metric.precision_ppm, metric.recall_ppm, metric.f1_ppm)
                if any((value is not None and (type(value) is not int or isinstance(value, bool) or not 0 <= value <= PPM))
                       for value in derived) or derived != expected_scores:
                    _fail()
                metrics.append(metric)
            if type(value["limitations"]) is not list or type(value["evaluated_at"]) is not str or type(value["posture"]) is not str:
                _fail()
            instant = datetime.fromisoformat(value["evaluated_at"].replace("Z", "+00:00"))
            record = cls.create(evidence_id=value["evidence_id"], binding=binding, metrics=tuple(metrics), coverage=coverage,
                                limitations=tuple(value["limitations"]), evaluated_at=instant)
            if (value["posture"] != record.posture.value or type(value["coverage_ppm"]) is not int
                    or isinstance(value["coverage_ppm"], bool) or value["coverage_ppm"] != coverage.coverage_ppm
                    or value["digest"] != record.digest):
                _fail()
            return record
        except (TypeError, ValueError, OverflowError, KeyError):
            _fail()
