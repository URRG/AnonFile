"""Server-owned admission profile for M17 benchmark policy evidence.

M8 evaluator reports are useful method observations, but an allowlisted
evaluator alone is not a release-gate benchmark.  This module fixes the exact
evaluator, corpus, detector, configuration, taxonomy, required categories and
per-category reference coverage that may be converted into M15's BENCHMARK
measurement.  It never accepts a client-selected subset or exposes corpus
contents, annotations, predictions, or source records.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
import re
from typing import Iterable

from app.evaluation_harness import ScoredEvaluation
from app.evaluator_authority import EvaluatorAuthority
from app.policies import TAXONOMY_CATEGORIES


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_MAX_CONFIG_BYTES = 32_000
_MAX_REFERENCE_COUNT = 1_000_000_000


class BenchmarkEvidenceProfileError(ValueError):
    """Fixed failure that never reflects profile or report contents."""

    def __init__(self) -> None:
        super().__init__("Invalid benchmark evidence profile")


def _fail() -> None:
    raise BenchmarkEvidenceProfileError()


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class BenchmarkEvidenceProfile:
    """One complete, tenant-owned benchmark qualification profile.

    The M15 threshold remains owned by the privacy-decision policy.  This
    profile instead fixes *what* is measured and proves every required family
    has a non-zero bounded annotation/reference population before the minimum
    category recall is calculated.
    """

    tenant: str
    evaluator_subject: str
    evaluator_id: str
    evaluator_version: str
    evaluator_config_digest: str
    corpus_digest: str
    detector_id: str
    detector_version: str
    detector_config_digest: str
    taxonomy_mapping_digest: str
    required_categories: tuple[str, ...]
    minimum_category_reference_count: int

    def __post_init__(self) -> None:
        for value in (self.tenant, self.evaluator_subject, self.evaluator_id,
                      self.evaluator_version, self.detector_id, self.detector_version):
            _identifier(value)
        for value in (self.evaluator_config_digest, self.corpus_digest,
                      self.detector_config_digest, self.taxonomy_mapping_digest):
            _digest(value)
        # This is a release-gate input, not a task-specific benchmark.  A
        # tenant cannot make a score look better by configuring only the easy
        # families: the profile must cover the complete platform taxonomy.
        if (type(self.required_categories) is not tuple
                or self.required_categories != tuple(sorted(TAXONOMY_CATEGORIES))
                or type(self.minimum_category_reference_count) is not int
                or isinstance(self.minimum_category_reference_count, bool)
                or not 1 <= self.minimum_category_reference_count <= _MAX_REFERENCE_COUNT):
            _fail()

    def canonical(self) -> dict[str, object]:
        """The complete server-owned measurement definition."""
        return {
            "corpus_digest": self.corpus_digest,
            "detector_config_digest": self.detector_config_digest,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "evaluator_config_digest": self.evaluator_config_digest,
            "evaluator_id": self.evaluator_id,
            "evaluator_subject": self.evaluator_subject,
            "evaluator_version": self.evaluator_version,
            "minimum_category_reference_count": self.minimum_category_reference_count,
            "required_categories": list(self.required_categories),
            "taxonomy_mapping_digest": self.taxonomy_mapping_digest,
            "tenant": self.tenant,
        }

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(json.dumps(
            self.canonical(), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":")).encode("ascii")).hexdigest()

    def matches_authority(self, authority: object) -> bool:
        """Require the current exact evaluator authority, not an old allowlist."""
        return (type(authority) is EvaluatorAuthority
                and authority.subject == self.evaluator_subject
                and authority.tenant == self.tenant
                and authority.evaluator_id == self.evaluator_id
                and authority.evaluator_version == self.evaluator_version
                and authority.evaluator_config_digest == self.evaluator_config_digest
                and self.corpus_digest in authority.corpus_digests)

    def observe(self, *, report: object, authority: object, evaluator_subject: object,
                evaluator_authority_id: object) -> int:
        """Return the conservative minimum recall, or reject the whole report.

        Exact category equality prevents selecting only the best-scoring
        families.  Per-category reference coverage prevents an undefined
        recall from being interpreted as a clean result.
        """
        if (type(report) is not ScoredEvaluation or type(evaluator_subject) is not str
                or type(evaluator_authority_id) is not str or not self.matches_authority(authority)
                or evaluator_subject != self.evaluator_subject
                or evaluator_authority_id != authority.authority_id):
            _fail()
        binding = report.binding
        if ((binding.evaluator_id, binding.evaluator_version, binding.evaluator_config_digest,
             binding.corpus_digest, binding.detector_id, binding.detector_version,
             binding.detector_config_digest, binding.taxonomy_mapping_digest) != (
                self.evaluator_id, self.evaluator_version, self.evaluator_config_digest,
                self.corpus_digest, self.detector_id, self.detector_version,
                self.detector_config_digest, self.taxonomy_mapping_digest)):
            _fail()
        if tuple(metric.category for metric in report.metrics) != self.required_categories:
            _fail()
        recalls: list[int] = []
        for metric in report.metrics:
            references = metric.true_positives + metric.false_negatives
            if references < self.minimum_category_reference_count or metric.recall_ppm is None:
                _fail()
            recalls.append(metric.recall_ppm)
        return min(recalls)


@dataclass(frozen=True, slots=True)
class BenchmarkEvidenceAssessment:
    """A source-safe M17 adapter result, derived only inside the control plane.

    The assessment intentionally stores neither benchmark examples nor
    predictions nor the per-category score vector.  Its single value is the
    minimum recall across every profile-required category, which prevents a
    caller from cherry-picking a favourable category into M15.
    """

    profile_digest: str
    source_report_digest: str
    conservative_recall_ppm: int
    evaluated_at: datetime

    def __post_init__(self) -> None:
        _digest(self.profile_digest)
        _digest(self.source_report_digest)
        if (type(self.conservative_recall_ppm) is not int or isinstance(self.conservative_recall_ppm, bool)
                or not 0 <= self.conservative_recall_ppm <= 1_000_000
                or not isinstance(self.evaluated_at, datetime) or self.evaluated_at.tzinfo is None
                or self.evaluated_at.utcoffset() is None):
            _fail()
        object.__setattr__(self, "evaluated_at", self.evaluated_at.astimezone(UTC).replace(microsecond=0))

    @classmethod
    def from_profile(cls, *, profile: BenchmarkEvidenceProfile, report: ScoredEvaluation,
                     authority: EvaluatorAuthority, evaluator_subject: str,
                     evaluator_authority_id: str) -> "BenchmarkEvidenceAssessment":
        return cls(profile_digest=profile.digest, source_report_digest=report.digest,
                   conservative_recall_ppm=profile.observe(report=report, authority=authority,
                                                            evaluator_subject=evaluator_subject,
                                                            evaluator_authority_id=evaluator_authority_id),
                   evaluated_at=report.evaluated_at)

    def to_record(self) -> dict[str, object]:
        return {"profile_digest": self.profile_digest, "source_report_digest": self.source_report_digest,
                "conservative_recall_ppm": self.conservative_recall_ppm,
                "evaluated_at": self.evaluated_at.isoformat().replace("+00:00", "Z")}

    @classmethod
    def from_record(cls, value: object) -> "BenchmarkEvidenceAssessment":
        if not isinstance(value, dict) or set(value) != {"profile_digest", "source_report_digest", "conservative_recall_ppm", "evaluated_at"}:
            _fail()
        try:
            return cls(profile_digest=value["profile_digest"], source_report_digest=value["source_report_digest"],
                       conservative_recall_ppm=value["conservative_recall_ppm"],
                       evaluated_at=datetime.fromisoformat(value["evaluated_at"].replace("Z", "+00:00")))
        except (TypeError, ValueError, AttributeError):
            _fail()


def load_benchmark_evidence_profiles() -> tuple[BenchmarkEvidenceProfile, ...]:
    """Load explicit profiles; absent configuration intentionally admits none."""
    raw = os.getenv("ANONFLOW_BENCHMARK_EVIDENCE_PROFILES", "")
    if not raw:
        return ()
    if len(raw.encode("utf-8")) > _MAX_CONFIG_BYTES:
        _fail()
    try:
        def unique_object(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise ValueError
                output[key] = value
            return output
        entries = json.loads(raw, object_pairs_hook=unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries) > 64:
            _fail()
        profiles: list[BenchmarkEvidenceProfile] = []
        tenants: set[str] = set()
        required = {"tenant", "evaluator_subject", "evaluator_id", "evaluator_version",
                    "evaluator_config_digest", "corpus_digest", "detector_id", "detector_version",
                    "detector_config_digest", "taxonomy_mapping_digest", "required_categories",
                    "minimum_category_reference_count"}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != required or type(entry["required_categories"]) is not list:
                _fail()
            profile = BenchmarkEvidenceProfile(
                tenant=entry["tenant"], evaluator_subject=entry["evaluator_subject"],
                evaluator_id=entry["evaluator_id"], evaluator_version=entry["evaluator_version"],
                evaluator_config_digest=entry["evaluator_config_digest"], corpus_digest=entry["corpus_digest"],
                detector_id=entry["detector_id"], detector_version=entry["detector_version"],
                detector_config_digest=entry["detector_config_digest"],
                taxonomy_mapping_digest=entry["taxonomy_mapping_digest"],
                required_categories=tuple(entry["required_categories"]),
                minimum_category_reference_count=entry["minimum_category_reference_count"],
            )
            if profile.tenant in tenants:
                _fail()
            tenants.add(profile.tenant)
            profiles.append(profile)
        return tuple(profiles)
    except (TypeError, ValueError, UnicodeError, BenchmarkEvidenceProfileError):
        _fail()


def profile_for_tenant(profiles: Iterable[BenchmarkEvidenceProfile], *, tenant: str) -> BenchmarkEvidenceProfile:
    matches = [profile for profile in profiles if type(profile) is BenchmarkEvidenceProfile and profile.tenant == tenant]
    if len(matches) != 1:
        _fail()
    return matches[0]
