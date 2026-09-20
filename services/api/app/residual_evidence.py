"""Aggregate-only evidence produced by the independent residual scanner.

This is deliberately a worker-side conversion layer.  It never accepts a
client report and never exposes candidate bytes, paths, matches, or detector
internals beyond the already-versioned scanner configuration identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import hmac
import json
import re

from app.candidate import CandidateArtifact, CandidateError
from app.independent_residual import ASSESSED_CATEGORIES, DETECTOR_CONFIG_DIGEST, DETECTOR_ID, scan_residual_candidate

PPM = 1_000_000
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ResidualEvidenceError(ValueError):
    def __init__(self): super().__init__("Invalid residual evidence")


class ResidualEvidenceStatus(StrEnum):
    ASSESSED = "ASSESSED"
    ABSTAINED = "ABSTAINED"


def _fail(): raise ResidualEvidenceError()
def _canon(value):
    try: return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError): _fail()
def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value): _fail()
    return value


@dataclass(frozen=True, slots=True)
class IndependentResidualReport:
    """One complete aggregate scan.  The score is a maximum, hence lower safer."""
    candidate_artifact_digest: str
    detector_id: str
    detector_config_digest: str
    status: ResidualEvidenceStatus
    total_units: int
    scanned_units: int
    abstained_units: int
    assessed_categories: tuple[str, ...]
    residual_counts: tuple[tuple[str, int], ...]
    maximum_residual_ppm: int | None
    digest: str = field(init=False)

    def __post_init__(self):
        _digest(self.candidate_artifact_digest); _digest(self.detector_config_digest)
        if (self.detector_id != DETECTOR_ID or self.detector_config_digest != DETECTOR_CONFIG_DIGEST
                or type(self.status) is not ResidualEvidenceStatus or type(self.total_units) is not int
                or type(self.scanned_units) is not int or type(self.abstained_units) is not int
                or not 1 <= self.total_units <= 10_000 or self.scanned_units != self.total_units
                or not 0 <= self.abstained_units <= self.scanned_units
                or type(self.assessed_categories) is not tuple
                or self.assessed_categories != tuple(sorted(ASSESSED_CATEGORIES))
                or type(self.residual_counts) is not tuple or len(self.residual_counts) != len(self.assessed_categories)
                or tuple(k for k, _ in self.residual_counts) != self.assessed_categories
                or any(type(n) is not int or isinstance(n, bool) or not 0 <= n <= self.scanned_units for _, n in self.residual_counts)):
            _fail()
        if self.status is ResidualEvidenceStatus.ASSESSED:
            if self.abstained_units != 0 or type(self.maximum_residual_ppm) is not int or not 0 <= self.maximum_residual_ppm <= PPM:
                _fail()
            maximum = max(n * PPM // self.scanned_units for _, n in self.residual_counts)
            if self.maximum_residual_ppm != maximum: _fail()
        elif self.maximum_residual_ppm is not None: _fail()
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(_canon(self._without_digest())).hexdigest())

    def _without_digest(self):
        return {"version": 1, "candidate_artifact_digest": self.candidate_artifact_digest,
                "detector_id": self.detector_id, "detector_config_digest": self.detector_config_digest,
                "status": self.status.value, "total_units": self.total_units, "scanned_units": self.scanned_units,
                "abstained_units": self.abstained_units, "assessed_categories": list(self.assessed_categories),
                "residual_counts": {k: n for k, n in self.residual_counts},
                "maximum_residual_ppm": self.maximum_residual_ppm}
    def to_record(self): return {**self._without_digest(), "digest": self.digest}
    @classmethod
    def from_record(cls, value):
        try:
            expected={"version","candidate_artifact_digest","detector_id","detector_config_digest","status","total_units","scanned_units","abstained_units","assessed_categories","residual_counts","maximum_residual_ppm","digest"}
            if type(value) is not dict or set(value) != expected or value["version"] != 1 or type(value["assessed_categories"]) is not list or type(value["residual_counts"]) is not dict: _fail()
            item=cls(value["candidate_artifact_digest"],value["detector_id"],value["detector_config_digest"],ResidualEvidenceStatus(value["status"]),value["total_units"],value["scanned_units"],value["abstained_units"],tuple(value["assessed_categories"]),tuple(sorted(value["residual_counts"].items())),value["maximum_residual_ppm"])
            if type(value["digest"]) is not str or not hmac.compare_digest(item.digest,value["digest"]): _fail()
            return item
        except (KeyError, TypeError, ValueError, ResidualEvidenceError): _fail()


def scan_independent_residual(*, candidate: CandidateArtifact) -> IndependentResidualReport:
    if type(candidate) is not CandidateArtifact: _fail()
    try:
        payload=candidate.materialize_for_private_worker()
        # The scanner defines list members as top-level units.  A structured
        # object is one unit, not an iterable of its keys: passing it directly
        # would silently scan only field names and could falsely report zero.
        if type(payload) is dict:
            scanner_input=[payload]
        elif type(payload) in (str, list):
            scanner_input=payload
        else:
            _fail()
        result=scan_residual_candidate(scanner_input)
    except (CandidateError, TypeError, ValueError, RecursionError): _fail()
    counts=tuple((category, result.residual_counts.get(category)) for category in sorted(ASSESSED_CATEGORIES))
    total=1 if type(payload) in (str, dict) else len(payload)
    # The scanner's count must agree with the private artifact boundary.  A
    # disagreement is an integrity failure, not a zero-risk observation.
    if result.scanned_units != total: _fail()
    status=ResidualEvidenceStatus.ASSESSED if result.abstained_units == 0 else ResidualEvidenceStatus.ABSTAINED
    return IndependentResidualReport(candidate.metadata.artifact_digest, DETECTOR_ID, DETECTOR_CONFIG_DIGEST, status,
        total, result.scanned_units, result.abstained_units, tuple(sorted(ASSESSED_CATEGORIES)), counts,
        max(n * PPM // total for _,n in counts) if status is ResidualEvidenceStatus.ASSESSED else None)
