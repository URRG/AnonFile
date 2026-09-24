"""Bounded, aggregate-only quasi-identifier singling-out observations.

This private-worker primitive measures equivalence classes in one decoded
JSON/JSONL tabular candidate (a list of object records).  It is deliberately
separate from external-reference linkage and from release controls.  It emits
only opaque commitments and bounded aggregate counts; it is not a privacy
guarantee, approval, or authorization to release anything.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
import base64
import hashlib
import hmac
from itertools import islice
import json
import math
import re
from typing import Iterable

from .candidate import CandidateArtifact, CandidateError, PayloadKind


MAX_RECORDS = 10_000
MAX_QUASI_IDENTIFIERS = 32
MAX_FIELD_NAME_BYTES = 128
MAX_KEY_BYTES = 65_536
THRESHOLDS = (1, 2, 5, 10)
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_OPAQUE = re.compile(r"qidrisk:v1:[A-Za-z0-9_-]{43}\Z")


class QuasiIdentifierRiskError(ValueError):
    """Fixed error surface; candidate data and config details never reflect."""
    def __init__(self) -> None:
        super().__init__("Invalid quasi-identifier risk assessment.")


class QuasiIdentifierRiskStatus(StrEnum):
    ASSESSED = "ASSESSED"
    ABSTAINED = "ABSTAINED"


class QuasiIdentifierRiskAbstention(StrEnum):
    CONFIG_UNVERIFIED = "CONFIG_UNVERIFIED"
    TEXT_PAYLOAD = "TEXT_PAYLOAD"
    UNSUPPORTED_RECORD_SHAPE = "UNSUPPORTED_RECORD_SHAPE"
    EMPTY_RECORD_SET = "EMPTY_RECORD_SET"
    RECORD_LIMIT_EXCEEDED = "RECORD_LIMIT_EXCEEDED"
    QUASI_IDENTIFIER_NOT_APPLICABLE = "QUASI_IDENTIFIER_NOT_APPLICABLE"
    MISSING_OR_BLANK_QUASI_IDENTIFIER = "MISSING_OR_BLANK_QUASI_IDENTIFIER"
    CANDIDATE_UNAVAILABLE = "CANDIDATE_UNAVAILABLE"


def _fail() -> None:
    raise QuasiIdentifierRiskError()


def _canonical(value: object) -> bytes:
    try:
        result = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                            separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    if len(result) > MAX_KEY_BYTES:
        _fail()
    return result


def _scalar(value: object) -> bool:
    return value is None or type(value) in (str, int, bool) or (type(value) is float and math.isfinite(value))


def _fields(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        _fail()
    try:
        selected = tuple(islice(values, MAX_QUASI_IDENTIFIERS + 1))
    except TypeError:
        _fail()
    if (not 1 <= len(selected) <= MAX_QUASI_IDENTIFIERS
            or any(type(value) is not str or not _FIELD.fullmatch(value) for value in selected)
            or len(set(selected)) != len(selected)):
        _fail()
    try:
        if any(len(value.encode("utf-8")) > MAX_FIELD_NAME_BYTES for value in selected):
            _fail()
    except UnicodeError:
        _fail()
    return tuple(sorted(selected))


@dataclass(frozen=True, slots=True)
class QuasiIdentifierRiskConfig:
    """Private field selection and scope, with an opaque public binding."""
    _fields: tuple[str, ...] = field(repr=False)
    _scope: str = field(repr=False)
    _commitment: str = field(repr=False)

    def __post_init__(self) -> None:
        if _fields(self._fields) != self._fields or type(self._scope) is not str or not _SCOPE.fullmatch(self._scope):
            _fail()
        if type(self._commitment) is not str or not _OPAQUE.fullmatch(self._commitment):
            _fail()

    @property
    def field_count(self) -> int:
        return len(self._fields)

    @property
    def commitment(self) -> str:
        return self._commitment


@dataclass(frozen=True, slots=True)
class QuasiIdentifierRiskAuthority:
    """Trusted in-memory issuer; it never serializes its secret, fields, or scope."""
    _secret: bytes = field(repr=False)

    @classmethod
    def from_secret(cls, secret: bytes) -> "QuasiIdentifierRiskAuthority":
        return cls(secret)

    def __post_init__(self) -> None:
        if type(self._secret) is not bytes or not 32 <= len(self._secret) <= 64:
            _fail()

    def _token(self, purpose: str, value: object) -> str:
        token = hmac.new(self._secret, _canonical({"purpose": purpose, "value": value, "version": 1}), hashlib.sha256).digest()
        return "qidrisk:v1:" + base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")

    def create_config(self, fields: Iterable[str], *, scope: str) -> QuasiIdentifierRiskConfig:
        normalised = _fields(fields)
        if type(scope) is not str or not _SCOPE.fullmatch(scope):
            _fail()
        return QuasiIdentifierRiskConfig(normalised, scope, self._token("config", {"fields": normalised, "scope": scope}))

    def verifies(self, config: QuasiIdentifierRiskConfig) -> bool:
        if type(config) is not QuasiIdentifierRiskConfig:
            return False
        try:
            return hmac.compare_digest(config.commitment, self._token("config", {"fields": config._fields, "scope": config._scope}))
        except QuasiIdentifierRiskError:
            return False

    def candidate_commitment(self, candidate: CandidateArtifact, config: QuasiIdentifierRiskConfig) -> str:
        if type(candidate) is not CandidateArtifact or not self.verifies(config):
            _fail()
        return self._token("candidate", {"artifact": candidate.metadata.artifact_digest, "config": config.commitment})


@dataclass(frozen=True, slots=True)
class ThresholdDistribution:
    """Count of records in classes no larger than a fixed public threshold."""
    maximum_group_size: int
    record_count: int

    def __post_init__(self) -> None:
        if (type(self.maximum_group_size) is not int or self.maximum_group_size not in THRESHOLDS
                or type(self.record_count) is not int or not 0 <= self.record_count <= MAX_RECORDS):
            _fail()


@dataclass(frozen=True, slots=True)
class QuasiIdentifierRiskReport:
    """Safe observation.  No candidate bytes, raw hashes, field names, or scope appear here."""
    candidate_commitment: str | None
    config_commitment: str
    methodology: str
    quasi_identifier_count: int
    status: QuasiIdentifierRiskStatus
    abstention_reason: QuasiIdentifierRiskAbstention | None
    record_count: int | None
    minimum_group_size: int | None
    singleton_record_count: int | None
    threshold_distribution: tuple[ThresholdDistribution, ...]

    def __post_init__(self) -> None:
        if (self.candidate_commitment is not None and (type(self.candidate_commitment) is not str or not _OPAQUE.fullmatch(self.candidate_commitment))
                or type(self.config_commitment) is not str or not _OPAQUE.fullmatch(self.config_commitment)
                or self.methodology != "m24-qid-singling-out-v1"
                or type(self.quasi_identifier_count) is not int or not 1 <= self.quasi_identifier_count <= MAX_QUASI_IDENTIFIERS
                or not isinstance(self.status, QuasiIdentifierRiskStatus) or type(self.threshold_distribution) is not tuple):
            _fail()
        metrics = (self.record_count, self.minimum_group_size, self.singleton_record_count)
        if self.status is QuasiIdentifierRiskStatus.ABSTAINED:
            if (not isinstance(self.abstention_reason, QuasiIdentifierRiskAbstention)
                    or any(value is not None for value in metrics) or self.threshold_distribution):
                _fail()
        elif (type(self.candidate_commitment) is not str or self.abstention_reason is not None
              or type(self.record_count) is not int or not 1 <= self.record_count <= MAX_RECORDS
              or type(self.minimum_group_size) is not int or not 1 <= self.minimum_group_size <= self.record_count
              or type(self.singleton_record_count) is not int or not 0 <= self.singleton_record_count <= self.record_count
              or len(self.threshold_distribution) != len(THRESHOLDS)
              or tuple(item.maximum_group_size for item in self.threshold_distribution) != THRESHOLDS
              or any(type(item) is not ThresholdDistribution for item in self.threshold_distribution)
              or any(item.record_count > self.record_count for item in self.threshold_distribution)
              or self.threshold_distribution[0].record_count != self.singleton_record_count
              or any(item.record_count != 0 for item in self.threshold_distribution
                     if item.maximum_group_size < self.minimum_group_size)
              or (self.minimum_group_size <= THRESHOLDS[-1]
                  and not any(item.record_count > 0 for item in self.threshold_distribution
                              if item.maximum_group_size >= self.minimum_group_size))
              or (self.minimum_group_size == 1 and self.singleton_record_count == 0)
              or (self.minimum_group_size > 1 and self.singleton_record_count != 0)
              or any(left.record_count > right.record_count for left, right in zip(self.threshold_distribution, self.threshold_distribution[1:]))):
            _fail()

    def to_record(self) -> dict[str, object]:
        """Detached aggregate-only output suitable for an observation log."""
        return {"candidate_commitment": self.candidate_commitment, "config_commitment": self.config_commitment,
                "methodology": self.methodology, "quasi_identifier_count": self.quasi_identifier_count,
                "status": self.status.value, "abstention_reason": self.abstention_reason.value if self.abstention_reason else None,
                "record_count": self.record_count, "minimum_group_size": self.minimum_group_size,
                "singleton_record_count": self.singleton_record_count,
                "threshold_distribution": [{"maximum_group_size": item.maximum_group_size, "record_count": item.record_count}
                                           for item in self.threshold_distribution]}


def _abstain(candidate: CandidateArtifact, config: QuasiIdentifierRiskConfig,
             authority: QuasiIdentifierRiskAuthority, reason: QuasiIdentifierRiskAbstention) -> QuasiIdentifierRiskReport:
    return QuasiIdentifierRiskReport(authority.candidate_commitment(candidate, config), config.commitment,
                                     "m24-qid-singling-out-v1", config.field_count, QuasiIdentifierRiskStatus.ABSTAINED,
                                     reason, None, None, None, ())


def assess_quasi_identifier_risk(*, candidate: CandidateArtifact, config: QuasiIdentifierRiskConfig,
                                 authority: QuasiIdentifierRiskAuthority | None = None) -> QuasiIdentifierRiskReport:
    """Observe within-candidate QID group sizes; this neither evaluates policy nor authorizes release."""
    if type(candidate) is not CandidateArtifact or type(config) is not QuasiIdentifierRiskConfig:
        _fail()
    if type(authority) is not QuasiIdentifierRiskAuthority or not authority.verifies(config):
        # Do not manufacture a candidate binding without the issuer.  The
        # opaque config token remains safe to return with no metrics.
        return QuasiIdentifierRiskReport(None, config.commitment, "m24-qid-singling-out-v1", config.field_count,
                                         QuasiIdentifierRiskStatus.ABSTAINED,
                                         QuasiIdentifierRiskAbstention.CONFIG_UNVERIFIED, None, None, None, ())
    if candidate.metadata.payload_kind is PayloadKind.TEXT:
        return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.TEXT_PAYLOAD)
    try:
        payload = candidate.materialize_for_private_worker()
    except (CandidateError, TypeError, ValueError, UnicodeError):
        return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.CANDIDATE_UNAVAILABLE)
    if type(payload) is not list or any(type(row) is not dict for row in payload):
        return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.UNSUPPORTED_RECORD_SHAPE)
    if not payload:
        return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.EMPTY_RECORD_SET)
    if len(payload) > MAX_RECORDS:
        return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.RECORD_LIMIT_EXCEEDED)
    groups: Counter[bytes] = Counter()
    for row in payload:
        try:
            values = tuple(row[name] for name in config._fields)
        except KeyError:
            return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE)
        if not all(_scalar(value) for value in values):
            return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE)
        # Missingness and blanks often aggregate into a deceptively large
        # class.  Do not allow that to be interpreted as protection.
        if any(value is None or (type(value) is str and not value.strip()) for value in values):
            return _abstain(candidate, config, authority,
                            QuasiIdentifierRiskAbstention.MISSING_OR_BLANK_QUASI_IDENTIFIER)
        try:
            groups[_canonical(values)] += 1
        except QuasiIdentifierRiskError:
            return _abstain(candidate, config, authority, QuasiIdentifierRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE)
    sizes = tuple(groups.values())
    distribution = tuple(ThresholdDistribution(limit, sum(size for size in sizes if size <= limit)) for limit in THRESHOLDS)
    return QuasiIdentifierRiskReport(authority.candidate_commitment(candidate, config), config.commitment,
                                     "m24-qid-singling-out-v1", config.field_count, QuasiIdentifierRiskStatus.ASSESSED,
                                     None, len(payload), min(sizes), distribution[0].record_count, distribution)
