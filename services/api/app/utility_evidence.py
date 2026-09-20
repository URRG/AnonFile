"""Bounded, source-safe utility evidence for trusted worker stages.

This module compares a private input payload with one private candidate
artifact.  It deliberately emits only fixed aggregate measurements and opaque
commitments: no records, field names, paths, values, snippets, or input digest
are retained in a report.  It is an observational measurement, never a
qualification, approval, export, or delivery capability.

The source commitment is an HMAC held and verified by a trusted control plane.
Using a raw source hash would make small or known inputs vulnerable to
dictionary checks, so neither an input digest nor an unkeyed source hash is
published here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import hmac
import json
import re
from base64 import urlsafe_b64encode
from typing import Any

from .candidate import CandidateArtifact, CandidateError, MAX_CANDIDATE_BYTES, PayloadKind, canonical_json


MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_TEXT_BYTES = MAX_CANDIDATE_BYTES
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMITMENT = re.compile(r"utilsrc:v1:[A-Za-z0-9_-]{43,86}\Z")
_VERSION = 1
_METHODOLOGY = {
    "algorithm": "value-free-structural-utility",
    "revision": "m9-v1",
    "version": _VERSION,
}


class UtilityEvidenceError(ValueError):
    """Fixed error surface; source and candidate content is never reflected."""

    MESSAGE = "Invalid utility-evidence assessment."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class UtilityEvidenceStatus(StrEnum):
    ASSESSED = "ASSESSED"
    ABSTAINED = "ABSTAINED"


class UtilityEvidenceAbstention(StrEnum):
    SOURCE_COMMITMENT_UNVERIFIED = "SOURCE_COMMITMENT_UNVERIFIED"
    PAYLOAD_KIND_MISMATCH = "PAYLOAD_KIND_MISMATCH"


def _fail() -> None:
    raise UtilityEvidenceError()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _is_valid_text(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_TEXT_BYTES
    except UnicodeError:
        return False


def _payload_bytes(value: object) -> tuple[PayloadKind, bytes]:
    """Validate a bounded private input without exposing validation detail."""
    if type(value) is str:
        if not _is_valid_text(value):
            _fail()
        try:
            return PayloadKind.TEXT, value.encode("utf-8")
        except UnicodeError:
            _fail()
    if type(value) not in (dict, list):
        _fail()
    try:
        encoded = canonical_json(value)
    except CandidateError:
        _fail()
    return PayloadKind.STRUCTURED, encoded


@dataclass(frozen=True, slots=True)
class UtilityEvidenceAuthority:
    """Ephemeral issuer/verifier for opaque input commitments.

    The owner must obtain the 32--64 byte secret from a proper secret-management
    system.  The secret is deliberately neither generated, persisted, nor
    exposed by this primitive.
    """

    _secret: bytes = field(repr=False, compare=False)

    @classmethod
    def from_secret(cls, secret: bytes) -> "UtilityEvidenceAuthority":
        return cls(_secret=secret)

    def __post_init__(self) -> None:
        if type(self._secret) is not bytes or not 32 <= len(self._secret) <= 64:
            _fail()

    def issue(self, source: str | dict[str, Any] | list[Any]) -> str:
        """Commit to exactly one valid private source without retaining it."""
        kind, payload = _payload_bytes(source)
        # Length-delimited fixed components avoid ambiguous concatenation and
        # do not expand a 2 MiB payload into a multi-megabyte hexadecimal copy.
        kind_bytes = kind.value.encode("ascii")
        signed = (b"utilsrc" + bytes([_VERSION]) + bytes([len(kind_bytes)])
                  + kind_bytes + len(payload).to_bytes(4, "big") + payload)
        mac = hmac.new(self._secret, signed, hashlib.sha256).digest()
        return "utilsrc:v1:" + urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")

    def verifies(self, source: object, commitment: object) -> bool:
        if type(commitment) is not str or not _COMMITMENT.fullmatch(commitment):
            return False
        try:
            return hmac.compare_digest(self.issue(source), commitment)
        except UtilityEvidenceError:
            return False


@dataclass(frozen=True, slots=True)
class UtilitySnapshot:
    """Value-free internal summary.  It cannot carry schema or source content."""

    byte_count: int
    unit_count: int
    node_count: int
    container_count: int
    scalar_count: int
    non_null_scalar_count: int
    maximum_depth: int
    _shape: bytes = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in (
            self.byte_count, self.unit_count, self.node_count, self.container_count,
            self.scalar_count, self.non_null_scalar_count, self.maximum_depth,
        )):
            _fail()
        if (self.byte_count > MAX_CANDIDATE_BYTES or self.unit_count < 1
                or self.node_count < 1 or self.container_count + self.scalar_count != self.node_count
                or self.non_null_scalar_count > self.scalar_count or self.maximum_depth > MAX_DEPTH
                or type(self._shape) is not bytes or len(self._shape) > MAX_CANDIDATE_BYTES):
            _fail()


def _value_free_shape(value: object) -> object:
    """Return a deterministic shape with no object keys or scalar contents."""
    kind = type(value)
    if kind is dict:
        # Keys are intentionally removed.  Sorting only child shapes makes the
        # result deterministic without turning key names into an observable.
        children = [_value_free_shape(item) for item in value.values()]
        return ["object", sorted(children, key=lambda item: _canonical(item))]
    if kind is list:
        return ["array", [_value_free_shape(item) for item in value]]
    if value is None:
        return "null"
    if kind is bool:
        return "boolean"
    if kind is int:
        return "integer"
    if kind is float:
        return "number"
    if kind is str:
        return "string"
    _fail()


def _snapshot(value: str | dict[str, Any] | list[Any]) -> UtilitySnapshot:
    payload_kind, encoded = _payload_bytes(value)
    if payload_kind is PayloadKind.TEXT:
        return UtilitySnapshot(byte_count=len(encoded), unit_count=1, node_count=1,
                               container_count=0, scalar_count=1, non_null_scalar_count=1,
                               maximum_depth=0, _shape=_canonical("text"))

    nodes = containers = scalars = non_null = maximum_depth = 0
    active: set[int] = set()
    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active.remove(id(current))
            continue
        nodes += 1
        maximum_depth = max(maximum_depth, depth)
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            _fail()
        kind = type(current)
        if kind in (dict, list):
            if id(current) in active:
                _fail()
            containers += 1
            active.add(id(current))
            stack.append((current, depth, True))
            children = current.values() if kind is dict else current
            stack.extend((child, depth + 1, False) for child in children)
        else:
            if current is not None:
                non_null += 1
            scalars += 1
    units = len(value) if type(value) is list else 1
    return UtilitySnapshot(byte_count=len(encoded), unit_count=units, node_count=nodes,
                           container_count=containers, scalar_count=scalars,
                           non_null_scalar_count=non_null, maximum_depth=maximum_depth,
                           _shape=_canonical(_value_free_shape(value)))


@dataclass(frozen=True, slots=True)
class DataUtilityReport:
    """Aggregate-only, candidate-bound measurement evidence.

    The status is never a release authorization.  An ``ASSESSED`` result only
    says that a bounded, committed source was compared to the exact candidate.
    It does not assess semantic correctness, downstream ML utility, privacy,
    linkage risk, or contractual fitness.
    """

    candidate_artifact_digest: str
    source_commitment: str
    methodology_digest: str
    status: UtilityEvidenceStatus
    abstention_reason: UtilityEvidenceAbstention | None
    input_byte_count: int | None
    candidate_byte_count: int | None
    input_unit_count: int | None
    candidate_unit_count: int | None
    input_node_count: int | None
    candidate_node_count: int | None
    input_scalar_count: int | None
    candidate_scalar_count: int | None
    input_non_null_scalar_count: int | None
    candidate_non_null_scalar_count: int | None
    structure_preserved: bool | None
    unit_count_preserved: bool | None
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        for value in (self.candidate_artifact_digest, self.methodology_digest):
            if type(value) is not str or not _DIGEST.fullmatch(value):
                _fail()
        if type(self.source_commitment) is not str or not _COMMITMENT.fullmatch(self.source_commitment):
            _fail()
        if not isinstance(self.status, UtilityEvidenceStatus):
            _fail()
        metrics = (self.input_byte_count, self.candidate_byte_count, self.input_unit_count,
                   self.candidate_unit_count, self.input_node_count, self.candidate_node_count,
                   self.input_scalar_count, self.candidate_scalar_count, self.input_non_null_scalar_count,
                   self.candidate_non_null_scalar_count)
        checks = (self.structure_preserved, self.unit_count_preserved)
        if self.status is UtilityEvidenceStatus.ABSTAINED:
            if (not isinstance(self.abstention_reason, UtilityEvidenceAbstention)
                    or any(item is not None for item in metrics + checks)):
                _fail()
        elif (self.abstention_reason is not None or any(type(item) is not int or item < 0 for item in metrics)
              or any(type(item) is not bool for item in checks)):
            _fail()
        object.__setattr__(self, "digest", _digest(_canonical(self._record_without_digest())))

    def _record_without_digest(self) -> dict[str, object]:
        return {
            "abstention_reason": self.abstention_reason.value if self.abstention_reason else None,
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_byte_count": self.candidate_byte_count,
            "candidate_node_count": self.candidate_node_count,
            "candidate_non_null_scalar_count": self.candidate_non_null_scalar_count,
            "candidate_scalar_count": self.candidate_scalar_count,
            "candidate_unit_count": self.candidate_unit_count,
            "input_byte_count": self.input_byte_count,
            "input_node_count": self.input_node_count,
            "input_non_null_scalar_count": self.input_non_null_scalar_count,
            "input_scalar_count": self.input_scalar_count,
            "input_unit_count": self.input_unit_count,
            "methodology_digest": self.methodology_digest,
            "source_commitment": self.source_commitment,
            "status": self.status.value,
            "structure_preserved": self.structure_preserved,
            "unit_count_preserved": self.unit_count_preserved,
            "version": _VERSION,
        }

    def to_record(self) -> dict[str, object]:
        """Detached, aggregate-only record suitable for controlled persistence."""
        return {**self._record_without_digest(), "digest": self.digest}


METHODOLOGY_DIGEST = _digest(_canonical(_METHODOLOGY))


def _abstain(candidate: CandidateArtifact, source_commitment: str,
             reason: UtilityEvidenceAbstention) -> DataUtilityReport:
    metadata = candidate.metadata
    return DataUtilityReport(
        candidate_artifact_digest=metadata.artifact_digest,
        source_commitment=source_commitment, methodology_digest=METHODOLOGY_DIGEST,
        status=UtilityEvidenceStatus.ABSTAINED, abstention_reason=reason,
        input_byte_count=None, candidate_byte_count=None, input_unit_count=None, candidate_unit_count=None,
        input_node_count=None, candidate_node_count=None, input_scalar_count=None, candidate_scalar_count=None,
        input_non_null_scalar_count=None, candidate_non_null_scalar_count=None,
        structure_preserved=None, unit_count_preserved=None,
    )


def assess_data_utility(*, source: str | dict[str, Any] | list[Any], candidate: CandidateArtifact,
                        source_commitment: str,
                        commitment_verifier: UtilityEvidenceAuthority | None = None) -> DataUtilityReport:
    """Compare an exact committed source and exact candidate in a trusted worker.

    Missing, malformed, oversized, cyclic, tampered, or foreign source inputs
    cannot produce metrics: all become a source-commitment abstention.  The
    report never stores the source or candidate payload after this call.
    """
    if not isinstance(candidate, CandidateArtifact) or type(source_commitment) is not str or not _COMMITMENT.fullmatch(source_commitment):
        _fail()
    if (not isinstance(commitment_verifier, UtilityEvidenceAuthority)
            or not commitment_verifier.verifies(source, source_commitment)):
        return _abstain(candidate, source_commitment, UtilityEvidenceAbstention.SOURCE_COMMITMENT_UNVERIFIED)
    try:
        source_kind, _ = _payload_bytes(source)
        candidate_payload = candidate.materialize_for_private_worker()
        candidate_kind, _ = _payload_bytes(candidate_payload)
    except (UtilityEvidenceError, CandidateError):
        return _abstain(candidate, source_commitment, UtilityEvidenceAbstention.SOURCE_COMMITMENT_UNVERIFIED)
    if source_kind is not candidate_kind:
        return _abstain(candidate, source_commitment, UtilityEvidenceAbstention.PAYLOAD_KIND_MISMATCH)
    input_snapshot, candidate_snapshot = _snapshot(source), _snapshot(candidate_payload)
    metadata = candidate.metadata
    return DataUtilityReport(
        candidate_artifact_digest=metadata.artifact_digest,
        source_commitment=source_commitment, methodology_digest=METHODOLOGY_DIGEST,
        status=UtilityEvidenceStatus.ASSESSED, abstention_reason=None,
        input_byte_count=input_snapshot.byte_count, candidate_byte_count=candidate_snapshot.byte_count,
        input_unit_count=input_snapshot.unit_count, candidate_unit_count=candidate_snapshot.unit_count,
        input_node_count=input_snapshot.node_count, candidate_node_count=candidate_snapshot.node_count,
        input_scalar_count=input_snapshot.scalar_count, candidate_scalar_count=candidate_snapshot.scalar_count,
        input_non_null_scalar_count=input_snapshot.non_null_scalar_count,
        candidate_non_null_scalar_count=candidate_snapshot.non_null_scalar_count,
        structure_preserved=input_snapshot._shape == candidate_snapshot._shape,
        unit_count_preserved=input_snapshot.unit_count == candidate_snapshot.unit_count,
    )
