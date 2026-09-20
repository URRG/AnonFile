"""Private, bounded candidate-artifact domain.

Candidate bytes are an internal worker concern.  This module can retain them in
an immutable value for a trusted in-process handoff, but never places them in a
representation or metadata record.  It grants no authorization, approval,
delivery capability, URL, or recipient access.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable


MAX_CANDIDATE_BYTES = 2_000_000
MAX_VALUE_BYTES = 65_536
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_LEDGER_ENTRIES = 256
MAX_LEDGER_COUNT = 1_000_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ENTITY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


class CandidateError(ValueError):
    """A fixed, source-independent candidate validation error."""

    MESSAGE = "Invalid private candidate artifact."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


class PayloadKind(StrEnum):
    TEXT = "text"
    STRUCTURED = "structured"


class LedgerAction(StrEnum):
    REDACT = "REDACT"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    GENERALIZE = "GENERALIZE"
    SUPPRESS = "SUPPRESS"
    NULLIFY = "NULLIFY"


class LedgerReason(StrEnum):
    POLICY_RULE = "POLICY_RULE"
    DETECTOR_FINDING = "DETECTOR_FINDING"
    SCHEMA_SAFE_NULL = "SCHEMA_SAFE_NULL"


def _fail() -> None:
    raise CandidateError()


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _string(value: str) -> None:
    try:
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            _fail()
    except UnicodeError:
        _fail()


def _validate_json(value: Any) -> None:
    """Validate JSON data without serializing an unbounded/cyclic graph."""
    active: set[int] = set()
    nodes = 0
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active.remove(id(current))
            continue
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            _fail()
        kind = type(current)
        if kind in (dict, list):
            if len(current) > MAX_NODES or id(current) in active:
                _fail()
            active.add(id(current))
            stack.append((current, depth, True))
            if kind is dict:
                for key, child in current.items():
                    if type(key) is not str:
                        _fail()
                    _string(key)
                    stack.append((child, depth + 1, False))
            else:
                stack.extend((child, depth + 1, False) for child in current)
        elif kind is str:
            _string(current)
        elif kind is float and not math.isfinite(current):
            _fail()
        elif kind not in (int, float, bool) and current is not None:
            _fail()


def canonical_json(value: Any) -> bytes:
    """Canonical JSON used for structured bytes, schemas and artifact digests."""
    _validate_json(value)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail()
    if len(encoded) > MAX_CANDIDATE_BYTES:
        _fail()
    return encoded


@dataclass(frozen=True, slots=True)
class TransformLedgerEntry:
    """An aggregate action record that intentionally has no field path/value."""

    entity_type: str
    action: LedgerAction
    reason: LedgerReason
    count: int

    def __post_init__(self) -> None:
        if (type(self.entity_type) is not str or not _ENTITY.fullmatch(self.entity_type)
                or not isinstance(self.action, LedgerAction) or not isinstance(self.reason, LedgerReason)
                or type(self.count) is not int or not 1 <= self.count <= MAX_LEDGER_COUNT):
            _fail()


def _shape(value: Any, *, nullable_scalars: bool, depth: int = 0) -> dict[str, Any]:
    if depth > MAX_DEPTH:
        _fail()
    kind = type(value)
    if kind is dict:
        return {"type": "object", "fields": [[key, _shape(value[key], nullable_scalars=nullable_scalars, depth=depth + 1)]
                                                   for key in sorted(value)]}
    if kind is list:
        return {"type": "array", "items": [_shape(item, nullable_scalars=nullable_scalars, depth=depth + 1)
                                                for item in value]}
    if kind is str:
        return {"type": "string", "nullable": nullable_scalars}
    if kind is bool:
        return {"type": "boolean", "nullable": nullable_scalars}
    if kind is int:
        return {"type": "integer", "nullable": nullable_scalars}
    if kind is float:
        return {"type": "number", "nullable": nullable_scalars}
    if value is None:
        return {"type": "null"}
    _fail()


def _validate_shape(value: Any) -> None:
    """Validate the compact schema descriptor before trusting direct construction."""
    if not isinstance(value, dict) or type(value.get("type")) is not str:
        _fail()
    kind = value["type"]
    if kind == "object":
        if set(value) != {"type", "fields"} or type(value["fields"]) is not list:
            _fail()
        keys: list[str] = []
        for item in value["fields"]:
            if type(item) is not list or len(item) != 2 or type(item[0]) is not str:
                _fail()
            _string(item[0])
            keys.append(item[0])
            _validate_shape(item[1])
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            _fail()
    elif kind == "array":
        if set(value) != {"type", "items"} or type(value["items"]) is not list:
            _fail()
        for item in value["items"]:
            _validate_shape(item)
    elif kind in {"string", "boolean", "integer", "number"}:
        if set(value) != {"type", "nullable"} or type(value["nullable"]) is not bool:
            _fail()
    elif kind != "null" or set(value) != {"type"}:
        _fail()


def _compatible(expected: dict[str, Any], actual: dict[str, Any]) -> bool:
    if actual["type"] == "null" and expected.get("nullable") is True:
        return True
    if expected["type"] != actual["type"]:
        return False
    if expected["type"] == "object":
        expected_fields, actual_fields = expected["fields"], actual["fields"]
        return (len(expected_fields) == len(actual_fields)
                and all(left[0] == right[0] and _compatible(left[1], right[1])
                        for left, right in zip(expected_fields, actual_fields)))
    if expected["type"] == "array":
        return (len(expected["items"]) == len(actual["items"])
                and all(_compatible(left, right) for left, right in zip(expected["items"], actual["items"])))
    return True


@dataclass(frozen=True, slots=True)
class SchemaContract:
    """Private expected type shape; field names never appear in its repr."""

    kind: PayloadKind
    digest: str
    _descriptor: bytes = field(repr=False, compare=True)

    @classmethod
    def from_value(cls, value: str | dict[str, Any] | list[Any], *, kind: PayloadKind,
                   allow_scalar_nulls: bool = False) -> "SchemaContract":
        if not isinstance(kind, PayloadKind) or type(allow_scalar_nulls) is not bool:
            _fail()
        if kind is PayloadKind.TEXT:
            if type(value) is not str:
                _fail()
            # Text is one artifact, not a structured scalar.  It shares the
            # artifact's 2 MiB byte ceiling; applying the 64 KiB scalar bound
            # here made already-accepted ingestion payloads fail during
            # candidate construction.
            try:
                if not value or len(value.encode("utf-8")) > MAX_CANDIDATE_BYTES:
                    _fail()
            except UnicodeError:
                _fail()
            descriptor = canonical_json({"type": "text"})
        else:
            if type(value) not in (dict, list):
                _fail()
            _validate_json(value)
            descriptor = canonical_json(_shape(value, nullable_scalars=allow_scalar_nulls))
        return cls(kind=kind, digest=_hash(descriptor), _descriptor=descriptor)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PayloadKind) or type(self._descriptor) is not bytes:
            _fail()
        try:
            descriptor = json.loads(self._descriptor.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail()
        if self.kind is PayloadKind.TEXT:
            if descriptor != {"type": "text"}:
                _fail()
        else:
            _validate_shape(descriptor)
        if canonical_json(descriptor) != self._descriptor or self.digest != _hash(self._descriptor):
            _fail()

    @classmethod
    def from_private_descriptor(cls, *, kind: PayloadKind, digest: str, descriptor: Any) -> "SchemaContract":
        """Restore a schema only from an encrypted private artifact record."""
        return cls(kind=kind, digest=digest, _descriptor=canonical_json(descriptor))

    @property
    def private_descriptor(self) -> Any:
        """Detached field/type shape for encrypted persistence; never API data."""
        try:
            return json.loads(self._descriptor.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail()

    def accepts(self, value: str | dict[str, Any] | list[Any]) -> bool:
        try:
            if self.kind is PayloadKind.TEXT:
                return type(value) is str and canonical_json({"type": "text"}) == self._descriptor
            if type(value) not in (dict, list):
                return False
            _validate_json(value)
            return _compatible(json.loads(self._descriptor), _shape(value, nullable_scalars=False))
        except (CandidateError, TypeError, ValueError, UnicodeError):
            return False


@dataclass(frozen=True, slots=True)
class CandidateMetadata:
    """Safe-only descriptor for persistence/audit; no candidate bytes exist here."""

    run_id: str
    input_digest: str
    policy_digest: str
    artifact_digest: str
    schema_digest: str
    payload_kind: PayloadKind
    media_type: str
    byte_count: int
    ledger: tuple[TransformLedgerEntry, ...]

    def __post_init__(self) -> None:
        _identifier(self.run_id)
        for digest in (self.input_digest, self.policy_digest, self.artifact_digest, self.schema_digest):
            _digest(digest)
        if not isinstance(self.payload_kind, PayloadKind):
            _fail()
        expected_media = "text/plain" if self.payload_kind is PayloadKind.TEXT else "application/json"
        if (self.media_type != expected_media or type(self.byte_count) is not int
                or not 0 <= self.byte_count <= MAX_CANDIDATE_BYTES
                or type(self.ledger) is not tuple or len(self.ledger) > MAX_LEDGER_ENTRIES
                or any(not isinstance(item, TransformLedgerEntry) for item in self.ledger)):
            _fail()
        if tuple(sorted(self.ledger, key=lambda entry: (entry.entity_type, entry.action.value, entry.reason.value))) != self.ledger:
            _fail()
        if len({(entry.entity_type, entry.action, entry.reason) for entry in self.ledger}) != len(self.ledger):
            _fail()


@dataclass(frozen=True, slots=True)
class CandidateArtifact:
    """A private candidate payload plus immutable, source-free metadata."""

    _metadata: CandidateMetadata
    _encoded: bytes = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        if not isinstance(self._metadata, CandidateMetadata) or type(self._encoded) is not bytes:
            _fail()
        if len(self._encoded) != self._metadata.byte_count or _hash(self._encoded) != self._metadata.artifact_digest:
            _fail()
        try:
            if self._metadata.payload_kind is PayloadKind.TEXT:
                self._encoded.decode("utf-8")
            else:
                decoded = json.loads(self._encoded.decode("utf-8"))
                if type(decoded) not in (dict, list) or canonical_json(decoded) != self._encoded:
                    _fail()
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail()

    @classmethod
    def create(cls, *, run_id: str, input_digest: str, policy_digest: str,
               transformed: str | dict[str, Any] | list[Any], schema: SchemaContract,
               ledger: Iterable[TransformLedgerEntry] = ()) -> "CandidateArtifact":
        run_id, input_digest, policy_digest = _identifier(run_id), _digest(input_digest), _digest(policy_digest)
        if not isinstance(schema, SchemaContract):
            _fail()
        try:
            entries = tuple(ledger)
        except TypeError:
            _fail()
        if len(entries) > MAX_LEDGER_ENTRIES or any(not isinstance(entry, TransformLedgerEntry) for entry in entries):
            _fail()
        # Aggregate rows must be deterministic and unique; the ledger cannot
        # encode a raw field/path by splitting the same typed action repeatedly.
        if tuple(sorted(entries, key=lambda entry: (entry.entity_type, entry.action.value, entry.reason.value))) != entries:
            _fail()
        if len({(entry.entity_type, entry.action, entry.reason) for entry in entries}) != len(entries):
            _fail()
        if not schema.accepts(transformed):
            _fail()
        if schema.kind is PayloadKind.TEXT:
            if type(transformed) is not str:
                _fail()
            try:
                encoded = transformed.encode("utf-8")
            except UnicodeError:
                _fail()
            media_type = "text/plain"
        else:
            if type(transformed) not in (dict, list):
                _fail()
            encoded = canonical_json(transformed)
            media_type = "application/json"
        if len(encoded) > MAX_CANDIDATE_BYTES:
            _fail()
        metadata = CandidateMetadata(run_id=run_id, input_digest=input_digest, policy_digest=policy_digest,
                                     artifact_digest=_hash(encoded), schema_digest=schema.digest,
                                     payload_kind=schema.kind, media_type=media_type, byte_count=len(encoded),
                                     ledger=entries)
        return cls(_metadata=metadata, _encoded=encoded)

    @property
    def metadata(self) -> CandidateMetadata:
        return self._metadata

    def materialize_for_private_worker(self) -> str | dict[str, Any] | list[Any]:
        """Return a detached payload for trusted internal worker stages only."""
        try:
            if self._metadata.payload_kind is PayloadKind.TEXT:
                return self._encoded.decode("utf-8")
            return json.loads(self._encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            # A frozen artifact produced by this module cannot reach this branch;
            # retain a safe failure for corrupt persistence adapters.
            _fail()
