"""Small, fail-closed domain model for durable processing runs.

This module deliberately has no persistence, queue, or processing dependency.
It gives an adapter a deterministic request identity and immutable snapshots to
persist.  A run records *metadata only*: it never accepts or retains source
data, transformed data, exception messages, or an output location.

The model is a lifecycle primitive, not a scheduler and not evidence that an
output is safe to deliver.  In particular, ``CANDIDATE`` means only that a
bounded worker attempt produced an artifact digest; it grants no release
approval.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Any, Callable, Mapping


MAX_ATTEMPTS = 3
MAX_EVENTS = 16
MAX_REQUEST_BYTES = 16_384
MAX_ARTIFACT_BYTES = 2_000_000
MAX_VALUE_BYTES = 4_096
MAX_DEPTH = 12
MAX_NODES = 1_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MEDIA_TYPES = frozenset({"text/plain", "application/json", "application/jsonl", "text/csv"})


class RunError(ValueError):
    """A fixed-message, safe processing-run domain error."""


class IdempotencyConflict(RunError):
    """The caller reused a key for a different immutable request."""


class RunState(StrEnum):
    REGISTERED = "REGISTERED"
    RUNNING = "RUNNING"
    CANDIDATE = "CANDIDATE"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"


def _fail(message: str) -> None:
    raise RunError(message)


def _identifier(value: object, *, idempotency: bool = False) -> str:
    pattern = _IDEMPOTENCY_KEY if idempotency else _IDENTIFIER
    if type(value) is not str or not pattern.fullmatch(value):
        _fail("Invalid processing run request.")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail("Invalid processing run request.")
    return value


def _safe_code(value: object) -> str:
    # Codes are deliberately small, enumerable-looking values.  Free-form
    # exception text can contain source values and must never reach run events.
    if type(value) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value):
        _fail("Invalid processing run request.")
    return value


def _validate_json(value: Any) -> None:
    """Bound a JSON-compatible graph before canonical serialization."""
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
            _fail("Invalid processing run request.")
        kind = type(current)
        if kind in (dict, list):
            if id(current) in active or len(current) > MAX_NODES:
                _fail("Invalid processing run request.")
            active.add(id(current))
            stack.append((current, depth, True))
            if kind is dict:
                for key, child in current.items():
                    if type(key) is not str:
                        _fail("Invalid processing run request.")
                    _validate_string(key)
                    stack.append((child, depth + 1, False))
            else:
                stack.extend((child, depth + 1, False) for child in current)
        elif kind is str:
            _validate_string(current)
        elif kind is float and not math.isfinite(current):
            _fail("Invalid processing run request.")
        elif kind not in (int, float, bool) and current is not None:
            _fail("Invalid processing run request.")


def _validate_string(value: str) -> None:
    try:
        if not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            _fail("Invalid processing run request.")
    except UnicodeError:
        _fail("Invalid processing run request.")


def canonical_json(value: Any) -> bytes:
    """Return the one permitted canonical JSON encoding for request digests."""
    _validate_json(value)
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail("Invalid processing run request.")
    if len(encoded) > MAX_REQUEST_BYTES:
        _fail("Invalid processing run request.")
    return encoded


def sha256_digest(value: bytes) -> str:
    """Use a labeled digest so it cannot be mistaken for a source identifier."""
    if type(value) is not bytes:
        _fail("Invalid processing run request.")
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class ProcessingPlan:
    """An immutable, fully versioned request for one processing attempt series."""

    dataset_id: str
    source_digest: str
    policy_id: str
    policy_version: str
    method_id: str
    mode: str
    options: bytes = field(repr=False, compare=True)

    @classmethod
    def create(cls, *, dataset_id: str, source_digest: str, policy_id: str,
               policy_version: str, method_id: str, mode: str,
               options: Mapping[str, Any] | None = None) -> "ProcessingPlan":
        if options is None:
            options = {}
        if type(options) is not dict:
            _fail("Invalid processing run request.")
        return cls(dataset_id=_identifier(dataset_id), source_digest=_digest(source_digest),
                   policy_id=_identifier(policy_id), policy_version=_identifier(policy_version),
                   method_id=_identifier(method_id), mode=_identifier(mode),
                   options=canonical_json(options))

    def __post_init__(self) -> None:
        # Dataclass construction is public; preserve the same invariants when an
        # adapter deserializes a plan instead of using ``create``.
        _identifier(self.dataset_id)
        _digest(self.source_digest)
        for value in (self.policy_id, self.policy_version, self.method_id, self.mode):
            _identifier(value)
        if type(self.options) is not bytes:
            _fail("Invalid processing run request.")
        try:
            parsed = json.loads(self.options.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("Invalid processing run request.")
        if type(parsed) is not dict:
            _fail("Invalid processing run request.")
        if canonical_json(parsed) != self.options:
            _fail("Invalid processing run request.")

    @property
    def request_digest(self) -> str:
        return sha256_digest(canonical_json({
            "dataset_id": self.dataset_id,
            "source_digest": self.source_digest,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "method_id": self.method_id,
            "mode": self.mode,
            "options": json.loads(self.options),
        }))


@dataclass(frozen=True, slots=True)
class OutputArtifact:
    """Digest-only output identity.  It intentionally has no payload or URI."""

    digest: str
    byte_count: int
    media_type: str

    def __post_init__(self) -> None:
        _digest(self.digest)
        if type(self.byte_count) is not int or not 0 <= self.byte_count <= MAX_ARTIFACT_BYTES:
            _fail("Invalid processing run request.")
        if self.media_type not in _MEDIA_TYPES:
            _fail("Invalid processing run request.")


def artifact_metadata(output: str | bytes | Any, *, media_type: str) -> OutputArtifact:
    """Compute digest metadata without retaining or returning ``output`` itself."""
    if media_type not in _MEDIA_TYPES:
        _fail("Invalid processing run request.")
    try:
        if media_type == "text/plain":
            if type(output) is str:
                raw = output.encode("utf-8")
            elif type(output) is bytes:
                raw = output
            else:
                _fail("Invalid processing run request.")
        else:
            # JSON/JSONL/CSV payload materialization is deliberately outside this
            # metadata layer.  Canonical JSON is the only safe generic format.
            if media_type not in {"application/json", "application/jsonl"}:
                _fail("Invalid processing run request.")
            raw = canonical_json(output)
    except UnicodeError:
        _fail("Invalid processing run request.")
    if len(raw) > MAX_ARTIFACT_BYTES:
        _fail("Invalid processing run request.")
    return OutputArtifact(digest=sha256_digest(raw), byte_count=len(raw), media_type=media_type)


@dataclass(frozen=True, slots=True)
class RunEvent:
    sequence: int
    state: RunState
    action: str
    occurred_at: datetime
    attempt: int
    error_code: str | None = None
    artifact: OutputArtifact | None = None


@dataclass(frozen=True, slots=True)
class ProcessingRun:
    """An immutable run snapshot suitable for append/replace persistence."""

    id: str
    tenant: str
    idempotency_key: str = field(repr=False)
    plan: ProcessingPlan
    state: RunState
    attempts: int
    events: tuple[RunEvent, ...]
    artifact: OutputArtifact | None = None

    @property
    def request_digest(self) -> str:
        return self.plan.request_digest


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _time(value: datetime | None, clock: Callable[[], datetime]) -> datetime:
    item = clock() if value is None else value
    if not isinstance(item, datetime) or item.tzinfo is None:
        _fail("Invalid processing run request.")
    return item.astimezone(UTC)


def _event(run: ProcessingRun, *, state: RunState, action: str, occurred_at: datetime,
           attempt: int, error_code: str | None = None,
           artifact: OutputArtifact | None = None) -> ProcessingRun:
    if len(run.events) >= MAX_EVENTS:
        _fail("Processing run event capacity exceeded.")
    if error_code is not None:
        _safe_code(error_code)
    event = RunEvent(sequence=len(run.events) + 1, state=state, action=action,
                     occurred_at=occurred_at, attempt=attempt, error_code=error_code,
                     artifact=artifact)
    return replace(run, state=state, attempts=attempt,
                   events=(*run.events, event), artifact=artifact or run.artifact)


class RunRegistry:
    """Thread-safe reference registry; a durable adapter must preserve its rules."""

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now):
        self._clock = clock
        self._lock = RLock()
        self._runs: dict[tuple[str, str], ProcessingRun] = {}
        self._keys: dict[tuple[str, str], str] = {}

    def register(self, *, run_id: str, tenant: str, idempotency_key: str,
                 plan: ProcessingPlan, occurred_at: datetime | None = None) -> tuple[ProcessingRun, bool]:
        """Register once per tenant/key; return ``(snapshot, reused)``.

        Reusing the key with the same immutable request is safe and returns the
        original run.  Reusing it for a different request fails closed, including
        when a caller selects a different proposed run id.
        """
        run_id, tenant = _identifier(run_id), _identifier(tenant)
        idempotency_key = _identifier(idempotency_key, idempotency=True)
        if not isinstance(plan, ProcessingPlan):
            _fail("Invalid processing run request.")
        timestamp = _time(occurred_at, self._clock)
        key = (tenant, idempotency_key)
        with self._lock:
            prior_id = self._keys.get(key)
            if prior_id is not None:
                prior = self._runs[(tenant, prior_id)]
                if prior.request_digest != plan.request_digest:
                    raise IdempotencyConflict("Idempotency key conflicts with a different request.")
                return prior, True
            if (tenant, run_id) in self._runs:
                _fail("Processing run already exists.")
            skeleton = ProcessingRun(id=run_id, tenant=tenant, idempotency_key=idempotency_key,
                                     plan=plan, state=RunState.REGISTERED, attempts=0, events=())
            result = _event(skeleton, state=RunState.REGISTERED, action="REGISTERED",
                            occurred_at=timestamp, attempt=0)
            self._runs[(tenant, run_id)] = result
            self._keys[key] = run_id
            return result, False

    def get(self, *, tenant: str, run_id: str) -> ProcessingRun:
        tenant, run_id = _identifier(tenant), _identifier(run_id)
        with self._lock:
            try:
                return self._runs[(tenant, run_id)]
            except KeyError:
                _fail("Processing run not found.")

    def start(self, *, tenant: str, run_id: str, occurred_at: datetime | None = None) -> ProcessingRun:
        return self._transition(tenant=tenant, run_id=run_id, target=RunState.RUNNING,
                                action="STARTED", occurred_at=occurred_at)

    def candidate(self, *, tenant: str, run_id: str, artifact: OutputArtifact,
                  occurred_at: datetime | None = None) -> ProcessingRun:
        if not isinstance(artifact, OutputArtifact):
            _fail("Invalid processing run request.")
        return self._transition(tenant=tenant, run_id=run_id, target=RunState.CANDIDATE,
                                action="CANDIDATE_CREATED", occurred_at=occurred_at, artifact=artifact)

    def quarantine(self, *, tenant: str, run_id: str, code: str,
                   occurred_at: datetime | None = None) -> ProcessingRun:
        return self._transition(tenant=tenant, run_id=run_id, target=RunState.QUARANTINED,
                                action="QUARANTINED", occurred_at=occurred_at, error_code=_safe_code(code))

    def fail(self, *, tenant: str, run_id: str, code: str,
             occurred_at: datetime | None = None) -> ProcessingRun:
        return self._transition(tenant=tenant, run_id=run_id, target=RunState.FAILED,
                                action="FAILED", occurred_at=occurred_at, error_code=_safe_code(code))

    def _transition(self, *, tenant: str, run_id: str, target: RunState, action: str,
                    occurred_at: datetime | None, error_code: str | None = None,
                    artifact: OutputArtifact | None = None) -> ProcessingRun:
        tenant, run_id = _identifier(tenant), _identifier(run_id)
        timestamp = _time(occurred_at, self._clock)
        with self._lock:
            run = self.get(tenant=tenant, run_id=run_id)
            legal = {
                (RunState.REGISTERED, RunState.RUNNING),
                (RunState.REGISTERED, RunState.FAILED),
                (RunState.RUNNING, RunState.CANDIDATE),
                (RunState.RUNNING, RunState.QUARANTINED),
                (RunState.RUNNING, RunState.FAILED),
                (RunState.FAILED, RunState.RUNNING),
                (RunState.CANDIDATE, RunState.QUARANTINED),
            }
            if (run.state, target) not in legal:
                _fail("Illegal processing run transition.")
            attempt = run.attempts + 1 if target is RunState.RUNNING else run.attempts
            if attempt > MAX_ATTEMPTS:
                _fail("Processing run attempt capacity exceeded.")
            result = _event(run, state=target, action=action, occurred_at=timestamp,
                            attempt=attempt, error_code=error_code, artifact=artifact)
            self._runs[(tenant, run_id)] = result
            return result
