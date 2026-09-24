"""Fail-closed contracts for a future production persistence substrate.

This module deliberately contains no database, object-store, queue, network
client, credentials, or route registration.  It defines the *metadata-only*
boundary that a future adapter must satisfy before it can be considered for
production integration.  In particular, control-plane records describe an
encrypted object by opaque reference, key reference, digest, and size; they do
not carry source, candidate, ciphertext, or plaintext bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import re
import json
from types import MappingProxyType
from typing import Mapping


MAX_METADATA_BYTES = 65_536
MAX_LEASE_SECONDS = 3_600
_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OBJECT = re.compile(r"objectref:v1:" + _OPAQUE + r"\Z")
_KEY = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_TX = re.compile(r"metatx:v1:" + _OPAQUE + r"\Z")
_RECORD = re.compile(r"metarecord:v1:" + _OPAQUE + r"\Z")
_WORK = re.compile(r"workref:v1:" + _OPAQUE + r"\Z")
_CLAIM = re.compile(r"workerclaim:v1:" + _OPAQUE + r"\Z")
_WORKER = re.compile(r"workerref:v1:" + _OPAQUE + r"\Z")
_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_REQUIRED_CAPABILITIES = frozenset({
    "atomic_tenant_metadata_transactions", "durable_metadata_commit",
    "tenant_isolation", "encrypted_object_references", "no_control_plane_bytes",
    "leased_at_least_once_claims", "compare_and_swap_claims", "expired_lease_reclaim",
})
_DIGEST_FIELDS = frozenset({
    "audit_checkpoint_digest", "ciphertext_digest", "metadata_digest",
    "policy_digest", "request_digest", "rights_digest",
})


class ProductionSubstrateContractError(ValueError):
    """Fixed failure for an invalid contract value or adapter declaration."""

    def __init__(self) -> None:
        super().__init__("Invalid production substrate contract")


def _fail() -> None:
    raise ProductionSubstrateContractError()


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _positive(value: object, *, maximum: int | None = None) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 1 or (maximum is not None and value > maximum):
        _fail()
    return value


def _instant(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None or value.microsecond:
        _fail()
    return value.astimezone(UTC)


def _opaque_reference(value: object) -> str:
    if type(value) is not str or not any(expression.fullmatch(value) for expression in
                                         (_OBJECT, _KEY, _RECORD, _WORK, _CLAIM, _WORKER)):
        _fail()
    return value


def _frozen_attributes(value: object) -> Mapping[str, object]:
    """Freeze a deliberately small metadata vocabulary.

    Arbitrary strings (even under innocent-looking keys) can be raw source or
    candidate data.  Therefore this contract admits only strongly shaped
    digests/references, a fixed state token, and named positive counters.
    """
    if type(value) is not dict or len(value) > 128:
        _fail()
    result: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            _fail()
        if key in _DIGEST_FIELDS:
            result[key] = _text(item, _DIGEST)
        elif key.endswith("_ref"):
            result[key] = _opaque_reference(item)
        elif key in {"attempt", "lease_epoch", "sequence"}:
            result[key] = _positive(item)
        elif key == "state" and item in {"PENDING", "RUNNING", "SUCCEEDED", "FAILED", "QUARANTINED"}:
            result[key] = item
        else:
            _fail()
    return MappingProxyType(result)


def _canonical_size(value: object) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                              separators=(",", ":")).encode("ascii"))
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


@dataclass(frozen=True, slots=True)
class EncryptedObjectReference:
    """Opaque reference to encrypted data held outside the control plane."""

    tenant_ref: str
    object_ref: str
    key_ref: str
    ciphertext_digest: str
    ciphertext_size_bytes: int
    encryption_algorithm: str = "AES-256-GCM"

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.object_ref, _OBJECT)
        _text(self.key_ref, _KEY)
        _text(self.ciphertext_digest, _DIGEST)
        if (type(self.ciphertext_size_bytes) is not int or isinstance(self.ciphertext_size_bytes, bool)
                or not 0 <= self.ciphertext_size_bytes <= 2 ** 63 - 1
                or self.encryption_algorithm != "AES-256-GCM"):
            _fail()


@dataclass(frozen=True, slots=True)
class ControlPlaneMetadata:
    """One tenant-scoped metadata record, optionally bound to an object reference."""

    tenant_ref: str
    record_id: str
    kind: str
    version: int
    attributes: Mapping[str, object]
    encrypted_object: EncryptedObjectReference | None = None

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.record_id, _RECORD)
        _text(self.kind, _KIND)
        _positive(self.version)
        frozen_attributes = _frozen_attributes(self.attributes)
        object.__setattr__(self, "attributes", frozen_attributes)
        if self.encrypted_object is not None:
            if type(self.encrypted_object) is not EncryptedObjectReference or self.encrypted_object.tenant_ref != self.tenant_ref:
                _fail()
        # Bound canonical built-in JSON, not ``repr`` of caller-controlled
        # objects.  This check is performed after copying/freezing attributes.
        reference = None if self.encrypted_object is None else {
            "ciphertext_digest": self.encrypted_object.ciphertext_digest,
            "ciphertext_size_bytes": self.encrypted_object.ciphertext_size_bytes,
            "encryption_algorithm": self.encrypted_object.encryption_algorithm,
            "key_ref": self.encrypted_object.key_ref, "object_ref": self.encrypted_object.object_ref,
        }
        if _canonical_size({"tenant_ref": self.tenant_ref, "record_id": self.record_id,
                            "kind": self.kind, "version": self.version,
                            "attributes": dict(frozen_attributes), "encrypted_object": reference}) > MAX_METADATA_BYTES:
            _fail()


@dataclass(frozen=True, slots=True)
class TenantMetadataTransaction:
    """An adapter must commit all writes atomically within this one tenant."""

    tenant_ref: str
    transaction_id: str
    expected_versions: Mapping[str, int]
    writes: tuple[ControlPlaneMetadata, ...]

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.transaction_id, _TX)
        if type(self.expected_versions) is not dict or not self.writes or len(self.writes) > 128:
            _fail()
        versions: dict[str, int] = {}
        for record_id, version in self.expected_versions.items():
            _text(record_id, _RECORD)
            if type(version) is not int or isinstance(version, bool) or version < 0:
                _fail()
            versions[record_id] = version
        object.__setattr__(self, "expected_versions", MappingProxyType(versions))
        ids = set()
        for write in self.writes:
            if type(write) is not ControlPlaneMetadata or write.tenant_ref != self.tenant_ref or write.record_id in ids:
                _fail()
            ids.add(write.record_id)


@dataclass(frozen=True, slots=True)
class LeasedWorkerClaim:
    """A fenced at-least-once claim; expired claims must be reclaimable."""

    tenant_ref: str
    work_ref: str
    claim_id: str
    worker_ref: str
    delivery_attempt: int
    lease_epoch: int
    leased_at: datetime
    lease_expires_at: datetime
    reclaimed_from_claim_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.work_ref, _WORK)
        _text(self.claim_id, _CLAIM)
        _text(self.worker_ref, _WORKER)
        _positive(self.delivery_attempt)
        _positive(self.lease_epoch)
        start, end = _instant(self.leased_at), _instant(self.lease_expires_at)
        if not start < end or (end - start).total_seconds() > MAX_LEASE_SECONDS:
            _fail()
        object.__setattr__(self, "leased_at", start)
        object.__setattr__(self, "lease_expires_at", end)
        if self.reclaimed_from_claim_id is not None:
            _text(self.reclaimed_from_claim_id, _CLAIM)
            if self.reclaimed_from_claim_id == self.claim_id or self.delivery_attempt < 2:
                _fail()


def validate_adapter_declaration(value: object) -> dict[str, object]:
    """Validate a capability declaration; any omission or extra claim rejects it.

    This verifies a declaration only.  It does not bless an adapter for live
    traffic, establish durability, or test an infrastructure provider.
    """
    expected = {"schema", "adapter_id", "capabilities"}
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != "anonflow-production-substrate-v1":
        _fail()
    adapter_id = value.get("adapter_id")
    if type(adapter_id) is not str or not re.fullmatch(r"[a-z][a-z0-9._-]{2,95}", adapter_id):
        _fail()
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != _REQUIRED_CAPABILITIES:
        _fail()
    if any(type(enabled) is not bool or enabled is not True for enabled in capabilities.values()):
        _fail()
    return {"schema": value["schema"], "adapter_id": adapter_id, "capabilities": dict(capabilities)}
