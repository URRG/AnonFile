"""Immutable commitments to the exact bytes of a release payload.

This module deliberately contains only deterministic validation and hashing.
It neither reads nor stores a payload.  Callers must obtain the business
authorization for a binding before asking the durable ledger to record it.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_PUBLICATION = re.compile(r"publicationref:v1:" + _OPAQUE + r"\Z")
_OBJECT = re.compile(r"objectref:v1:" + _OPAQUE + r"\Z")
_KEY = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SERIALIZATIONS = frozenset({"binary-v1", "jsonl-utf8-v1"})
_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
_BINDING_DOMAIN = b"anonflow-publication-payload-binding:v1\0"
_PAYLOAD_DOMAIN = b"anonflow-release-payload:v1\0"


class PublicationPayloadBindingError(ValueError):
    """Fixed local validation failure; callers must fail closed."""


def _fail() -> None:
    raise PublicationPayloadBindingError("invalid publication payload binding")


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _size(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= _MAX_PAYLOAD_BYTES:
        _fail()
    return value


def payload_digest(payload: bytes) -> str:
    """Commit to exact release bytes, including an empty payload's size.

    The bounded input and explicit uint64 size make this a commitment to the
    serialization input, not to any decoded representation of it.
    """
    if type(payload) is not bytes or len(payload) > _MAX_PAYLOAD_BYTES:
        _fail()
    digest = hashlib.sha256(_PAYLOAD_DOMAIN + len(payload).to_bytes(8, "big") + payload)
    return "sha256:" + digest.hexdigest()


def _canonical(fields: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(fields, ensure_ascii=True, allow_nan=False, sort_keys=True,
                             separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    return _BINDING_DOMAIN + encoded


@dataclass(frozen=True, slots=True)
class PublicationPayloadBinding:
    """An immutable, non-secret commitment for one publication's payload."""

    tenant_ref: str
    publication_ref: str
    object_ref: str
    key_ref: str
    plan_digest: str
    payload_digest: str
    payload_size_bytes: int
    serialization_id: str
    binding_digest: str

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.publication_ref, _PUBLICATION)
        _text(self.object_ref, _OBJECT)
        _text(self.key_ref, _KEY)
        _text(self.plan_digest, _DIGEST)
        _text(self.payload_digest, _DIGEST)
        _size(self.payload_size_bytes)
        if type(self.serialization_id) is not str or self.serialization_id not in _SERIALIZATIONS:
            _fail()
        _text(self.binding_digest, _DIGEST)
        if self.binding_digest != self.calculate_digest(
                tenant_ref=self.tenant_ref, publication_ref=self.publication_ref,
                object_ref=self.object_ref, key_ref=self.key_ref, plan_digest=self.plan_digest,
                payload_digest=self.payload_digest, payload_size_bytes=self.payload_size_bytes,
                serialization_id=self.serialization_id):
            _fail()

    @staticmethod
    def calculate_digest(*, tenant_ref: str, publication_ref: str, object_ref: str, key_ref: str,
                         plan_digest: str, payload_digest: str, payload_size_bytes: int,
                         serialization_id: str) -> str:
        """Return the canonical commitment for validated non-secret fields."""
        _text(tenant_ref, _TENANT)
        _text(publication_ref, _PUBLICATION)
        _text(object_ref, _OBJECT)
        _text(key_ref, _KEY)
        _text(plan_digest, _DIGEST)
        _text(payload_digest, _DIGEST)
        _size(payload_size_bytes)
        if type(serialization_id) is not str or serialization_id not in _SERIALIZATIONS:
            _fail()
        fields = {
            "key_ref": key_ref, "object_ref": object_ref, "payload_digest": payload_digest,
            "payload_size_bytes": payload_size_bytes, "plan_digest": plan_digest,
            "publication_ref": publication_ref, "serialization_id": serialization_id,
            "tenant_ref": tenant_ref,
        }
        return "sha256:" + hashlib.sha256(_canonical(fields)).hexdigest()

    @classmethod
    def create(cls, *, tenant_ref: str, publication_ref: str, object_ref: str, key_ref: str,
               plan_digest: str, payload_digest: str, payload_size_bytes: int,
               serialization_id: str) -> "PublicationPayloadBinding":
        """Construct a binding after the caller has independently authorized it."""
        return cls(tenant_ref, publication_ref, object_ref, key_ref, plan_digest, payload_digest,
                   payload_size_bytes, serialization_id, cls.calculate_digest(
                       tenant_ref=tenant_ref, publication_ref=publication_ref, object_ref=object_ref,
                       key_ref=key_ref, plan_digest=plan_digest, payload_digest=payload_digest,
                       payload_size_bytes=payload_size_bytes, serialization_id=serialization_id))
