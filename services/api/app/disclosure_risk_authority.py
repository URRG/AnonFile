"""Server-owned QID configuration and attestation for disclosure-risk workers."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import re
from typing import Iterable

from app.disclosure_risk import (DisclosureRiskError, DisclosureRiskReport,
                                 QuasiIdentifierCommitmentAuthority, QuasiIdentifierConfig)


_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_SIG = re.compile(r"risksig:v1:[A-Za-z0-9_-]{43}\Z")
_QID_REVISION = re.compile(r"qidrev:v1:[A-Za-z0-9_-]{43}\Z")
_MAX = 32_000


class DisclosureRiskAuthorityError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid disclosure-risk authority")


def _fail() -> None:
    raise DisclosureRiskAuthorityError()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _id(value: object) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _expiry(value: object) -> datetime:
    if type(value) is not str or not 20 <= len(value) <= 40 or not value.endswith("Z") or "+" in value[:-1]:
        _fail()
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
        if result.tzinfo is None or result.utcoffset() is None:
            _fail()
        return result.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()


@dataclass(frozen=True, slots=True)
class DisclosureRiskControlAuthority:
    tenant: str
    key_id: str
    expires_at: datetime
    _qid_config: QuasiIdentifierConfig = field(repr=False, compare=False)
    _secret: bytes = field(repr=False, compare=False)
    qid_config_revision: str = field(init=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        _id(self.tenant); _id(self.key_id)
        if (not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None
                or self.expires_at.utcoffset() is None or not isinstance(self._qid_config, QuasiIdentifierConfig)
                or type(self._secret) is not bytes or not 32 <= len(self._secret) <= 64):
            _fail()
        revision = "qidrev:v1:" + base64.urlsafe_b64encode(hmac.new(
            self._secret, _canonical({"schema": "disclosure-risk-qid-config-v1", "fields": self._qid_config._fields}),
            hashlib.sha256).digest()).decode("ascii").rstrip("=")
        if not _QID_REVISION.fullmatch(revision): _fail()
        object.__setattr__(self, "qid_config_revision", revision)
        # Fields remain private: public identity uses a keyed opaque revision,
        # never a dictionary-checkable field-name commitment.
        public = {"schema": "disclosure-risk-authority-v1", "tenant": self.tenant,
                  "key_id": self.key_id, "expires_at": self.expires_at.astimezone(UTC).isoformat(),
                  "qid_config_revision": self.qid_config_revision}
        object.__setattr__(self, "authority_id", "sha256:" + hashlib.sha256(_canonical(public)).hexdigest())

    @property
    def quasi_identifiers(self) -> QuasiIdentifierConfig:
        return self._qid_config

    @property
    def commitment_verifier(self) -> QuasiIdentifierCommitmentAuthority:
        """Trusted-worker-only verifier; neither secret nor fields are serialized."""
        return QuasiIdentifierCommitmentAuthority.from_secret(self._secret)

    def is_active(self, *, at: datetime | None = None) -> bool:
        moment = datetime.now(UTC) if at is None else at
        return (isinstance(moment, datetime) and moment.tzinfo is not None and moment.utcoffset() is not None
                and self.expires_at > moment.astimezone(UTC))

    def _message(self, *, tenant: str, run_id: str, processing_request_digest: str,
                 candidate_artifact_digest: str, policy_digest: str, rights_digest: str,
                 method_id: str, method_version: str, method_config_digest: str,
                 taxonomy_mapping_digest: str, idempotency_key: str,
                 qid_config_revision: str,
                 report: DisclosureRiskReport) -> bytes:
        if not isinstance(report, DisclosureRiskReport) or tenant != self.tenant:
            _fail()
        for value in (run_id, method_id, method_version): _id(value)
        for value in (processing_request_digest, candidate_artifact_digest, policy_digest, rights_digest,
                      method_config_digest, taxonomy_mapping_digest): _digest(value)
        if (type(idempotency_key) is not str or not 1 <= len(idempotency_key) <= 200 or not idempotency_key.isascii()
                or any(character.isspace() for character in idempotency_key)
                or qid_config_revision != self.qid_config_revision
                or report.candidate_artifact_digest != candidate_artifact_digest):
            _fail()
        return _canonical({"schema": "disclosure-risk-attestation-v1", "authority_id": self.authority_id,
                           "tenant": tenant, "run_id": run_id, "processing_request_digest": processing_request_digest,
                           "candidate_artifact_digest": candidate_artifact_digest, "policy_digest": policy_digest,
                           "rights_digest": rights_digest, "method_id": method_id, "method_version": method_version,
                           "method_config_digest": method_config_digest,
                           "taxonomy_mapping_digest": taxonomy_mapping_digest, "idempotency_key": idempotency_key,
                           "qid_config_revision": qid_config_revision,
                           "report": report.to_record()})

    def sign_for_worker(self, **binding) -> str:
        return "risksig:v1:" + base64.urlsafe_b64encode(hmac.new(
            self._secret, self._message(**binding), hashlib.sha256).digest()).decode("ascii").rstrip("=")

    def verify(self, *, signature: object, **binding) -> bool:
        if type(signature) is not str or not _SIG.fullmatch(signature): return False
        try:
            supplied = base64.urlsafe_b64decode(signature.split(":", 2)[2] + "=")
            return hmac.compare_digest(supplied, hmac.new(self._secret, self._message(**binding), hashlib.sha256).digest())
        except (ValueError, UnicodeError, DisclosureRiskAuthorityError):
            return False


def load_disclosure_risk_authorities() -> tuple[DisclosureRiskControlAuthority, ...]:
    raw = os.getenv("ANONFLOW_DISCLOSURE_RISK_AUTHORITIES", "")
    if not raw: return ()
    if len(raw.encode("utf-8")) > _MAX: _fail()
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError
                result[key] = value
            return result
        entries = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries) > 64: _fail()
        result = []; tenants = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"tenant", "key_id", "expires_at", "key", "quasi_identifier_fields"}:
                _fail()
            if type(entry["key"]) is not str: _fail()
            secret = base64.b64decode(entry["key"], validate=True)
            qid = QuasiIdentifierCommitmentAuthority.from_secret(secret).create_config(entry["quasi_identifier_fields"])
            item = DisclosureRiskControlAuthority(entry["tenant"], entry["key_id"], _expiry(entry["expires_at"]), qid, secret)
            if item.tenant in tenants: _fail()
            tenants.add(item.tenant); result.append(item)
        return tuple(result)
    except (TypeError, ValueError, UnicodeError, binascii.Error, DisclosureRiskError, DisclosureRiskAuthorityError):
        _fail()


def authority_for_tenant(authorities: Iterable[DisclosureRiskControlAuthority], *, tenant: str) -> DisclosureRiskControlAuthority:
    matches = [item for item in authorities if item.tenant == tenant]
    if len(matches) != 1 or not matches[0].is_active(): _fail()
    return matches[0]
