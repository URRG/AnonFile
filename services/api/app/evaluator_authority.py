"""Fail-closed evaluator attestation for aggregate benchmark evidence.

An M8 score is internally self-consistent but is not trustworthy merely because
it hashes correctly.  This module admits it only when a separately configured
evaluator service principal signs it and its evaluator/corpus identity matches
an allowlisted authority.  Secrets never enter evidence records or responses.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
from typing import Iterable

from app.evaluation_harness import ScoredEvaluation


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_SIGNATURE = re.compile(r"evalsig:v1:[A-Za-z0-9_-]{43}\Z")
_MAX_CONFIG_BYTES = 32_000


class EvaluatorAuthorityError(ValueError):
    """Fixed rejection that never exposes authority configuration or secrets."""

    def __init__(self) -> None:
        super().__init__("Invalid evaluator authority")


def _fail() -> None:
    raise EvaluatorAuthorityError()


def _identity(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


@dataclass(frozen=True, slots=True)
class EvaluatorAuthority:
    """One tenant-bound evaluator service and its approved benchmark corpus."""

    subject: str
    tenant: str
    evaluator_id: str
    evaluator_version: str
    evaluator_config_digest: str
    corpus_digests: frozenset[str] = field(repr=False)
    _key: bytes = field(repr=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        for value in (self.subject, self.tenant, self.evaluator_id, self.evaluator_version):
            _identity(value)
        _digest(self.evaluator_config_digest)
        if (type(self.corpus_digests) is not frozenset or not self.corpus_digests
                or len(self.corpus_digests) > 64 or any(_digest(value) != value for value in self.corpus_digests)
                or type(self._key) is not bytes or not 32 <= len(self._key) <= 64):
            _fail()
        public = {"schema": "evaluator-authority-v1", "subject": self.subject, "tenant": self.tenant,
                  "evaluator_id": self.evaluator_id, "evaluator_version": self.evaluator_version,
                  "evaluator_config_digest": self.evaluator_config_digest,
                  "corpus_digests": sorted(self.corpus_digests)}
        object.__setattr__(self, "authority_id", "sha256:" + hashlib.sha256(_canonical(public)).hexdigest())

    def _message(self, *, run_id: str, processing_request_digest: str, report: ScoredEvaluation) -> bytes:
        _identity(run_id)
        _digest(processing_request_digest)
        return _canonical({"schema": "evaluator-attestation-v1", "authority_id": self.authority_id,
                           "run_id": run_id, "processing_request_digest": processing_request_digest,
                           "report_digest": report.digest})

    def accepts(self, *, subject: str, tenant: str, report: ScoredEvaluation) -> bool:
        return (subject == self.subject and tenant == self.tenant
                and report.binding.evaluator_id == self.evaluator_id
                and report.binding.evaluator_version == self.evaluator_version
                and report.binding.evaluator_config_digest == self.evaluator_config_digest
                and report.binding.corpus_digest in self.corpus_digests)

    def verify(self, *, subject: str, tenant: str, run_id: str, processing_request_digest: str,
               report: ScoredEvaluation, signature: object) -> bool:
        if not self.accepts(subject=subject, tenant=tenant, report=report):
            return False
        if type(signature) is not str or not _SIGNATURE.fullmatch(signature):
            return False
        encoded = signature.split(":", 2)[2]
        try:
            supplied = base64.urlsafe_b64decode(encoded + "=")
        except (ValueError, UnicodeError):
            return False
        expected = hmac.new(self._key, self._message(run_id=run_id,
                                                       processing_request_digest=processing_request_digest,
                                                       report=report), hashlib.sha256).digest()
        return hmac.compare_digest(supplied, expected)

    def sign_for_test_or_worker(self, *, run_id: str, processing_request_digest: str,
                                report: ScoredEvaluation) -> str:
        """Sign inside an evaluator worker boundary; never call from API clients."""
        signature = hmac.new(self._key, self._message(run_id=run_id,
                                                       processing_request_digest=processing_request_digest,
                                                       report=report), hashlib.sha256).digest()
        return "evalsig:v1:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def load_evaluator_authorities() -> tuple[EvaluatorAuthority, ...]:
    """Load explicit local evaluator authorities; no configuration means no admission."""
    raw = os.getenv("ANONFLOW_EVALUATOR_AUTHORITIES", "")
    if not raw:
        return ()
    if len(raw.encode("utf-8")) > _MAX_CONFIG_BYTES:
        _fail()
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def no_constant(value):
            raise ValueError

        entries = json.loads(raw, object_pairs_hook=unique_object, parse_constant=no_constant)
        if type(entries) is not list or not entries or len(entries) > 64:
            _fail()
        result = []
        identities = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"subject", "tenant", "evaluator_id", "evaluator_version",
                                                              "evaluator_config_digest", "corpus_digests", "key"}:
                _fail()
            encoded_key = entry["key"]
            if type(encoded_key) is not str:
                _fail()
            key = base64.b64decode(encoded_key, validate=True)
            authority = EvaluatorAuthority(entry["subject"], entry["tenant"], entry["evaluator_id"],
                                           entry["evaluator_version"], entry["evaluator_config_digest"],
                                           frozenset(entry["corpus_digests"]), key)
            identity = (authority.subject, authority.tenant)
            if identity in identities:
                _fail()
            identities.add(identity)
            result.append(authority)
        return tuple(result)
    except (TypeError, ValueError, UnicodeError, binascii.Error, EvaluatorAuthorityError):
        _fail()


def matching_authority(authorities: Iterable[EvaluatorAuthority], *, subject: str, tenant: str,
                       run_id: str, processing_request_digest: str, report: ScoredEvaluation,
                       signature: object) -> EvaluatorAuthority:
    """Return the unique configured authority that verifies the complete report."""
    matches = [authority for authority in authorities if authority.verify(
        subject=subject, tenant=tenant, run_id=run_id,
        processing_request_digest=processing_request_digest, report=report, signature=signature)]
    if len(matches) != 1:
        _fail()
    return matches[0]
