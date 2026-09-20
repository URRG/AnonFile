"""Fail-closed development API. Synthetic data only; no release qualification."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import os
from secrets import token_urlsafe
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Literal
from uuid import uuid4
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from app.contracts import PayloadError
from app.processing import (RULES_METHOD_CONFIG_DIGEST, RULES_METHOD_ID, RULES_METHOD_VERSION,
                            detect_text, process_payload)
from app.ingestion import IngestionError, parse_source
from app.storage_config import create_store
from app.security import Principal, configure_auth, require_roles
from app.policies import PolicyError, PolicyProfile, PolicyRule, PolicySnapshot
from app.rights import RightsError, RightsProfile, evaluate_rights
from app.runs import ProcessingPlan, RunError, RunRegistry
from app.candidate import (CandidateArtifact, CandidateError, LedgerAction, LedgerReason,
                           PayloadKind, SchemaContract, TransformLedgerEntry)
from app.rules_policy_execution import (ActualOutputOperation as PolicyOutputOperation,
                                        RULES_LABEL_TO_CATEGORY, RulesPolicyExecutionError,
                                        RULES_TAXONOMY_MAPPING_DIGEST, execute_rules_policy)
from app.residual_eval import (CandidateMetadata as ResidualCandidateMetadata, DetectorIdentity,
                               DetectorResult, EvaluationError, EvaluationProfile,
                               EvidenceStatus, candidate_schema_digest, evaluate_candidate)
from app.independent_residual import DETECTOR_CONFIG_DIGEST, DETECTOR_ID, scan_residual_candidate
from app.qualification import (CandidateBinding, CategoryMeasurement, CategoryThreshold,
                               EvaluationReport as QualificationReport, QualificationCriteria,
                               QualificationError, qualify)
from app.evaluation_harness import EvaluationHarnessError, ScoredEvaluation
from app.evaluator_authority import (EvaluatorAuthorityError, load_evaluator_authorities,
                                     matching_authority)
from app.utility_evidence import DataUtilityReport, UtilityEvidenceError, assess_data_utility
from app.utility_evidence_authority import (UtilityEvidenceAuthorityError, authority_for_tenant,
                                            load_utility_evidence_authorities)
from app.disclosure_risk import DisclosureRiskError, DisclosureRiskReport, QuasiIdentifierCommitmentAuthority, assess_disclosure_risk
from app.disclosure_risk_authority import (DisclosureRiskAuthorityError,
                                           authority_for_tenant as disclosure_risk_authority_for_tenant,
                                           load_disclosure_risk_authorities)
from app.linkage_risk import METHODOLOGY_DIGEST as LINKAGE_METHODOLOGY_DIGEST
from app.linkage_risk import LinkageRiskError, LinkageRiskReport, assess_linkage_risk
from app.linkage_risk_authority import (LinkageRiskAuthorityError,
                                        authority_for_tenant as linkage_risk_authority_for_tenant,
                                        load_linkage_risk_authorities)
from app.release_case import ReleaseCase, ReleaseCaseError
from app.release_case_authority import (ReleaseCaseAuthorityError,
                                        authority_for_tenant as release_case_authority_for_tenant,
                                        load_release_case_authorities)
from app.privacy_decision import (PrivacyDecision, PrivacyDecisionError, control_for_tenant as privacy_decision_control_for_tenant,
                                  load_privacy_decision_controls)
from app.privacy_evidence_policy import (PrivacyEvidenceBinding, PrivacyEvidenceKind, assess_privacy_evidence)
from app.policies import TAXONOMY_CATEGORIES

MAX_BODY_BYTES = 2_100_000
MAX_PAYLOAD_BYTES = 2_000_000

class StrictJSONRequest(Request):
    """Parse once, rejecting ambiguous objects instead of silently losing values."""
    async def json(self):
        if not hasattr(self, "_json"):
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError
                    result[key] = value
                return result

            def reject_constant(value):
                raise ValueError

            def finite_float(value):
                parsed = float(value)
                if not math.isfinite(parsed):
                    raise ValueError
                return parsed

            try:
                self._json = json.loads((await self.body()).decode("utf-8"),
                                        object_pairs_hook=unique_object,
                                        parse_constant=reject_constant,
                                        parse_float=finite_float)
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                raise HTTPException(422, "Request validation failed") from None
        return self._json


class StrictJSONRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def strict_handler(request: Request):
            return await handler(StrictJSONRequest(request.scope, request.receive))

        return strict_handler

class BodyLimitMiddleware:
    """Bound Content-Length and chunked bodies before JSON parsing/buffering."""
    def __init__(self, app, max_bytes=MAX_BODY_BYTES):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
            if length < 0:
                raise ValueError
        except ValueError:
            return await JSONResponse({"detail": "Invalid request"}, status_code=400)(scope, receive, send)
        if length > self.max_bytes:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        await self.app(scope, bounded_receive, send)

class ReleaseMode(str, Enum):
    EXTERNAL_ANONYMIZED = "external_anonymized"
    RESTRICTED_PSEUDONYMIZED = "restricted_pseudonymized"

class Eligibility(str, Enum):
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class DatasetMetadata(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    owner: str = Field(default="unknown", max_length=160)
    jurisdiction: str = Field(default="unspecified", max_length=80)
    intended_use: str = Field(default="evaluation", max_length=160)
    recipient: str = Field(default="unspecified", max_length=160)
    retention_days: int = Field(default=1, ge=1, le=3650)

class IngestionCreate(DatasetMetadata):
    format: Literal["text", "json", "jsonl", "csv"]
    content: str = Field(min_length=1, max_length=MAX_PAYLOAD_BYTES)

class DatasetCreate(DatasetMetadata):
    content: str | None = Field(default=None, min_length=1, max_length=MAX_PAYLOAD_BYTES)
    records: list[dict[str, Any]] | None = Field(default=None, min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def payload_contract(self):
        if (self.content is None) == (self.records is None):
            raise ValueError("Exactly one payload required")
        nodes, stack = 0, [(self.content if self.content is not None else self.records, 0)]
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if depth > 32 or nodes > 100_000:
                raise ValueError("Unsupported payload structure")
            if isinstance(value, dict):
                # A value embedded in a key cannot be safely renamed without a
                # collision/provenance policy; reject before storing the source.
                if any(detect_text(key) for key in value):
                    raise ValueError("Sensitive object keys are unsupported")
                stack.extend((v, depth + 1) for v in value.values())
                nodes += len(value)
            elif isinstance(value, list):
                stack.extend((v, depth + 1) for v in value)
            elif isinstance(value, float) and not math.isfinite(value):
                raise ValueError("Unsupported numeric value")
        try:
            # Metadata and object keys also must be encodable; do not let them
            # raise source-bearing internal errors after validation succeeds.
            json.dumps(self.model_dump(), ensure_ascii=False, allow_nan=False).encode("utf-8")
            encoded = json.dumps(self.records, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") if self.records is not None else self.content.encode("utf-8")
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("Unsupported payload") from None
        if len(encoded) > MAX_PAYLOAD_BYTES or self.content is not None and not self.content.strip():
            raise ValueError("Unsupported payload")
        return self

class DatasetSummary(BaseModel):
    id: str
    name: str
    created_at: datetime
    record_count: int
    owner: str
    intended_use: str

class ReleaseCreate(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=80)
    release_mode: str = "external_anonymized"
    policy_version: str = Field(default="baseline-v1", max_length=80)
    allow_review: bool = True

    @model_validator(mode="after")
    def coherent_policy(self):
        profiles = {"baseline-v1": {m.value for m in ReleaseMode},
                    "external-release-v1": {"external_anonymized"},
                    "restricted-pseudonymized-v1": {"restricted_pseudonymized"}}
        if self.release_mode not in profiles.get(self.policy_version, set()):
            raise ValueError("Unsupported policy or release mode")
        return self

class ReviewDecision(StrictModel):
    decision: str = Field(pattern="^(approve|reject)$")
    # Accepted for legacy UI compatibility, never trusted or echoed.
    reviewer: str | None = Field(default=None, max_length=160)
    note: str = Field(default="", max_length=1000)

class PolicyRuleCreate(StrictModel):
    category: str = Field(min_length=1, max_length=80)
    action: str = Field(min_length=1, max_length=80)
    priority: int = Field(default=100, ge=0, le=10_000)

class PolicySnapshotCreate(StrictModel):
    policy_id: str = Field(min_length=1, max_length=80)
    version: str = Field(min_length=1, max_length=80)
    release_modes: list[str] = Field(min_length=1, max_length=2)
    formats: list[str] = Field(min_length=1, max_length=4)
    languages: list[str] = Field(min_length=1, max_length=8)
    rules: list[PolicyRuleCreate] = Field(min_length=1, max_length=64)

class RightsProfileCreate(StrictModel):
    profile_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    permitted_purposes: list[str] = Field(min_length=1, max_length=64)
    permitted_recipients: list[str] = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=20, max_length=40)
    resale_allowed: bool

class ProcessingRunCreate(StrictModel):
    dataset_id: str = Field(min_length=1, max_length=80)
    rights_profile_id: str = Field(min_length=1, max_length=80)
    policy_snapshot_id: str = Field(min_length=1, max_length=80)
    recipient: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=128)
    release_mode: str = Field(min_length=1, max_length=80)
    language: str = Field(default="en", min_length=2, max_length=8)
    method_id: str = Field(default="rules-v1", min_length=1, max_length=80)

class ReleaseCard(BaseModel):
    release_id: str
    dataset_id: str
    generated_at: datetime
    policy_version: str
    release_mode: str
    eligibility: Eligibility
    findings: list[dict[str, Any]]
    gates: list[str]
    limitations: list[str]
    evidence_status: str = "INSUFFICIENT_EVIDENCE"
    scores: None = None
    revision: int = 1

class ReleaseView(BaseModel):
    id: str
    dataset_id: str
    status: str = "evaluation_incomplete"
    eligibility: Eligibility
    output: None = None
    card: ReleaseCard
    review: dict[str, Any] | None = None

class PolicySnapshotView(BaseModel):
    id: str
    key: str
    digest: str
    formats: list[str]
    languages: list[str]
    release_modes: list[str]

class RightsProfileView(BaseModel):
    id: str
    profile_id: str
    version: str
    digest: str
    expires_at: str
    resale_allowed: bool
    permitted_purposes: list[str]
    permitted_recipients: list[str]

class ProcessingRunView(BaseModel):
    id: str
    dataset_id: str
    state: str
    attempts: int
    request_digest: str
    method_id: str
    method_version: str
    method_config_digest: str | None
    taxonomy_mapping_digest: str | None
    language: str
    policy_digest: str
    rights_digest: str
    recipient: str
    purpose: str
    events: list[dict[str, Any]]
    candidate: dict[str, Any] | None = None

class ResidualEvaluationView(BaseModel):
    id: str
    run_id: str
    candidate_digest: str
    report_digest: str
    evidence_status: str
    residual_counts: dict[str, int]
    coverage_percent: int
    assessed_categories: list[str]
    category_coverage_percent: int
    utility_checks: list[dict[str, Any]]

class DetectorEvaluationEvidenceCreate(StrictModel):
    """An aggregate M8 harness report from a trusted processor worker.

    The report contract itself rejects corpus cases, annotations, protected
    references, predictions, source values, and field paths.  It is method
    benchmark evidence, not a candidate residual report.
    """
    report: dict[str, Any]
    attestation_signature: str = Field(min_length=54, max_length=54)

class DetectorEvaluationEvidenceView(BaseModel):
    id: str
    run_id: str
    processing_request_digest: str
    report_digest: str
    posture: Literal["OBSERVATIONAL_ONLY"]
    limitations: list[str]
    report: dict[str, Any]

class UtilityEvidenceView(BaseModel):
    """Source-safe structural evidence from a trusted local worker only."""
    id: str
    run_id: str
    processing_request_digest: str
    candidate_artifact_digest: str
    report_digest: str
    posture: Literal["OBSERVATIONAL_ONLY"]
    limitations: list[str]
    report: dict[str, Any]

class DisclosureRiskEvidenceView(BaseModel):
    id: str
    run_id: str
    processing_request_digest: str
    candidate_artifact_digest: str
    report_digest: str
    posture: Literal["OBSERVATIONAL_ONLY"]
    limitations: list[str]
    report: dict[str, Any]

class LinkageRiskEvidenceView(BaseModel):
    """Aggregate-only linkage-risk evidence from a trusted local worker."""
    id: str
    run_id: str
    processing_request_digest: str
    candidate_artifact_digest: str
    report_digest: str
    posture: Literal["OBSERVATIONAL_ONLY"]
    limitations: list[str]
    report: dict[str, Any]

class ReleaseCaseView(BaseModel):
    """A signed scope record only; this endpoint cannot approve or deliver data."""
    id: str
    run_id: str
    candidate_artifact_digest: str
    case_digest: str
    authority_id: str
    issuer_key_id: str
    expires_at: datetime
    posture: Literal["NO_RELEASE_AUTHORIZATION"]
    limitations: list[str]

class PrivacyDecisionView(BaseModel):
    """Signed evidence holding/quarantine only; never a release authorization."""
    id: str
    case_id: str
    case_digest: str
    outcome: Literal["QUARANTINED", "INSUFFICIENT_EVIDENCE"]
    reasons: list[str]
    decision_digest: str
    evidence: list[dict[str, str]]
    expires_at: datetime
    posture: Literal["NO_RELEASE_AUTHORIZATION"]
    limitations: list[str]

class QualificationCreate(StrictModel):
    evaluation_id: str = Field(min_length=1, max_length=80)
    max_evaluation_age_seconds: int = Field(default=3600, ge=1, le=2_678_400)

class QualificationView(BaseModel):
    id: str
    run_id: str
    outcome: str
    reasons: list[str]
    digest: str

def now():
    return datetime.now(UTC)

def release_view(record):
    return ReleaseView(id=record["id"], dataset_id=record["dataset_id"], eligibility=record["card"]["eligibility"],
                       card=record["card"], review=record["review"])

def dataset_summary(data):
    return DatasetSummary(**{k: data[k] for k in ("id", "name", "created_at", "owner", "intended_use")},
                          record_count=len(data["records"]) if data["records"] is not None else 1)

def parse_timestamp(value: str) -> datetime:
    try:
        if not value.endswith("Z") or "+" in value[:-1]:
            raise ValueError
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        raise HTTPException(422, "Request validation failed") from None

def control_record(*, kind: str, identifier: str, tenant: str, payload: dict[str, Any], expires_at: float | None = None) -> dict[str, Any]:
    created = now()
    maximum = created.timestamp() + 3600
    expiry = maximum if expires_at is None else min(maximum, expires_at)
    if expiry <= created.timestamp():
        raise HTTPException(409, "Control is expired or unavailable")
    return {"id": identifier, "kind": kind, "tenant": tenant, "created_at": created.isoformat(),
            "expires_at": expiry, "size_bytes": 0, "payload": payload}

def policy_from_control(record: dict[str, Any]) -> PolicySnapshot:
    try:
        payload = record["payload"]
        profile_data = payload["profile"]
        profile = PolicyProfile(
            policy_id=profile_data["policy_id"], version=profile_data["version"],
            release_modes=tuple(profile_data["release_modes"]), formats=tuple(profile_data["formats"]),
            languages=tuple(profile_data["languages"]),
            rules=tuple(PolicyRule(**rule) for rule in profile_data["rules"]),
        )
        snapshot = PolicySnapshot.seal(profile)
        if payload["digest"] != snapshot.digest or payload["key"] != snapshot.key:
            raise ValueError
        return snapshot
    except (KeyError, TypeError, ValueError, PolicyError):
        raise HTTPException(503, "Control integrity verification failed") from None

def policy_view(record: dict[str, Any]) -> PolicySnapshotView:
    snapshot = policy_from_control(record)
    manifest = snapshot.manifest()
    return PolicySnapshotView(id=record["id"], key=snapshot.key, digest=snapshot.digest,
                              formats=list(manifest["formats"]), languages=list(manifest["languages"]),
                              release_modes=list(manifest["release_modes"]))

def rights_from_control(record: dict[str, Any]) -> RightsProfile:
    try:
        return RightsProfile.from_record(record["payload"])
    except (KeyError, RightsError, TypeError, ValueError):
        raise HTTPException(503, "Control integrity verification failed") from None

def rights_view(record: dict[str, Any]) -> RightsProfileView:
    profile = rights_from_control(record)
    return RightsProfileView(id=record["id"], profile_id=profile.profile_id, version=profile.version,
                             digest=profile.digest, expires_at=profile.expires_at.isoformat().replace("+00:00", "Z"),
                             resale_allowed=profile.resale_allowed, permitted_purposes=sorted(profile.permitted_purposes),
                             permitted_recipients=sorted(profile.permitted_recipients))

def run_view(record: dict[str, Any]) -> ProcessingRunView:
    try:
        payload = record["payload"]
        method_id, language = payload.get("method_id"), payload.get("language")
        method_version = payload.get("method_version")
        method_config_digest = payload.get("method_config_digest")
        taxonomy_mapping_digest = payload.get("taxonomy_mapping_digest")
        # M5 execution provenance was not persisted in M2b/M3 records.  Keep
        # those records inspectable but make their inability to run explicit;
        # reconstructing an executor/language from an old request digest would
        # fabricate evidence.
        if method_id is None and language is None:
            method_id, language = "legacy-unavailable", "und"
            method_version, method_config_digest, taxonomy_mapping_digest = "legacy-unavailable", None, None
        elif (method_id == RULES_METHOD_ID and language is not None
              and method_version is method_config_digest is taxonomy_mapping_digest is None):
            # Existing M5 records preserve their method label but have no
            # attested method configuration.  They remain viewable but cannot
            # receive M9 method evidence.
            method_version, method_config_digest, taxonomy_mapping_digest = "legacy-unavailable", None, None
        if (payload["state"] not in {"REGISTERED", "RUNNING", "CANDIDATE", "QUARANTINED", "FAILED"}
                or type(payload["attempts"]) is not int or not 0 <= payload["attempts"] <= 3
                or method_id not in {RULES_METHOD_ID, "legacy-unavailable"} or type(language) is not str
                or (method_id == RULES_METHOD_ID and (method_version != RULES_METHOD_VERSION
                    or method_config_digest != RULES_METHOD_CONFIG_DIGEST
                    or taxonomy_mapping_digest != RULES_TAXONOMY_MAPPING_DIGEST)
                    and method_version != "legacy-unavailable")
                or (method_id == "legacy-unavailable" and (method_version != "legacy-unavailable"
                    or method_config_digest is not None or taxonomy_mapping_digest is not None))
                or not isinstance(payload["events"], list) or not 1 <= len(payload["events"]) <= 16):
            raise ValueError
        return ProcessingRunView(id=record["id"], dataset_id=payload["dataset_id"], state=payload["state"],
                                 attempts=payload["attempts"], request_digest=payload["request_digest"],
                                 method_id=method_id, language=language,
                                 method_version=method_version, method_config_digest=method_config_digest,
                                 taxonomy_mapping_digest=taxonomy_mapping_digest,
                                 policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                                 recipient=payload["recipient"], purpose=payload["purpose"], events=copy.deepcopy(payload["events"]),
                                 candidate=copy.deepcopy(payload.get("candidate")))
    except (KeyError, TypeError, ValueError):
        raise HTTPException(503, "Control integrity verification failed") from None

def residual_view(record: dict[str, Any]) -> ResidualEvaluationView:
    try:
        payload = record["payload"]
        report = payload["report"]
        if (payload["run_id"] != report["run_id"] or type(report["residual_counts"]) is not dict
                or report["evidence_status"] not in {"INSUFFICIENT_EVIDENCE", "FAILS_PROFILE"}):
            raise ValueError
        return ResidualEvaluationView(id=record["id"], run_id=payload["run_id"],
                                      candidate_digest=report["candidate_digest"], report_digest=report["digest"],
                                      evidence_status=report["evidence_status"],
                                      residual_counts=copy.deepcopy(report["residual_counts"]),
                                      coverage_percent=report["coverage_percent"],
                                      assessed_categories=copy.deepcopy(report["assessed_categories"]),
                                      category_coverage_percent=report["category_coverage_percent"],
                                      utility_checks=copy.deepcopy(report["utility_checks"]))
    except (KeyError, TypeError, ValueError):
        raise HTTPException(503, "Control integrity verification failed") from None

def qualification_view(record: dict[str, Any]) -> QualificationView:
    try:
        payload = record["payload"]
        if payload["outcome"] not in {"QUARANTINED", "INSUFFICIENT_EVIDENCE"} or not isinstance(payload["reasons"], list):
            raise ValueError
        return QualificationView(id=record["id"], run_id=payload["run_id"], outcome=payload["outcome"],
                                 reasons=copy.deepcopy(payload["reasons"]), digest=payload["digest"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(503, "Control integrity verification failed") from None

def detector_evaluation_evidence_view(record: dict[str, Any], *, evaluator_authorities) -> DetectorEvaluationEvidenceView:
    """Return only a verified M8 aggregate report and safe run binding."""
    try:
        payload = record["payload"]
        report = ScoredEvaluation.from_record(payload["report"])
        if (set(payload) != {"run_id", "processing_request_digest", "policy_digest", "rights_digest",
                            "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest",
                            "idempotency_key", "evaluator_subject", "evaluator_authority_id",
                            "attestation_signature", "report"}
                or payload["report"]["digest"] != report.digest
                or (report.binding.detector_id, report.binding.detector_version,
                    report.binding.detector_config_digest, report.binding.taxonomy_mapping_digest) != (
                        payload["method_id"], payload["method_version"], payload["method_config_digest"],
                        payload["taxonomy_mapping_digest"])
                or report.posture.value != "OBSERVATIONAL_ONLY"):
            raise ValueError
        authority = matching_authority(evaluator_authorities, subject=payload["evaluator_subject"], tenant=record["tenant"],
                                       run_id=payload["run_id"], processing_request_digest=payload["processing_request_digest"],
                                       report=report, signature=payload["attestation_signature"])
        if authority.authority_id != payload["evaluator_authority_id"]:
            raise ValueError
        return DetectorEvaluationEvidenceView(
            id=record["id"], run_id=payload["run_id"],
            processing_request_digest=payload["processing_request_digest"],
            report_digest=report.digest, posture="OBSERVATIONAL_ONLY",
            limitations=list(report.limitations), report=report.to_record())
    except (KeyError, TypeError, ValueError, EvaluationHarnessError, EvaluatorAuthorityError):
        raise HTTPException(503, "Control integrity verification failed") from None

def utility_evidence_view(record: dict[str, Any], *, utility_evidence_authorities) -> UtilityEvidenceView:
    """Render one independently reconstructed, aggregate-only utility report."""
    try:
        payload = record["payload"]
        expected = {"run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest",
                    "rights_digest", "method_id", "method_version", "method_config_digest",
                    "taxonomy_mapping_digest", "idempotency_key", "utility_authority_id",
                    "attestation_signature", "report"}
        report = DataUtilityReport.from_record(payload["report"])
        if (set(payload) != expected or payload["report"]["digest"] != report.digest
                or payload["candidate_artifact_digest"] != report.candidate_artifact_digest
                or type(payload["run_id"]) is not str or type(payload["processing_request_digest"]) is not str
                or type(payload["utility_authority_id"]) is not str):
            raise ValueError
        authority = authority_for_tenant(utility_evidence_authorities, tenant=record["tenant"])
        if (authority.authority_id != payload["utility_authority_id"]
                or not authority.verify(
                    signature=payload["attestation_signature"], tenant=record["tenant"], run_id=payload["run_id"],
                    processing_request_digest=payload["processing_request_digest"],
                    candidate_artifact_digest=payload["candidate_artifact_digest"],
                    policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                    method_id=payload["method_id"], method_version=payload["method_version"],
                    method_config_digest=payload["method_config_digest"],
                    taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                    idempotency_key=payload["idempotency_key"], report=report)):
            raise ValueError
        return UtilityEvidenceView(
            id=record["id"], run_id=payload["run_id"],
            processing_request_digest=payload["processing_request_digest"],
            candidate_artifact_digest=report.candidate_artifact_digest, report_digest=report.digest,
            posture="OBSERVATIONAL_ONLY",
            limitations=[
                "NO_RELEASE_AUTHORIZATION",
                "Structural counts and value-free shape checks are not semantic, ML-task, fairness, privacy, or linkage evidence.",
                "A server-owned in-process authority is not KMS-backed production secret custody.",
            ], report=report.to_record(),
        )
    except (KeyError, TypeError, ValueError, UtilityEvidenceError, UtilityEvidenceAuthorityError):
        raise HTTPException(503, "Control integrity verification failed") from None

def disclosure_risk_evidence_view(record: dict[str, Any], *, disclosure_risk_authorities) -> DisclosureRiskEvidenceView:
    try:
        payload = record["payload"]
        expected = {"run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest", "rights_digest",
                    "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest", "idempotency_key",
                    "risk_authority_id", "qid_config_revision", "attestation_signature", "report"}
        report = DisclosureRiskReport.from_record(payload["report"])
        if set(payload) != expected or report.candidate_artifact_digest != payload["candidate_artifact_digest"]:
            raise ValueError
        authority = disclosure_risk_authority_for_tenant(disclosure_risk_authorities, tenant=record["tenant"])
        if (authority.authority_id != payload["risk_authority_id"] or payload["qid_config_revision"] != authority.qid_config_revision
                or report.quasi_identifier_commitment != authority.quasi_identifiers.public_commitment
                or report.quasi_identifier_count != authority.quasi_identifiers.field_count or not authority.verify(
                signature=payload["attestation_signature"], tenant=record["tenant"], run_id=payload["run_id"],
                processing_request_digest=payload["processing_request_digest"],
                candidate_artifact_digest=payload["candidate_artifact_digest"], policy_digest=payload["policy_digest"],
                rights_digest=payload["rights_digest"], method_id=payload["method_id"], method_version=payload["method_version"],
                method_config_digest=payload["method_config_digest"], taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                idempotency_key=payload["idempotency_key"], qid_config_revision=payload["qid_config_revision"], report=report)):
            raise ValueError
        return DisclosureRiskEvidenceView(id=record["id"], run_id=payload["run_id"],
            processing_request_digest=payload["processing_request_digest"], candidate_artifact_digest=report.candidate_artifact_digest,
            report_digest=report.digest, posture="OBSERVATIONAL_ONLY",
            limitations=["NO_RELEASE_AUTHORIZATION", "Aggregate k-anonymity is not semantic privacy, linkage, or re-identification assurance."],
            report=report.to_record())
    except (KeyError, TypeError, ValueError, DisclosureRiskError, DisclosureRiskAuthorityError):
        raise HTTPException(503, "Control integrity verification failed") from None

def linkage_risk_evidence_view(record: dict[str, Any], *, linkage_risk_authorities) -> LinkageRiskEvidenceView:
    """Render only a currently verified, aggregate-only linkage report."""
    try:
        payload = record["payload"]
        expected = {"run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest", "rights_digest",
                    "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest", "idempotency_key",
                    "linkage_authority_id", "linkage_config_revision", "attestation_signature", "report"}
        report = LinkageRiskReport.from_record(payload["report"])
        if (set(payload) != expected or payload["candidate_artifact_digest"] != report.candidate_artifact_digest
                or type(payload["run_id"]) is not str or type(payload["processing_request_digest"]) is not str
                or type(payload["linkage_authority_id"]) is not str):
            raise ValueError
        authority = linkage_risk_authority_for_tenant(linkage_risk_authorities, tenant=record["tenant"])
        if (authority.authority_id != payload["linkage_authority_id"]
                or payload["linkage_config_revision"] != authority.linkage_config_revision
                or report.linkage_key_commitment != authority.linkage_keys.public_commitment
                or report.linkage_key_count != authority.linkage_keys.field_count
                or report.reference_commitment != authority.reference.public_commitment
                or report.methodology_digest != LINKAGE_METHODOLOGY_DIGEST
                or not authority.verify(
                    signature=payload["attestation_signature"], tenant=record["tenant"], run_id=payload["run_id"],
                    processing_request_digest=payload["processing_request_digest"],
                    candidate_artifact_digest=payload["candidate_artifact_digest"],
                    policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                    method_id=payload["method_id"], method_version=payload["method_version"],
                    method_config_digest=payload["method_config_digest"],
                    taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                    idempotency_key=payload["idempotency_key"],
                    linkage_config_revision=payload["linkage_config_revision"], report=report)):
            raise ValueError
        return LinkageRiskEvidenceView(
            id=record["id"], run_id=payload["run_id"],
            processing_request_digest=payload["processing_request_digest"],
            candidate_artifact_digest=report.candidate_artifact_digest, report_digest=report.digest,
            posture="OBSERVATIONAL_ONLY", report=report.to_record(),
            limitations=[
                "NO_RELEASE_AUTHORIZATION",
                "Aggregate HMAC-token linkage counts do not establish identity correctness, semantic privacy, or re-identification safety.",
                "A server-owned in-process reference authority is not KMS-backed production secret or reference custody.",
            ],
        )
    except (KeyError, TypeError, ValueError, LinkageRiskError, LinkageRiskAuthorityError):
        raise HTTPException(503, "Control integrity verification failed") from None

def release_case_view(record: dict[str, Any]) -> ReleaseCaseView:
    """Return a source-safe index; scope verification occurs in the repository."""
    try:
        payload = record["payload"]
        if set(payload) != {"run_id", "idempotency_key", "case"}:
            raise ValueError
        case = ReleaseCase.from_record(payload["case"])
        if case.case_id != record["id"] or case.tenant != record["tenant"]:
            raise ValueError
        return ReleaseCaseView(id=record["id"], run_id=payload["run_id"],
            candidate_artifact_digest=case.binding.candidate_artifact_digest, case_digest=case.digest,
            authority_id=case.authority_id, issuer_key_id=case.issuer_key_id, expires_at=case.expires_at,
            posture="NO_RELEASE_AUTHORIZATION", limitations=[
                "NO_RELEASE_AUTHORIZATION",
                "This immutable scope record is not a privacy-policy decision, approval, release, delivery, or download handle.",
                "Recipient and contract values remain server-side; only opaque commitments/digests are retained.",
            ])
    except (KeyError, TypeError, ValueError, ReleaseCaseError):
        raise HTTPException(503, "Control integrity verification failed") from None

def privacy_decision_view(record: dict[str, Any]) -> PrivacyDecisionView:
    try:
        payload=record["payload"]
        if set(payload)!={"case_id","run_id","idempotency_key","decision"}: raise ValueError
        item=PrivacyDecision.from_record(payload["decision"])
        if item.decision_id != record["id"] or item.tenant != record["tenant"] or item.case_id != payload["case_id"]: raise ValueError
        return PrivacyDecisionView(id=item.decision_id, case_id=item.case_id, case_digest=item.case_digest,
            outcome=item.decision.outcome.value, reasons=[x.value for x in item.decision.reasons], decision_digest=item.digest,
            evidence=[{"kind":kind,"record_id":record_id,"record_digest":digest} for kind,record_id,digest in item.evidence_references],
            expires_at=item.expires_at, posture="NO_RELEASE_AUTHORIZATION", limitations=["NO_RELEASE_AUTHORIZATION", "A privacy evidence holding or quarantine is not approval, export, delivery, or a download handle."])
    except (KeyError,TypeError,ValueError,PrivacyDecisionError):
        raise HTTPException(503,"Control integrity verification failed") from None

def private_candidate_artifact(private: dict[str, Any]) -> CandidateArtifact:
    """Recreate a validated candidate only within a trusted worker boundary."""
    try:
        schema = SchemaContract.from_private_descriptor(
            kind=PayloadKind(private["payload_kind"]), digest=private["schema_digest"],
            descriptor=private["schema_descriptor"],
        )
        ledger = tuple(TransformLedgerEntry(item["entity_type"], LedgerAction(item["action"]),
                                            LedgerReason(item["reason"]), item["count"])
                       for item in private["ledger"])
        artifact = CandidateArtifact.create(
            run_id=private["run_id"], input_digest=private["input_digest"],
            policy_digest=private["policy_digest"], transformed=private["body"], schema=schema, ledger=ledger,
        )
        metadata = artifact.metadata
        if (metadata.artifact_digest != private["artifact_digest"]
                or metadata.byte_count != private["byte_count"]
                or metadata.media_type != private["media_type"]
                or metadata.payload_kind.value != private["payload_kind"]):
            raise ValueError
        return artifact
    except (KeyError, TypeError, ValueError, CandidateError):
        raise HTTPException(503, "Control integrity verification failed") from None

def _residual_detector(candidate: str | list[dict[str, Any]]) -> DetectorResult:
    """Compatibility adapter for the separately configured residual scanner."""
    return scan_residual_candidate(candidate)

def _policy_output_operations(result) -> tuple[PolicyOutputOperation, ...]:
    """Aggregate operations recorded by the worker into policy families.

    This deliberately never turns a detection into a claimed transformation.
    The processing result must already contain a source-free actual operation.
    """
    totals: dict[tuple[str, LedgerAction], int] = {}
    for operation in result.actual_operations:
        category = RULES_LABEL_TO_CATEGORY.get(operation.entity_type)
        if category is None:
            raise RulesPolicyExecutionError()
        key = (category, operation.action)
        totals[key] = totals.get(key, 0) + operation.count
    return tuple(PolicyOutputOperation(category, action, count)
                 for (category, action), count in sorted(totals.items(), key=lambda item: (item[0][0], item[0][1].value)))

def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            app.state.store.close()
    app = FastAPI(title="AnonFlow development API", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.router.route_class = StrictJSONRoute
    configure_auth(app)
    try:
        app.state.evaluator_authorities = load_evaluator_authorities()
    except EvaluatorAuthorityError:
        raise RuntimeError("Invalid evaluator authority configuration") from None
    try:
        app.state.utility_evidence_authorities = load_utility_evidence_authorities()
    except UtilityEvidenceAuthorityError:
        raise RuntimeError("Invalid utility-evidence authority configuration") from None
    try:
        app.state.disclosure_risk_authorities = load_disclosure_risk_authorities()
    except DisclosureRiskAuthorityError:
        raise RuntimeError("Invalid disclosure-risk authority configuration") from None
    try:
        app.state.linkage_risk_authorities = load_linkage_risk_authorities()
    except LinkageRiskAuthorityError:
        raise RuntimeError("Invalid linkage-risk authority configuration") from None
    try:
        app.state.release_case_authorities = load_release_case_authorities()
    except ReleaseCaseAuthorityError:
        raise RuntimeError("Invalid release-case authority configuration") from None
    try:
        app.state.privacy_decision_controls = load_privacy_decision_controls()
    except PrivacyDecisionError:
        raise RuntimeError("Invalid privacy-decision authority configuration") from None
    app.state.store = create_store()
    app.add_middleware(BodyLimitMiddleware)
    origins = [v.strip() for v in os.getenv("WEB_ORIGIN", "http://localhost:3000,http://localhost:5173").split(",") if v.strip()]
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "Authorization", "Idempotency-Key"])

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc):
        return JSONResponse({"detail": "Request validation failed"}, status_code=422)

    @app.exception_handler(PayloadError)
    @app.exception_handler(IngestionError)
    async def invalid_payload(request: Request, exc):
        return JSONResponse({"detail": "Unsupported payload"}, status_code=422)

    @app.exception_handler(PolicyError)
    @app.exception_handler(RightsError)
    @app.exception_handler(RunError)
    @app.exception_handler(CandidateError)
    @app.exception_handler(EvaluationError)
    @app.exception_handler(QualificationError)
    async def invalid_control(request: Request, exc):
        return JSONResponse({"detail": "Control validation failed"}, status_code=422)

    @app.middleware("http")
    async def response_protection(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "anonflow-api", "mode": "development", "production_ready": False}

    @app.post("/datasets", response_model=DatasetSummary, status_code=201)
    def create_dataset(request: DatasetCreate, principal: Principal = Depends(require_roles("processor"))):
        return persist_dataset(request, principal)

    def persist_dataset(request, principal, *, source=None, manifest=None, provenance=()):
        identifier = str(uuid4())
        data = request.model_dump()
        data.update(id=identifier, tenant=principal.tenant, owner=principal.subject, created_at=now().isoformat())
        if source is not None:
            data.update(original_source=source, ingestion_manifest=manifest, provenance=list(provenance))
        data["size_bytes"] = len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
        app.state.store.add_dataset(data)
        return dataset_summary(data)

    @app.post("/ingestions", response_model=DatasetSummary, status_code=201)
    def ingest(request: IngestionCreate, principal: Principal = Depends(require_roles("processor"))):
        parsed = parse_source(content=request.content, format=request.format)
        try:
            canonical = DatasetCreate(**request.model_dump(exclude={"format", "content"}), content=parsed.content, records=parsed.records)
        except ValidationError:
            raise HTTPException(422, "Unsupported payload") from None
        return persist_dataset(canonical, principal, source=request.content, manifest=parsed.manifest, provenance=parsed.provenance)

    @app.get("/datasets/{dataset_id}/manifest")
    def manifest(dataset_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        record = app.state.store.get_dataset(dataset_id, principal.tenant)
        if "ingestion_manifest" not in record:
            raise HTTPException(404, "Manifest not available")
        return {"dataset_id": dataset_id, "manifest": record["ingestion_manifest"], "provenance": record["provenance"]}

    @app.delete("/datasets/{dataset_id}", status_code=204)
    def delete_dataset(dataset_id: str, principal: Principal = Depends(require_roles("processor"))):
        app.state.store.delete_dataset(dataset_id, principal.tenant, principal.subject)

    @app.get("/audit")
    def audit(principal: Principal = Depends(require_roles("reviewer"))):
        return {"events": app.state.store.audit_events(principal.tenant)}

    @app.post("/policy-snapshots", response_model=PolicySnapshotView, status_code=201)
    def create_policy_snapshot(request: PolicySnapshotCreate, principal: Principal = Depends(require_roles("processor"))):
        profile = PolicyProfile(policy_id=request.policy_id, version=request.version,
                                release_modes=tuple(request.release_modes), formats=tuple(request.formats),
                                languages=tuple(request.languages),
                                rules=tuple(PolicyRule(**rule.model_dump()) for rule in request.rules))
        snapshot = PolicySnapshot.seal(profile)
        record = control_record(kind="policy_snapshot", identifier=str(uuid4()), tenant=principal.tenant,
                                payload={"profile": profile.canonical(), "key": snapshot.key, "digest": snapshot.digest})
        return policy_view(app.state.store.add_control(record, principal.subject))

    @app.get("/policy-snapshots/{snapshot_id}", response_model=PolicySnapshotView)
    def get_policy_snapshot(snapshot_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return policy_view(app.state.store.get_control("policy_snapshot", snapshot_id, principal.tenant))

    @app.post("/rights-profiles", response_model=RightsProfileView, status_code=201)
    def create_rights_profile(request: RightsProfileCreate, principal: Principal = Depends(require_roles("processor"))):
        profile = RightsProfile.create(profile_id=request.profile_id, version=request.version,
                                       permitted_purposes=request.permitted_purposes,
                                       permitted_recipients=request.permitted_recipients,
                                       expires_at=parse_timestamp(request.expires_at), resale_allowed=request.resale_allowed)
        record = control_record(kind="rights_profile", identifier=str(uuid4()), tenant=principal.tenant,
                                payload=profile.to_record(), expires_at=profile.expires_at.timestamp())
        return rights_view(app.state.store.add_control(record, principal.subject))

    @app.get("/rights-profiles/{profile_id}", response_model=RightsProfileView)
    def get_rights_profile(profile_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return rights_view(app.state.store.get_control("rights_profile", profile_id, principal.tenant))

    @app.post("/processing-runs", response_model=ProcessingRunView, status_code=201)
    def create_processing_run(request: ProcessingRunCreate, request_context: Request,
                              principal: Principal = Depends(require_roles("processor"))):
        keys = request_context.headers.getlist("idempotency-key")
        if len(keys) != 1:
            raise HTTPException(422, "Request validation failed")
        key = keys[0]
        if request.method_id != RULES_METHOD_ID:
            raise HTTPException(422, "Unsupported processing method")
        dataset = app.state.store.get_dataset(request.dataset_id, principal.tenant)
        if "ingestion_manifest" not in dataset:
            raise HTTPException(409, "Ingestion provenance is required")
        rights_record = app.state.store.get_control("rights_profile", request.rights_profile_id, principal.tenant)
        profile = rights_from_control(rights_record)
        gate = evaluate_rights(profile, purpose=request.purpose, recipient=request.recipient, at=now(), for_resale=True)
        if not gate.allowed:
            raise HTTPException(409, "Rights do not permit this processing request")
        policy_record = app.state.store.get_control("policy_snapshot", request.policy_snapshot_id, principal.tenant)
        snapshot = policy_from_control(policy_record)
        source_format = dataset["ingestion_manifest"].get("format")
        snapshot.require_support(release_mode=request.release_mode, format=source_format, language=request.language)
        source_hash = dataset["ingestion_manifest"].get("source_sha256")
        if type(source_hash) is not str or len(source_hash) != 64:
            raise HTTPException(503, "Control integrity verification failed")
        plan = ProcessingPlan.create(dataset_id=request.dataset_id, source_digest="sha256:" + source_hash,
                                     policy_id=snapshot.policy_id, policy_version=snapshot.version,
                                     method_id=request.method_id, mode=request.release_mode,
                                     options={"language": request.language, "policy_digest": snapshot.digest,
                                              "purpose": request.purpose, "recipient": request.recipient,
                                              "rights_digest": profile.digest})
        timestamp = now()
        registered, _ = RunRegistry(clock=lambda: timestamp).register(run_id=str(uuid4()), tenant=principal.tenant,
                                                                        idempotency_key=key, plan=plan)
        payload = {"idempotency_key": key, "request_digest": registered.request_digest,
                   "dataset_id": request.dataset_id, "rights_profile_id": request.rights_profile_id,
                   "policy_snapshot_id": request.policy_snapshot_id, "state": registered.state.value,
                   "attempts": registered.attempts, "policy_digest": snapshot.digest,
                   "source_digest": plan.source_digest,
                   "mode": request.release_mode, "method_id": request.method_id,
                   "method_version": RULES_METHOD_VERSION, "method_config_digest": RULES_METHOD_CONFIG_DIGEST,
                   "taxonomy_mapping_digest": RULES_TAXONOMY_MAPPING_DIGEST,
                   "language": request.language,
                   "rights_digest": profile.digest, "recipient": request.recipient,
                   "purpose": request.purpose, "processor_subject": principal.subject,
                   "events": [{"sequence": event.sequence, "state": event.state.value, "action": event.action,
                               "occurred_at": event.occurred_at.isoformat(), "attempt": event.attempt}
                              for event in registered.events]}
        record = control_record(kind="processing_run", identifier=registered.id, tenant=principal.tenant, payload=payload)
        persisted, reused = app.state.store.register_run_control(record, principal.subject)
        response = run_view(persisted)
        if reused:
            # The immutable resource already exists; FastAPI's default 201 is
            # deliberately replaced with a stable replay result.
            return Response(response.model_dump_json(), status_code=200, media_type="application/json")
        return response

    @app.get("/processing-runs/{run_id}", response_model=ProcessingRunView)
    def get_processing_run(run_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return run_view(app.state.store.get_control("processing_run", run_id, principal.tenant))

    @app.get("/processing-runs", response_model=list[ProcessingRunView])
    def list_processing_runs(principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return [run_view(record) for record in app.state.store.list_controls("processing_run", principal.tenant)]

    @app.post("/processing-runs/{run_id}/execute", response_model=ProcessingRunView)
    def execute_processing_run(run_id: str, principal: Principal = Depends(require_roles("processor"))):
        """Run the local development worker without returning source/output bytes."""
        registered = app.state.store.get_control("processing_run", run_id, principal.tenant)
        if (registered["payload"].get("method_id") != "rules-v1"
                or type(registered["payload"].get("language")) is not str):
            raise HTTPException(409, "Legacy processing run lacks execution provenance")
        claimed, dataset = app.state.store.claim_processing_run(run_id, principal.tenant, principal.subject)
        try:
            run_payload = claimed["payload"]
            if run_payload.get("method_id") != "rules-v1":
                raise RulesPolicyExecutionError()
            policy = policy_from_control(app.state.store.get_control("policy_snapshot", run_payload["policy_snapshot_id"], principal.tenant))
            policy.require_support(release_mode=run_payload["mode"],
                                   format=dataset["ingestion_manifest"].get("format"),
                                   language=run_payload["language"])
            source = dataset["content"] if dataset["content"] is not None else dataset["records"]
            payload_kind = PayloadKind.TEXT if dataset["content"] is not None else PayloadKind.STRUCTURED
            schema = SchemaContract.from_value(source, kind=payload_kind, allow_scalar_nulls=payload_kind is PayloadKind.STRUCTURED)
            result = process_payload(content=dataset["content"], records=dataset["records"], mode=run_payload["mode"])
            policy_execution = execute_rules_policy(policy=policy, release_mode=run_payload["mode"], result=result,
                                                     actual_operations=_policy_output_operations(result))
            artifact = CandidateArtifact.create(run_id=run_id, input_digest=run_payload["source_digest"],
                                                 policy_digest=run_payload["policy_digest"], transformed=result.output,
                                                 schema=schema, ledger=policy_execution.actual_ledger)
            metadata = artifact.metadata
            private_payload = {"run_id": metadata.run_id, "input_digest": metadata.input_digest,
                               "policy_digest": metadata.policy_digest, "artifact_digest": metadata.artifact_digest,
                               "schema_digest": metadata.schema_digest, "payload_kind": metadata.payload_kind.value,
                               "schema_descriptor": schema.private_descriptor,
                               "evaluation_schema_digest": candidate_schema_digest(result.output),
                               "media_type": metadata.media_type, "byte_count": metadata.byte_count,
                               "ledger": [{"entity_type": item.entity_type, "action": item.action.value,
                                           "reason": item.reason.value, "count": item.count} for item in metadata.ledger],
                               "policy_execution": {"plan_digest": policy_execution.plan.digest,
                                                    "disposition": policy_execution.disposition.value,
                                                    "obligations_satisfied": policy_execution.obligations_satisfied,
                                                    "assessed_categories": sorted(RULES_LABEL_TO_CATEGORY.values()),
                                                    "uncovered_categories": sorted(policy_execution.uncovered_categories)},
                               "body": artifact.materialize_for_private_worker()}
            record = control_record(kind="private_candidate", identifier=str(uuid4()), tenant=principal.tenant,
                                    payload=private_payload, expires_at=dataset["expires_at"])
            if policy_execution.can_create_private_candidate:
                completed = app.state.store.complete_processing_run(run_id, principal.tenant, record, principal.subject)
            else:
                code = ("POLICY_BLOCKED" if policy_execution.plan.disposition.value == "QUARANTINE_REQUIRED" else
                        "POLICY_REVIEW_REQUIRED" if policy_execution.plan.disposition.value == "REVIEW_REQUIRED" else
                        "POLICY_UNCOVERED" if policy_execution.uncovered_categories else
                        "POLICY_OBLIGATION_UNSATISFIED")
                completed = app.state.store.quarantine_processing_run(run_id, principal.tenant, record, code, principal.subject)
            return run_view(completed)
        except (CandidateError, PayloadError, ValueError):
            # Never return or persist an exception message: it can carry source values.
            return run_view(app.state.store.fail_processing_run(run_id, principal.tenant, "PROCESSING_FAILURE", principal.subject))
        except HTTPException:
            # A quota/race error after a claim must not leave a permanent RUNNING
            # run that neither retry nor review can resolve.
            return run_view(app.state.store.fail_processing_run(run_id, principal.tenant, "STORAGE_FAILURE", principal.subject))

    @app.post("/processing-runs/{run_id}/recover", response_model=ProcessingRunView)
    def recover_processing_run(run_id: str, principal: Principal = Depends(require_roles("processor"))):
        """Terminally recover a lease-expired local claim; it never requeues output."""
        return run_view(app.state.store.recover_stale_processing_run(run_id, principal.tenant, principal.subject))

    @app.post("/processing-runs/{run_id}/detector-evaluation-evidence",
              response_model=DetectorEvaluationEvidenceView, status_code=201)
    def create_detector_evaluation_evidence(run_id: str, request: DetectorEvaluationEvidenceCreate,
                                             request_context: Request,
                                             principal: Principal = Depends(require_roles("evaluator"))):
        """Persist source-free method evidence without changing the run lifecycle.

        A report is bound to an existing run only as evidence for that run's
        configured method.  It does not score the private candidate, alter its
        state, qualify a release, or become a delivery authorization.
        """
        keys = request_context.headers.getlist("idempotency-key")
        if len(keys) != 1 or not 1 <= len(keys[0]) <= 200 or not keys[0].isascii() or any(c.isspace() for c in keys[0]):
            raise HTTPException(422, "Request validation failed")
        try:
            report = ScoredEvaluation.from_record(request.report)
        except EvaluationHarnessError:
            raise HTTPException(422, "Control validation failed") from None
        run = app.state.store.get_control("processing_run", run_id, principal.tenant)
        run_payload = run["payload"]
        if run_payload.get("processor_subject") != principal.subject:
            try:
                authority = matching_authority(app.state.evaluator_authorities, subject=principal.subject,
                                               tenant=principal.tenant, run_id=run_id,
                                               processing_request_digest=run_payload["request_digest"], report=report,
                                               signature=request.attestation_signature)
            except EvaluatorAuthorityError:
                raise HTTPException(409, "Evaluator attestation is unavailable or invalid") from None
        else:
            # An ingestion/processing identity must not self-attest benchmark
            # metrics, even if it has accidentally been granted evaluator role.
            raise HTTPException(403, "Independent evaluator required")
        # A harness report measures a detector/method; it must never be
        # attached to an unrelated processing method merely because both are
        # aggregate-only records.
        if (report.binding.detector_id, report.binding.detector_version,
            report.binding.detector_config_digest, report.binding.taxonomy_mapping_digest) != (
                run_payload.get("method_id"), run_payload.get("method_version"),
                run_payload.get("method_config_digest"), run_payload.get("taxonomy_mapping_digest")):
            raise HTTPException(409, "Detector evidence does not match the processing method")
        payload = {"run_id": run_id, "processing_request_digest": run_payload["request_digest"],
                   "policy_digest": run_payload["policy_digest"], "rights_digest": run_payload["rights_digest"],
                   "method_id": run_payload["method_id"], "method_version": run_payload["method_version"],
                   "method_config_digest": run_payload["method_config_digest"],
                   "taxonomy_mapping_digest": run_payload["taxonomy_mapping_digest"], "idempotency_key": keys[0],
                   "evaluator_subject": principal.subject, "evaluator_authority_id": authority.authority_id,
                   "attestation_signature": request.attestation_signature,
                   "report": report.to_record()}
        record = control_record(kind="detector_evaluation_evidence", identifier=str(uuid4()), tenant=principal.tenant,
                                payload=payload, expires_at=run["expires_at"])
        persisted, reused = app.state.store.record_detector_evaluation_evidence(
            run_id, principal.tenant, record, principal.subject, authority)
        view = detector_evaluation_evidence_view(persisted, evaluator_authorities=app.state.evaluator_authorities)
        if reused:
            return Response(view.model_dump_json(), status_code=200, media_type="application/json")
        return view

    @app.get("/processing-runs/{run_id}/detector-evaluation-evidence/{evidence_id}",
             response_model=DetectorEvaluationEvidenceView)
    def get_detector_evaluation_evidence(run_id: str, evidence_id: str,
                                         principal: Principal = Depends(require_roles("processor", "reviewer"))):
        record = app.state.store.get_control("detector_evaluation_evidence", evidence_id, principal.tenant)
        if record["payload"].get("run_id") != run_id:
            raise HTTPException(404, "Control record not found")
        return detector_evaluation_evidence_view(record, evaluator_authorities=app.state.evaluator_authorities)

    @app.post("/processing-runs/{run_id}/utility-evidence", response_model=UtilityEvidenceView, status_code=201)
    async def create_utility_evidence(run_id: str, request_context: Request,
                                      principal: Principal = Depends(require_roles("processor"))):
        """Run a server-owned source/candidate comparison and retain aggregates only.

        This intentionally accepts no JSON body: a client cannot provide source
        values, candidate values, commitments, keys, detector output, or a
        purported report.  The private source and candidate cross the boundary
        only inside the local trusted-worker path below.
        """
        keys = request_context.headers.getlist("idempotency-key")
        if (len(keys) != 1 or not 1 <= len(keys[0]) <= 200 or not keys[0].isascii()
                or any(char.isspace() for char in keys[0]) or await request_context.body()):
            raise HTTPException(422, "Request validation failed")
        candidate_record, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        if run["payload"].get("processor_subject") != principal.subject:
            raise HTTPException(403, "Processing-run owner required")
        try:
            authority = authority_for_tenant(app.state.utility_evidence_authorities, tenant=principal.tenant)
        except UtilityEvidenceAuthorityError:
            # No authority means there is no safe way to issue a private-source
            # commitment.  Do not compute or retain a partial metric report.
            raise HTTPException(409, "Utility evidence authority is unavailable") from None
        dataset = app.state.store.get_dataset(run["payload"]["dataset_id"], principal.tenant)
        source = dataset["content"] if dataset["content"] is not None else dataset["records"]
        try:
            artifact = private_candidate_artifact(candidate_record["payload"])
            commitment = authority.issue(source)
            report = assess_data_utility(source=source, candidate=artifact, source_commitment=commitment,
                                         commitment_verifier=authority.verifier)
        except (UtilityEvidenceAuthorityError, UtilityEvidenceError, CandidateError, KeyError, TypeError, ValueError):
            # Source/candidate integrity errors and authority failures must not
            # become an HTTP reflection or retained aggregate measurement.
            raise HTTPException(503, "Utility evidence is unavailable") from None
        if report.status.value != "ASSESSED":
            raise HTTPException(503, "Utility evidence is unavailable")
        payload = {
            "run_id": run_id, "processing_request_digest": run["payload"]["request_digest"],
            "candidate_artifact_digest": artifact.metadata.artifact_digest,
            "policy_digest": run["payload"]["policy_digest"], "rights_digest": run["payload"]["rights_digest"],
            "method_id": run["payload"]["method_id"], "method_version": run["payload"]["method_version"],
            "method_config_digest": run["payload"]["method_config_digest"],
            "taxonomy_mapping_digest": run["payload"]["taxonomy_mapping_digest"],
            "idempotency_key": keys[0], "utility_authority_id": authority.authority_id,
            "report": report.to_record(),
        }
        try:
            payload["attestation_signature"] = authority.sign_for_worker(
                tenant=principal.tenant, run_id=run_id,
                processing_request_digest=payload["processing_request_digest"],
                candidate_artifact_digest=payload["candidate_artifact_digest"],
                policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                method_id=payload["method_id"], method_version=payload["method_version"],
                method_config_digest=payload["method_config_digest"],
                taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                idempotency_key=payload["idempotency_key"], report=report,
            )
        except UtilityEvidenceAuthorityError:
            raise HTTPException(503, "Utility evidence is unavailable") from None
        record = control_record(kind="utility_evidence", identifier=str(uuid4()), tenant=principal.tenant,
                                payload=payload, expires_at=min(run["expires_at"], candidate_record["expires_at"]))
        persisted, reused = app.state.store.record_utility_evidence(
            run_id, principal.tenant, record, principal.subject, authority)
        view = utility_evidence_view(persisted, utility_evidence_authorities=app.state.utility_evidence_authorities)
        if reused:
            return Response(view.model_dump_json(), status_code=200, media_type="application/json")
        return view

    @app.get("/processing-runs/{run_id}/utility-evidence/{evidence_id}", response_model=UtilityEvidenceView)
    def get_utility_evidence(run_id: str, evidence_id: str,
                             principal: Principal = Depends(require_roles("processor", "reviewer"))):
        record = app.state.store.get_control("utility_evidence", evidence_id, principal.tenant)
        if record["payload"].get("run_id") != run_id:
            raise HTTPException(404, "Control record not found")
        return utility_evidence_view(record, utility_evidence_authorities=app.state.utility_evidence_authorities)

    @app.post("/processing-runs/{run_id}/disclosure-risk-evidence", response_model=DisclosureRiskEvidenceView, status_code=201)
    async def create_disclosure_risk_evidence(run_id: str, request_context: Request,
                                              principal: Principal = Depends(require_roles("processor"))):
        """Assess stored private candidate data using server-owned QID configuration only."""
        keys = request_context.headers.getlist("idempotency-key")
        if (len(keys) != 1 or not 1 <= len(keys[0]) <= 200 or not keys[0].isascii()
                or any(char.isspace() for char in keys[0]) or await request_context.body()):
            raise HTTPException(422, "Request validation failed")
        candidate_record, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        if run["payload"].get("processor_subject") != principal.subject:
            raise HTTPException(403, "Processing-run owner required")
        try:
            authority = disclosure_risk_authority_for_tenant(app.state.disclosure_risk_authorities, tenant=principal.tenant)
            artifact = private_candidate_artifact(candidate_record["payload"])
            report = assess_disclosure_risk(candidate=artifact, quasi_identifiers=authority.quasi_identifiers,
                                            commitment_verifier=authority.commitment_verifier)
        except (DisclosureRiskAuthorityError, DisclosureRiskError, CandidateError, KeyError, TypeError, ValueError):
            raise HTTPException(503, "Disclosure-risk evidence is unavailable") from None
        payload = {"run_id": run_id, "processing_request_digest": run["payload"]["request_digest"],
                   "candidate_artifact_digest": artifact.metadata.artifact_digest,
                   "policy_digest": run["payload"]["policy_digest"], "rights_digest": run["payload"]["rights_digest"],
                   "method_id": run["payload"]["method_id"], "method_version": run["payload"]["method_version"],
                   "method_config_digest": run["payload"]["method_config_digest"],
                   "taxonomy_mapping_digest": run["payload"]["taxonomy_mapping_digest"], "idempotency_key": keys[0],
                   "risk_authority_id": authority.authority_id, "qid_config_revision": authority.qid_config_revision,
                   "report": report.to_record()}
        try:
            payload["attestation_signature"] = authority.sign_for_worker(
                tenant=principal.tenant, run_id=run_id, processing_request_digest=payload["processing_request_digest"],
                candidate_artifact_digest=payload["candidate_artifact_digest"], policy_digest=payload["policy_digest"],
                rights_digest=payload["rights_digest"], method_id=payload["method_id"], method_version=payload["method_version"],
                method_config_digest=payload["method_config_digest"], taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                idempotency_key=keys[0], qid_config_revision=payload["qid_config_revision"], report=report)
        except DisclosureRiskAuthorityError:
            raise HTTPException(503, "Disclosure-risk evidence is unavailable") from None
        record = control_record(kind="disclosure_risk_evidence", identifier=str(uuid4()), tenant=principal.tenant,
                                payload=payload, expires_at=min(run["expires_at"], candidate_record["expires_at"]))
        persisted, reused = app.state.store.record_disclosure_risk_evidence(run_id, principal.tenant, record, principal.subject, authority)
        view = disclosure_risk_evidence_view(persisted, disclosure_risk_authorities=app.state.disclosure_risk_authorities)
        if reused: return Response(view.model_dump_json(), status_code=200, media_type="application/json")
        return view

    @app.get("/processing-runs/{run_id}/disclosure-risk-evidence/{evidence_id}", response_model=DisclosureRiskEvidenceView)
    def get_disclosure_risk_evidence(run_id: str, evidence_id: str,
                                     principal: Principal = Depends(require_roles("processor", "reviewer"))):
        record = app.state.store.get_control("disclosure_risk_evidence", evidence_id, principal.tenant)
        if record["payload"].get("run_id") != run_id: raise HTTPException(404, "Control record not found")
        return disclosure_risk_evidence_view(record, disclosure_risk_authorities=app.state.disclosure_risk_authorities)

    @app.post("/processing-runs/{run_id}/linkage-risk-evidence", response_model=LinkageRiskEvidenceView, status_code=201)
    async def create_linkage_risk_evidence(run_id: str, request_context: Request,
                                           principal: Principal = Depends(require_roles("processor"))):
        """Assess a stored candidate against a server-owned linkage reference only.

        This deliberately accepts no JSON body.  Clients cannot select fields,
        supply a reference, key, candidate, commitment, or purported report.
        """
        keys = request_context.headers.getlist("idempotency-key")
        if (len(keys) != 1 or not 1 <= len(keys[0]) <= 200 or not keys[0].isascii()
                or any(char.isspace() for char in keys[0]) or await request_context.body()):
            raise HTTPException(422, "Request validation failed")
        candidate_record, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        if run["payload"].get("processor_subject") != principal.subject:
            raise HTTPException(403, "Processing-run owner required")
        try:
            authority = linkage_risk_authority_for_tenant(app.state.linkage_risk_authorities, tenant=principal.tenant)
        except LinkageRiskAuthorityError:
            raise HTTPException(409, "Linkage-risk evidence authority is unavailable") from None
        try:
            artifact = private_candidate_artifact(candidate_record["payload"])
            report = assess_linkage_risk(candidate=artifact, reference=authority.reference,
                                         linkage_keys=authority.linkage_keys,
                                         commitment_verifier=authority.commitment_verifier)
        except (LinkageRiskAuthorityError, LinkageRiskError, CandidateError, KeyError, TypeError, ValueError):
            raise HTTPException(503, "Linkage-risk evidence is unavailable") from None
        payload = {
            "run_id": run_id, "processing_request_digest": run["payload"]["request_digest"],
            "candidate_artifact_digest": artifact.metadata.artifact_digest,
            "policy_digest": run["payload"]["policy_digest"], "rights_digest": run["payload"]["rights_digest"],
            "method_id": run["payload"]["method_id"], "method_version": run["payload"]["method_version"],
            "method_config_digest": run["payload"]["method_config_digest"],
            "taxonomy_mapping_digest": run["payload"]["taxonomy_mapping_digest"],
            "idempotency_key": keys[0], "linkage_authority_id": authority.authority_id,
            "linkage_config_revision": authority.linkage_config_revision, "report": report.to_record(),
        }
        try:
            payload["attestation_signature"] = authority.sign_for_worker(
                tenant=principal.tenant, run_id=run_id,
                processing_request_digest=payload["processing_request_digest"],
                candidate_artifact_digest=payload["candidate_artifact_digest"],
                policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                method_id=payload["method_id"], method_version=payload["method_version"],
                method_config_digest=payload["method_config_digest"],
                taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                idempotency_key=payload["idempotency_key"],
                linkage_config_revision=payload["linkage_config_revision"], report=report)
        except LinkageRiskAuthorityError:
            raise HTTPException(503, "Linkage-risk evidence is unavailable") from None
        record = control_record(kind="linkage_risk_evidence", identifier=str(uuid4()), tenant=principal.tenant,
                                payload=payload, expires_at=min(run["expires_at"], candidate_record["expires_at"]))
        persisted, reused = app.state.store.record_linkage_risk_evidence(
            run_id, principal.tenant, record, principal.subject, authority)
        view = linkage_risk_evidence_view(persisted, linkage_risk_authorities=app.state.linkage_risk_authorities)
        if reused:
            return Response(view.model_dump_json(), status_code=200, media_type="application/json")
        return view

    @app.get("/processing-runs/{run_id}/linkage-risk-evidence/{evidence_id}", response_model=LinkageRiskEvidenceView)
    def get_linkage_risk_evidence(run_id: str, evidence_id: str,
                                  principal: Principal = Depends(require_roles("processor", "reviewer"))):
        record = app.state.store.get_control("linkage_risk_evidence", evidence_id, principal.tenant)
        if record["payload"].get("run_id") != run_id:
            raise HTTPException(404, "Control record not found")
        return linkage_risk_evidence_view(record, linkage_risk_authorities=app.state.linkage_risk_authorities)

    @app.post("/processing-runs/{run_id}/release-cases", response_model=ReleaseCaseView, status_code=201)
    async def create_release_case(run_id: str, request_context: Request,
                                  principal: Principal = Depends(require_roles("processor"))):
        """Create a non-authorizing case from server-held run/candidate/config only."""
        keys = request_context.headers.getlist("idempotency-key")
        if len(keys) != 1 or await request_context.body():
            raise HTTPException(422, "Request validation failed")
        # Resolve the tenant-scoped private candidate first.  This preserves
        # the control-plane's normal cross-tenant 404 boundary rather than
        # revealing whether that tenant configured a release-case issuer.
        candidate, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        try:
            authority = release_case_authority_for_tenant(app.state.release_case_authorities,
                                                          tenant=principal.tenant)
        except ReleaseCaseAuthorityError:
            raise HTTPException(409, "Release-case authority is unavailable") from None
        try:
            dataset = app.state.store.get_dataset(run["payload"]["dataset_id"], principal.tenant)
            rights = app.state.store.get_control("rights_profile", run["payload"]["rights_profile_id"], principal.tenant)
            issued = now().replace(microsecond=0)
            convert = lambda value: datetime.fromtimestamp(value, UTC).replace(microsecond=0)
            candidate_expiry, run_expiry, rights_expiry = (convert(candidate["expires_at"]),
                                                           convert(run["expires_at"]), convert(rights["expires_at"]))
            expiry = min(candidate_expiry, run_expiry, rights_expiry, authority.contract_expires_at,
                         authority.issuer.expires_at, issued + timedelta(hours=1))
            dataset_provenance_digest = "sha256:" + hashlib.sha256(json.dumps(
                {"ingestion_manifest": dataset["ingestion_manifest"], "provenance": dataset["provenance"]},
                ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            method_provenance_digest = "sha256:" + hashlib.sha256(json.dumps(
                {key: run["payload"][key] for key in ("method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest")},
                ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            run_digest = "sha256:" + hashlib.sha256(json.dumps(run, ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            case = authority.issuer.issue(
                case_id="release-case:v1:" + token_urlsafe(32), candidate_artifact_digest=candidate["payload"]["artifact_digest"],
                processing_run_id=run_id, processing_run_digest=run_digest,
                processing_request_digest=run["payload"]["request_digest"], processing_mode=run["payload"]["mode"],
                processing_policy_digest=run["payload"]["policy_digest"], dataset_provenance_digest=dataset_provenance_digest,
                ingestion_provenance_digest=run["payload"]["source_digest"], rights_digest=run["payload"]["rights_digest"],
                recipient=run["payload"]["recipient"], purpose_code=run["payload"]["purpose"],
                method_provenance_digest=method_provenance_digest, contract_reference=authority.contract_reference,
                contract_digest=authority.contract_digest, candidate_expires_at=candidate_expiry,
                processing_run_expires_at=run_expiry, rights_expires_at=rights_expiry,
                contract_expires_at=authority.contract_expires_at, issued_at=issued, expires_at=expiry, at=issued)
        except (KeyError, TypeError, ValueError, OSError, OverflowError, ReleaseCaseError):
            raise HTTPException(503, "Release-case scope is unavailable") from None
        record = control_record(kind="release_case", identifier=case.case_id, tenant=principal.tenant,
                                payload={"run_id": run_id, "idempotency_key": keys[0], "case": case.to_record()},
                                expires_at=case.expires_at.timestamp())
        persisted, reused = app.state.store.record_release_case(run_id, principal.tenant, record,
                                                                  principal.subject, authority)
        view = release_case_view(persisted)
        if reused:
            return Response(view.model_dump_json(), status_code=200, media_type="application/json")
        return view

    @app.get("/release-cases/{case_id}", response_model=ReleaseCaseView)
    def get_release_case(case_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        # Keep tenant isolation ahead of configuration selection.  A caller in
        # another tenant learns only the usual not-found result.
        app.state.store.get_control("release_case", case_id, principal.tenant)
        try:
            authority = release_case_authority_for_tenant(app.state.release_case_authorities,
                                                          tenant=principal.tenant)
        except ReleaseCaseAuthorityError:
            raise HTTPException(409, "Release-case authority is unavailable") from None
        return release_case_view(app.state.store.get_release_case(case_id, principal.tenant, authority))

    def assess_case_privacy(case_id: str, tenant: str, moment: datetime, decision_id: str):
        """Server-only M15 adapter; native report validation precedes M12 V2 issue.

        Residual and benchmark currently have no source-safe candidate-bound
        attested control appropriate for this gate, so they deliberately remain
        missing.  They are never converted from a naked digest or aggregate.
        """
        authority = release_case_authority_for_tenant(app.state.release_case_authorities, tenant=tenant, at=moment)
        raw_case = app.state.store.get_release_case(case_id, tenant, authority)
        case = ReleaseCase.from_record(raw_case["payload"]["case"])
        control = privacy_decision_control_for_tenant(app.state.privacy_decision_controls, tenant=tenant, at=moment)
        binding = PrivacyEvidenceBinding(candidate_artifact_digest=case.binding.candidate_artifact_digest,
            processing_policy_digest=case.binding.processing_policy_digest, rights_digest=case.binding.rights_digest,
            recipient_reference="sha256:" + hashlib.sha256(case.binding.recipient_commitment.encode("ascii")).hexdigest(),
            purpose_code=case.binding.purpose_code, method_provenance_digest=case.binding.method_provenance_digest,
            candidate_expires_at=case.binding.candidate_expires_at)
        policy = control.policy(binding)
        candidates = {
            PrivacyEvidenceKind.UTILITY: ("utility_evidence", utility_evidence_view, app.state.utility_evidence_authorities),
            PrivacyEvidenceKind.DISCLOSURE_RISK: ("disclosure_risk_evidence", disclosure_risk_evidence_view, app.state.disclosure_risk_authorities),
            PrivacyEvidenceKind.LINKAGE: ("linkage_risk_evidence", linkage_risk_evidence_view, app.state.linkage_risk_authorities),
        }
        evidence=[]; refs=[]; expiry=min(case.expires_at, control.decision_authority.expires_at)
        for kind, (storage_kind, renderer, authorities) in candidates.items():
            records=[record for record in app.state.store.list_controls(storage_kind, tenant)
                     if record.get("payload",{}).get("run_id") == case.binding.processing_run_id]
            if len(records) != 1:
                if len(records) > 1: evidence.append(object()) # ambiguous source selection quarantines
                continue
            record=records[0]
            try:
                view=renderer(record, **({"utility_evidence_authorities": authorities} if kind is PrivacyEvidenceKind.UTILITY else
                                           {"disclosure_risk_authorities": authorities} if kind is PrivacyEvidenceKind.DISCLOSURE_RISK else
                                           {"linkage_risk_authorities": authorities}))
                report=view.report
                if (view.candidate_artifact_digest != case.binding.candidate_artifact_digest
                        or view.processing_request_digest != case.binding.processing_request_digest): raise ValueError
                if kind is PrivacyEvidenceKind.UTILITY:
                    if report.get("status") != "ASSESSED": raise ValueError
                    observed=1_000_000 if report.get("structure_preserved") and report.get("unit_count_preserved") else 0
                elif kind is PrivacyEvidenceKind.DISCLOSURE_RISK:
                    if report.get("status") != "ASSESSED" or type(report.get("unique_record_count")) is not int: raise ValueError
                    observed=report["unique_record_count"]
                else:
                    if report.get("status") != "ASSESSED" or type(report.get("unique_match_count")) is not int: raise ValueError
                    observed=report["unique_match_count"]
                created=datetime.fromisoformat(record["created_at"].replace("Z","+00:00")).astimezone(UTC).replace(microsecond=0)
                record_expiry=datetime.fromtimestamp(record["expires_at"], UTC).replace(microsecond=0)
                item_expiry=min(record_expiry, case.expires_at, control.decision_authority.expires_at)
                issuer=control.evidence_authority(kind)
                reference=issuer.issue(kind=kind, evidence_reference=control.opaque_reference(kind=kind, record_id=record["id"], record_digest=view.report_digest),
                    evidence_digest=view.report_digest, binding=binding, policy=policy, observed_value=observed,
                    measured_at=created, expires_at=item_expiry, at=moment)
                evidence.append(issuer.to_policy_evidence(reference, at=moment))
                refs.append((kind.value, record["id"], view.report_digest)); expiry=min(expiry,item_expiry)
            except (HTTPException, KeyError, TypeError, ValueError, PrivacyDecisionError):
                evidence.append(object()) # invalid native evidence is a quarantining policy input
        assessment=assess_privacy_evidence(decision_id="m15-policy-decision", binding=binding, policy=policy,
            evidence=tuple(evidence), authorities=tuple(x.policy_verifier for _,x in control.evidence_authorities), at=moment)
        decision=control.decision_authority.issue(decision_id=decision_id,
            case_id=case_id, case_digest=case.digest, decision=assessment, evidence_references=tuple(sorted(refs)), expires_at=expiry, at=moment)
        return decision, authority

    @app.post("/release-cases/{case_id}/privacy-decisions", response_model=PrivacyDecisionView, status_code=201)
    async def create_privacy_decision(case_id: str, request_context: Request, principal: Principal = Depends(require_roles("processor"))):
        keys=request_context.headers.getlist("idempotency-key")
        if len(keys)!=1 or await request_context.body(): raise HTTPException(422,"Request validation failed")
        moment=now().replace(microsecond=0)
        try:
            control=privacy_decision_control_for_tenant(app.state.privacy_decision_controls, tenant=principal.tenant, at=moment)
            item, release_authority=assess_case_privacy(case_id, principal.tenant, moment,
                                                        control.decision_identifier(case_id=case_id,idempotency_key=keys[0]))
        except (PrivacyDecisionError, ReleaseCaseAuthorityError, ReleaseCaseError, HTTPException):
            raise HTTPException(409,"Privacy decision scope is unavailable") from None
        record=control_record(kind="privacy_decision", identifier=item.decision_id, tenant=principal.tenant,
            payload={"case_id":case_id,"run_id":ReleaseCase.from_record(app.state.store.get_control("release_case",case_id,principal.tenant)["payload"]["case"]).binding.processing_run_id,
                     "idempotency_key":keys[0],"decision":item.to_record()}, expires_at=item.expires_at.timestamp())
        persisted,reused=app.state.store.record_privacy_decision(case_id,principal.tenant,record,principal.subject,
            control.decision_authority,release_authority,lambda checked_case, checked_tenant, checked_moment, checked_id:
                assess_case_privacy(checked_case,checked_tenant,checked_moment,checked_id)[0])
        view=privacy_decision_view(persisted)
        return Response(view.model_dump_json(),status_code=200,media_type="application/json") if reused else view

    @app.get("/privacy-decisions/{decision_id}", response_model=PrivacyDecisionView)
    def get_privacy_decision(decision_id: str, principal: Principal = Depends(require_roles("processor","reviewer"))):
        raw=app.state.store.get_control("privacy_decision",decision_id,principal.tenant)
        moment=now().replace(microsecond=0)
        try:
            control=privacy_decision_control_for_tenant(app.state.privacy_decision_controls,tenant=principal.tenant,at=moment)
            case_id=raw["payload"]["case_id"]
            # Reassess live sources; a changed or invalid source must never be
            # rendered as a still-valid holding decision.
            stored=PrivacyDecision.from_record(raw["payload"]["decision"])
            current, release_authority=assess_case_privacy(case_id,principal.tenant,moment,stored.decision_id)
            # ``decided_at`` is intentionally immutable, while reassessment
            # happens at read time.  Every substantive binding, policy result,
            # reason and exact digest/ref map must nevertheless remain equal.
            if (stored.decision.outcome != current.decision.outcome or stored.decision.reasons != current.decision.reasons
                    or stored.decision.binding != current.decision.binding
                    or stored.decision.privacy_evidence_policy_digest != current.decision.privacy_evidence_policy_digest
                    or stored.decision.evidence_digests != current.decision.evidence_digests
                    or stored.evidence_references != current.evidence_references): raise ValueError
            return privacy_decision_view(app.state.store.get_privacy_decision(decision_id,principal.tenant,control.decision_authority,release_authority))
        except (KeyError,TypeError,ValueError,PrivacyDecisionError,ReleaseCaseAuthorityError,HTTPException):
            raise HTTPException(503,"Privacy decision is unavailable") from None

    @app.post("/processing-runs/{run_id}/residual-evaluations", response_model=ResidualEvaluationView, status_code=201)
    def create_residual_evaluation(run_id: str, principal: Principal = Depends(require_roles("reviewer"))):
        candidate, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        private = candidate["payload"]
        body = private["body"]
        profile = EvaluationProfile.create(profile_id="m3-residual", version="rules-v1",
                                           required_categories=("PII", "HEALTH_SENSITIVE", "PAYMENT", "CREDENTIAL", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER"))
        detector = DetectorIdentity(detector_id=DETECTOR_ID, config_digest=DETECTOR_CONFIG_DIGEST)
        metadata = ResidualCandidateMetadata(artifact_digest=private["artifact_digest"], media_type=private["media_type"],
                                              expected_record_count=1 if type(body) is str else len(body),
                                              expected_schema_digest=None if type(body) is str else private["evaluation_schema_digest"])
        report = evaluate_candidate(body, metadata=metadata, detector=_residual_detector,
                                    detector_identity=detector, profile=profile)
        report_record = report.to_record()
        report_record.update(run_id=run_id, policy_digest=run["payload"]["policy_digest"], rights_digest=run["payload"]["rights_digest"],
                             evaluated_at=now().isoformat().replace("+00:00", "Z"))
        record = control_record(kind="evaluation_report", identifier=str(uuid4()), tenant=principal.tenant,
                                payload={"run_id": run_id, "candidate_digest": report.candidate_digest,
                                         "policy_digest": run["payload"]["policy_digest"], "rights_digest": run["payload"]["rights_digest"],
                                         "evidence_status": report.evidence_status.value,
                                         "report": report_record}, expires_at=candidate["expires_at"])
        persisted, _ = app.state.store.record_evaluation(run_id, principal.tenant, record, principal.subject)
        return residual_view(persisted)

    @app.post("/processing-runs/{run_id}/qualifications", response_model=QualificationView, status_code=201)
    def create_qualification(run_id: str, request: QualificationCreate,
                             principal: Principal = Depends(require_roles("reviewer"))):
        candidate, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        evaluation = app.state.store.get_control("evaluation_report", request.evaluation_id, principal.tenant)
        report = evaluation["payload"].get("report", {})
        if evaluation["payload"].get("run_id") != run_id:
            raise HTTPException(409, "Evaluation does not belong to the processing run")
        try:
            evaluated_at = parse_timestamp(report["evaluated_at"])
            expiry = datetime.fromtimestamp(candidate["expires_at"], UTC)
            candidate_binding = CandidateBinding(candidate["payload"]["artifact_digest"], run["payload"]["policy_digest"],
                                                 run["payload"]["rights_digest"], run["payload"]["recipient"],
                                                 run["payload"]["purpose"], expiry)
            counts = report["residual_counts"]
            # A missing family is absence of coverage, never zero residuals.
            # The local rules adapter only claims the categories it reports.
            measured = tuple(CategoryMeasurement(category, counts[category], report["total_units"])
                             for category in sorted(TAXONOMY_CATEGORIES) if category in {"PII", "PAYMENT", "CREDENTIAL"})
            qualification_report = QualificationReport(report["digest"], report["candidate_digest"],
                                                        run["payload"]["policy_digest"], run["payload"]["rights_digest"],
                                                        run["payload"]["recipient"], run["payload"]["purpose"], evaluated_at, measured)
            criteria = QualificationCriteria(tuple(CategoryThreshold(category, 0) for category in TAXONOMY_CATEGORIES),
                                             request.max_evaluation_age_seconds)
            decision = qualify(qualification_id=str(uuid4()), candidate=candidate_binding,
                               report=qualification_report, criteria=criteria, at=now())
        except (KeyError, TypeError, ValueError, QualificationError):
            raise HTTPException(503, "Control integrity verification failed") from None
        payload = dict(decision.snapshot())
        payload.update(run_id=run_id, reasons=list(payload.pop("reasons")))
        record = control_record(kind="qualification", identifier=decision.qualification_id, tenant=principal.tenant,
                                payload=payload, expires_at=candidate["expires_at"])
        persisted, _ = app.state.store.record_qualification(run_id, principal.tenant, record, request.evaluation_id, principal.subject)
        return qualification_view(persisted)

    @app.get("/datasets", response_model=list[DatasetSummary])
    def list_datasets(principal: Principal = Depends(require_roles("processor"))):
        return [dataset_summary(d) for d in app.state.store.list_datasets(principal.tenant)]

    @app.post("/releases", response_model=ReleaseView, status_code=201)
    def create_release(request: ReleaseCreate, principal: Principal = Depends(require_roles("processor"))):
        store = app.state.store
        dataset = store.get_dataset(request.dataset_id, principal.tenant)
        result = process_payload(content=dataset["content"], records=dataset["records"], mode=request.release_mode)
        identifier = str(uuid4())
        eligibility = Eligibility.BLOCKED if result.critical_detected or not request.allow_review else Eligibility.REVIEW_REQUIRED
        card = ReleaseCard(release_id=identifier, dataset_id=request.dataset_id, generated_at=now(), policy_version=request.policy_version,
                               release_mode=request.release_mode, eligibility=eligibility,
                               findings=[{"entity_type": f.entity_type, "severity": f.severity, "count": f.count} for f in result.findings],
                               gates=["EXPORT_DISABLED", "QUALIFICATION_REQUIRED"] + (["CRITICAL_FINDING"] if result.critical_detected else []) + (["REVIEW_DISABLED"] if not request.allow_review else []),
                               limitations=list(dict.fromkeys([*result.limitations, "No independent privacy or utility qualification has been performed.", "Development-only: source retention is capped at one hour; cleanup is access-triggered, not secure erasure or backup deletion.", "No buyer delivery, anonymity guarantee or production authorization is supported."]))).model_dump(mode="json")
        record = {"id": identifier, "dataset_id": request.dataset_id, "tenant": principal.tenant, "creator": principal.subject,
                  "card": card, "review": None, "events": [{"revision": 1, "card": copy.deepcopy(card)}]}
        # Atomic insertion rechecks parent liveness and quotas after processing.
        # Candidate output deliberately is neither retained nor returned.
        store.add_release(record)
        return release_view(record)

    @app.get("/releases/{release_id}", response_model=ReleaseView)
    def get_release(release_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return release_view(app.state.store.get_release(release_id, principal.tenant))

    @app.get("/releases/{release_id}/card", response_model=ReleaseCard)
    def get_card(release_id: str, principal: Principal = Depends(require_roles("processor", "reviewer"))):
        return app.state.store.get_release(release_id, principal.tenant)["card"]

    @app.post("/reviews/{release_id}/decision", response_model=ReleaseView)
    def review(release_id: str, request: ReviewDecision, principal: Principal = Depends(require_roles("reviewer"))):
        record = app.state.store.get_release(release_id, principal.tenant)
        if record["creator"] == principal.subject:
            raise HTTPException(403, "Independent reviewer required")
        if request.decision == "approve":
            raise HTTPException(409, "Insufficient evidence; approval is disabled")
        return release_view(app.state.store.reject_release(release_id, principal.tenant, principal.subject, now().isoformat()))

    return app

app = create_app()
