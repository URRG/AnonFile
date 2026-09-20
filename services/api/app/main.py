"""Fail-closed development API. Synthetic data only; no release qualification."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
from app.processing import detect_text, process_payload
from app.ingestion import IngestionError, parse_source
from app.storage_config import create_store
from app.security import Principal, configure_auth, require_roles
from app.policies import PolicyError, PolicyProfile, PolicyRule, PolicySnapshot
from app.rights import RightsError, RightsProfile, evaluate_rights
from app.runs import ProcessingPlan, RunError, RunRegistry
from app.candidate import CandidateArtifact, CandidateError, LedgerAction, PayloadKind, SchemaContract
from app.rules_policy_execution import (ActualOutputOperation as PolicyOutputOperation,
                                        RULES_LABEL_TO_CATEGORY, RULES_POLICY_COVERED_CATEGORIES, RulesPolicyExecutionError,
                                        execute_rules_policy)
from app.residual_eval import (CandidateMetadata as ResidualCandidateMetadata, DetectorIdentity,
                               DetectorResult, EvaluationError, EvaluationProfile,
                               EvidenceStatus, candidate_schema_digest, evaluate_candidate)
from app.qualification import (CandidateBinding, CategoryMeasurement, CategoryThreshold,
                               EvaluationReport as QualificationReport, QualificationCriteria,
                               QualificationError, qualify)
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
        # M5 execution provenance was not persisted in M2b/M3 records.  Keep
        # those records inspectable but make their inability to run explicit;
        # reconstructing an executor/language from an old request digest would
        # fabricate evidence.
        if method_id is None and language is None:
            method_id, language = "legacy-unavailable", "und"
        if (payload["state"] not in {"REGISTERED", "RUNNING", "CANDIDATE", "QUARANTINED", "FAILED"}
                or type(payload["attempts"]) is not int or not 0 <= payload["attempts"] <= 3
                or method_id not in {"rules-v1", "legacy-unavailable"} or type(language) is not str
                or not isinstance(payload["events"], list) or not 1 <= len(payload["events"]) <= 16):
            raise ValueError
        return ProcessingRunView(id=record["id"], dataset_id=payload["dataset_id"], state=payload["state"],
                                 attempts=payload["attempts"], request_digest=payload["request_digest"],
                                 method_id=method_id, language=language,
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

def _residual_detector(candidate: str | list[dict[str, Any]]) -> DetectorResult:
    """Rules-based residual pass limited to independently policy-qualified families.

    The new contextual health, business and quasi rules are processing safety
    measures, not residual-evaluation evidence.  They are deliberately
    ignored here so this adapter cannot assert all-taxonomy assessment.
    """
    counts = {category: 0 for category in sorted(RULES_POLICY_COVERED_CATEGORIES)}
    def inspect(value: Any, observed: set[str]):
        if type(value) is str:
            for finding in detect_text(value):
                category = RULES_LABEL_TO_CATEGORY.get(finding.entity_type)
                if category is None:
                    raise RulesPolicyExecutionError()
                if category in counts:
                    observed.add(category)
        elif type(value) is dict:
            for child in value.values():
                inspect(child, observed)
        elif type(value) is list:
            for child in value:
                inspect(child, observed)
    units = [candidate] if type(candidate) is str else candidate
    for unit in units:
        observed: set[str] = set()
        inspect(unit, observed)
        for family in observed:
            counts[family] += 1
    return DetectorResult(residual_counts=counts, scanned_units=len(units))

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
        if request.method_id != "rules-v1":
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
                   "language": request.language,
                   "rights_digest": profile.digest, "recipient": request.recipient,
                   "purpose": request.purpose,
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

    @app.post("/processing-runs/{run_id}/residual-evaluations", response_model=ResidualEvaluationView, status_code=201)
    def create_residual_evaluation(run_id: str, principal: Principal = Depends(require_roles("reviewer"))):
        candidate, run = app.state.store.private_candidate_for_run(run_id, principal.tenant)
        private = candidate["payload"]
        body = private["body"]
        profile = EvaluationProfile.create(profile_id="m3-residual", version="rules-v1",
                                           required_categories=("PII", "HEALTH_SENSITIVE", "PAYMENT", "CREDENTIAL", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER"))
        detector = DetectorIdentity(detector_id="m3-rules-residual", config_digest="sha256:" + hashlib.sha256(b"m3-rules-residual-v1").hexdigest())
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
