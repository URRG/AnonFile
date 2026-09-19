"""Fail-closed development API. Synthetic data only; no release qualification."""
from __future__ import annotations
import copy
import json
import math
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import uuid4
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from app.contracts import PayloadError
from app.processing import detect_text, process_payload
from app.ingestion import IngestionError, parse_source
from app.storage_config import create_store
from app.security import Principal, configure_auth, require_roles

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

def now():
    return datetime.now(UTC)

def release_view(record):
    return ReleaseView(id=record["id"], dataset_id=record["dataset_id"], eligibility=record["card"]["eligibility"],
                       card=record["card"], review=record["review"])

def dataset_summary(data):
    return DatasetSummary(**{k: data[k] for k in ("id", "name", "created_at", "owner", "intended_use")},
                          record_count=len(data["records"]) if data["records"] is not None else 1)

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
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "Authorization"])

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc):
        return JSONResponse({"detail": "Request validation failed"}, status_code=422)

    @app.exception_handler(PayloadError)
    @app.exception_handler(IngestionError)
    async def invalid_payload(request: Request, exc):
        return JSONResponse({"detail": "Unsupported payload"}, status_code=422)

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
