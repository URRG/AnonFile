"""Demo API for an auditable anonymisation release workflow.

This module intentionally keeps persistence and recognisers replaceable. Raw inputs are
kept only in process memory; production deployments must use encrypted storage and KMS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import os
from collections import Counter
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator


class ReleaseMode(str, Enum):
    EXTERNAL_ANONYMIZED = "external_anonymized"
    RESTRICTED_PSEUDONYMIZED = "restricted_pseudonymized"


class Eligibility(str, Enum):
    BLOCKED = "BLOCKED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED_RESTRICTED = "APPROVED_RESTRICTED"
    APPROVED_ANONYMIZED = "APPROVED_ANONYMIZED"


class DatasetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    content: str | None = Field(default=None, max_length=2_000_000)
    records: list[dict[str, Any]] | None = Field(default=None, max_length=10_000)
    owner: str = Field(default="unknown", max_length=160)
    jurisdiction: str = Field(default="unspecified", max_length=80)
    intended_use: str = Field(default="analytics", max_length=160)
    recipient: str = Field(default="internal", max_length=160)
    retention_days: int = Field(default=30, ge=1, le=3650)

    @field_validator("records")
    @classmethod
    def require_payload(cls, value: list[dict[str, Any]] | None, info: Any) -> list[dict[str, Any]] | None:
        if not value and not info.data.get("content"):
            raise ValueError("provide content or records")
        return value


class DatasetSummary(BaseModel):
    id: str
    name: str
    created_at: datetime
    record_count: int
    owner: str
    intended_use: str


class ReleaseCreate(BaseModel):
    dataset_id: str
    release_mode: ReleaseMode = ReleaseMode.EXTERNAL_ANONYMIZED
    policy_version: str = Field(default="baseline-v1", max_length=80)
    allow_review: bool = True


class ReviewDecision(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    reviewer: str = Field(min_length=1, max_length=160)
    note: str = Field(default="", max_length=1000)


class Finding(BaseModel):
    entity_type: str
    severity: str
    count: int
    confidence: float


class ScoreCard(BaseModel):
    privacy_risk: int = Field(ge=0, le=100)
    utility_legibility: int = Field(ge=0, le=100)
    subjectivity: int = Field(ge=0, le=100)
    sensitivity: str
    confidence: int = Field(ge=0, le=100)


class ReleaseCard(BaseModel):
    release_id: str
    dataset_id: str
    generated_at: datetime
    policy_version: str
    release_mode: ReleaseMode
    eligibility: Eligibility
    scores: ScoreCard
    findings: list[Finding]
    gates: list[str]
    controls: list[str]
    output_sha256: str
    signature: str
    disclaimer: str


class ReleaseView(BaseModel):
    id: str
    dataset_id: str
    status: str
    eligibility: Eligibility
    output: str | list[dict[str, Any]]
    card: ReleaseCard
    review: dict[str, Any] | None = None


DATASETS: dict[str, dict[str, Any]] = {}
RELEASES: dict[str, dict[str, Any]] = {}
SIGNING_KEY = secrets.token_bytes(32)

# A conservative first pass: production must replace this with versioned recognisers.
PATTERNS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "CREDENTIAL": (re.compile(r"(?i)\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*['\"]?[^\s,'\"]+"), "critical", "[REDACTED_CREDENTIAL]"),
    "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "high", "EMAIL"),
    "PHONE": (re.compile(r"(?<!\w)(?:\+?\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -]?)?\d{3,5}[ -]\d{4}(?!\w)"), "high", "PHONE"),
    "AADHAAR": (re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"), "critical", "[REDACTED_AADHAAR]"),
    "PAN": (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "high", "[REDACTED_PAN]"),
    "CARD": (re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)"), "critical", "[REDACTED_CARD]"),
    "IP_ADDRESS": (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "medium", "IP_ADDRESS"),
}
SUBJECTIVE = re.compile(r"(?i)\b(?:i think|i believe|in my opinion|probably|perhaps|should|best|worst|great|terrible)\b")


def now() -> datetime:
    return datetime.now(UTC)


def serialise_records(records: list[dict[str, Any]] | None, content: str | None) -> str:
    return content if content is not None else json.dumps(records or [], sort_keys=True, ensure_ascii=False)


def anonymize(text: str, mode: ReleaseMode) -> tuple[str, list[Finding], list[str]]:
    findings: list[Finding] = []
    gates: list[str] = []
    counters: Counter[str] = Counter()
    replacements: dict[str, str] = {}

    for kind, (pattern, severity, default) in PATTERNS.items():
        def replace(match: re.Match[str], kind: str = kind, default: str = default) -> str:
            value = match.group(0)
            counters[kind] += 1
            if kind == "CREDENTIAL":
                gates.append("credential detected and suppressed; external release blocked")
                return default
            if mode == ReleaseMode.EXTERNAL_ANONYMIZED:
                # Deliberately not stable across documents/releases.
                return f"[{default}]"
            key = f"{kind}:{value.lower()}"
            if key not in replacements:
                replacements[key] = f"{default}_{len(replacements) + 1:04d}"
            return f"[{replacements[key]}]"
        text = pattern.sub(replace, text)

    for kind, (_, severity, _) in PATTERNS.items():
        if counters[kind]:
            findings.append(Finding(entity_type=kind, severity=severity, count=counters[kind], confidence=0.92 if kind != "IP_ADDRESS" else 0.80))
    return text, findings, list(dict.fromkeys(gates))


def build_card(release_id: str, dataset_id: str, output: str, findings: list[Finding], gates: list[str], request: ReleaseCreate) -> ReleaseCard:
    severity = {"critical": 30, "high": 14, "medium": 6}
    detected_risk = min(85, sum(severity[f.severity] * f.count for f in findings))
    credential = any(f.entity_type == "CREDENTIAL" for f in findings)
    sensitivity = "Restricted" if any(f.severity == "critical" for f in findings) else "Confidential" if findings else "Internal"
    utility = max(35, 100 - min(55, sum(f.count for f in findings) * 3))
    subjectivity = min(100, len(SUBJECTIVE.findall(output)) * 15)
    confidence = 88 if findings else 70
    if credential:
        eligibility = Eligibility.BLOCKED
    elif request.release_mode == ReleaseMode.RESTRICTED_PSEUDONYMIZED:
        eligibility = Eligibility.APPROVED_RESTRICTED
        gates.append("pseudonymized output requires named-recipient restricted controls")
    elif detected_risk > 60:
        eligibility = Eligibility.REVIEW_REQUIRED if request.allow_review else Eligibility.BLOCKED
        gates.append("high sensitivity requires human review")
    else:
        eligibility = Eligibility.APPROVED_ANONYMIZED
        gates.append("residual scan passed baseline policy")
    encoded = output.encode()
    digest = hashlib.sha256(encoded).hexdigest()
    payload = f"{release_id}:{dataset_id}:{digest}:{request.policy_version}".encode()
    signature = hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()
    return ReleaseCard(release_id=release_id, dataset_id=dataset_id, generated_at=now(), policy_version=request.policy_version,
        release_mode=request.release_mode, eligibility=eligibility,
        scores=ScoreCard(privacy_risk=detected_risk, utility_legibility=utility, subjectivity=subjectivity, sensitivity=sensitivity, confidence=confidence),
        findings=findings, gates=list(dict.fromkeys(gates)),
        controls=["policy-versioned", "independent-release-card", "raw-data-not-logged"] + (["named-recipient", "expiry-required"] if request.release_mode == ReleaseMode.RESTRICTED_PSEUDONYMIZED else ["no-mapping-retained"]),
        output_sha256=digest, signature=signature,
        disclaimer="A score is evidence for review, not a legal determination of anonymity or compliance.")


app = FastAPI(title="AnonFlow API", version="0.1.0", description="Policy-driven anonymisation demo API")
allowed_origins = [origin.strip() for origin in os.getenv("WEB_ORIGIN", "http://localhost:3000,http://localhost:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "anonflow-api"}


@app.post("/datasets", response_model=DatasetSummary, status_code=status.HTTP_201_CREATED)
def create_dataset(request: DatasetCreate) -> DatasetSummary:
    dataset_id = str(uuid4())
    DATASETS[dataset_id] = {"id": dataset_id, **request.model_dump(), "created_at": now()}
    return DatasetSummary(id=dataset_id, name=request.name, created_at=DATASETS[dataset_id]["created_at"], record_count=len(request.records or []), owner=request.owner, intended_use=request.intended_use)


@app.get("/datasets", response_model=list[DatasetSummary])
def list_datasets() -> list[DatasetSummary]:
    return [DatasetSummary(id=d["id"], name=d["name"], created_at=d["created_at"], record_count=len(d["records"] or []), owner=d["owner"], intended_use=d["intended_use"]) for d in DATASETS.values()]


@app.post("/releases", response_model=ReleaseView, status_code=status.HTTP_201_CREATED)
def create_release(request: ReleaseCreate) -> ReleaseView:
    dataset = DATASETS.get(request.dataset_id)
    if not dataset:
        raise HTTPException(404, "dataset not found")
    source = serialise_records(dataset["records"], dataset["content"])
    output, findings, gates = anonymize(source, request.release_mode)
    release_id = str(uuid4())
    card = build_card(release_id, request.dataset_id, output, findings, gates, request)
    record = {"id": release_id, "dataset_id": request.dataset_id, "output": output, "card": card, "review": None}
    RELEASES[release_id] = record
    return ReleaseView(id=release_id, dataset_id=request.dataset_id, status="completed", eligibility=card.eligibility, output=output, card=card)


@app.get("/releases/{release_id}", response_model=ReleaseView)
def get_release(release_id: str) -> ReleaseView:
    record = RELEASES.get(release_id)
    if not record:
        raise HTTPException(404, "release not found")
    card: ReleaseCard = record["card"]
    return ReleaseView(id=release_id, dataset_id=record["dataset_id"], status="completed", eligibility=card.eligibility, output=record["output"], card=card, review=record["review"])


@app.get("/releases/{release_id}/card", response_model=ReleaseCard)
def get_release_card(release_id: str) -> ReleaseCard:
    if release_id not in RELEASES:
        raise HTTPException(404, "release not found")
    return RELEASES[release_id]["card"]


@app.post("/reviews/{release_id}/decision", response_model=ReleaseView)
def review_release(release_id: str, request: ReviewDecision) -> ReleaseView:
    record = RELEASES.get(release_id)
    if not record:
        raise HTTPException(404, "release not found")
    card: ReleaseCard = record["card"]
    if card.eligibility != Eligibility.REVIEW_REQUIRED:
        raise HTTPException(409, "release is not awaiting review")
    if request.decision == "approve":
        card.eligibility = Eligibility.APPROVED_RESTRICTED
        card.gates.append("human reviewer approved restricted delivery")
    else:
        card.eligibility = Eligibility.BLOCKED
        card.gates.append("human reviewer rejected release")
    record["review"] = {**request.model_dump(), "decided_at": now().isoformat()}
    return ReleaseView(id=release_id, dataset_id=record["dataset_id"], status="completed", eligibility=card.eligibility, output=record["output"], card=card, review=record["review"])
