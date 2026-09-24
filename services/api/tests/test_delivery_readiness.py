"""Adversarial M21 signed readiness-record checks (no delivery capability)."""
from __future__ import annotations
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.delivery_readiness import (DeliveryReadiness, DeliveryReadinessAuthority,
    DeliveryReadinessError, load_delivery_readiness_authorities)
from app.release_authorization import ReleaseAuthorizationApproval, ReleaseAuthorizationControl
from app.repository import DevelopmentStore
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import create_app
from test_control_plane_api import setup
from test_access import auth
import json
from pathlib import Path

NOW=datetime.now(UTC).replace(microsecond=0)
def signer():
    key=Ed25519PrivateKey.from_private_bytes(b"m"*32)
    raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    return DeliveryReadinessAuthority("tenant-a","m21-signer",NOW+timedelta(days=2),base64.b64encode(raw).decode())
def record(authority):
    return authority.issue(readiness_id=authority.readiness_id("release-authorization-request:v1:"+"A"*43,"once"),case_id="release-case:v1:"+"A"*43,case_digest="sha256:"+"a"*64,privacy_decision_id="privacy-decision:v1:"+"B"*43,privacy_decision_digest="sha256:"+"b"*64,request_id="release-authorization-request:v1:"+"A"*43,request_digest="sha256:"+"c"*64,scope_digest="sha256:"+"d"*64,processing_run_id="run-a",candidate_artifact_digest="sha256:"+"e"*64,rights_digest="f"*64,contract_digest="sha256:"+"1"*64,recipient_commitment="recipient-commitment:v1:"+"C"*43,purpose_code="evaluation",approval_digests=("sha256:"+"2"*64,"sha256:"+"3"*64),assessed_at=NOW,expires_at=NOW+timedelta(minutes=10))

def test_ed25519_record_is_scope_bound_source_safe_and_non_delivering():
    authority=signer(); item=record(authority); wire=item.to_record()
    assert authority.verifies(item,NOW)
    assert DeliveryReadiness.from_record(wire).digest==item.digest
    assert not {"artifact","url","token","export","transport","recipient"} & set(wire)
    assert item.posture=="DELIVERY_READINESS_ONLY"

def test_tampering_and_staleness_fail_closed():
    authority=signer(); item=record(authority)
    assert not authority.verifies(replace(item,purpose_code="other"),NOW)
    assert not authority.verifies(item,item.expires_at)
    forged=item.to_record(); forged["approval_digests"]=["sha256:"+"9"*64,"sha256:"+"3"*64]
    with pytest.raises(DeliveryReadinessError): DeliveryReadiness.from_record(forged)
    assert not authority.verifies(replace(item,assessed_at=NOW+timedelta(seconds=1)),NOW)
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last=alphabet.index(item.signature[-1]); alias=alphabet[(last & 0b111100) | ((last + 1) & 0b11)]
    assert not authority.verifies(replace(item,signature=item.signature[:-1]+alias),NOW)

def test_idempotency_identifier_is_scoped_to_request_and_key():
    authority=signer()
    assert authority.readiness_id("release-authorization-request:v1:"+"A"*43,"one") != authority.readiness_id("release-authorization-request:v1:"+"A"*43,"two")
    with pytest.raises(DeliveryReadinessError): authority.readiness_id("wrong","key")

def test_authority_config_rejects_duplicate_keys_and_non_finite_values(monkeypatch):
    monkeypatch.setenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES", '[{"tenant":"tenant-a","tenant":"tenant-b"}]')
    with pytest.raises(DeliveryReadinessError): load_delivery_readiness_authorities()

def _b64(key, private=False):
    return base64.b64encode((key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()) if private else key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))).decode()

def _approval(key, *, role, subject, request, at, suffix):
    blank="release-authorization-approval-sig:v1:"+"A"*86
    item=ReleaseAuthorizationApproval("tenant-a","release-authorization-approval:v1:"+suffix*43,request.request_id,request.case_id,"run-a",request.digest,request.scope_digest,subject,role,at,request.expires_at,blank)
    sig="release-authorization-approval-sig:v1:"+base64.urlsafe_b64encode(key.sign(b"release-authorization-approval-v1:"+json.dumps(item.canonical(),ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii"))).decode().rstrip("=")
    return ReleaseAuthorizationApproval("tenant-a",item.approval_id,item.request_id,item.case_id,item.processing_run_id,item.request_digest,item.scope_digest,subject,role,item.approved_at,item.expires_at,sig)

def _store_fixture(monkeypatch, requested_by="requester"):
    # Keep the replay tick safely in the past; CI scheduling on a second
    # boundary must not turn this idempotency regression into a future-time test.
    at=datetime.now(UTC).replace(microsecond=0)-timedelta(seconds=5); expiry=at+timedelta(minutes=20)
    server=Ed25519PrivateKey.from_private_bytes(b"r"*32); privacy=Ed25519PrivateKey.from_private_bytes(b"p"*32); release=Ed25519PrivateKey.from_private_bytes(b"q"*32)
    authz=ReleaseAuthorizationControl("tenant-a","authz",at+timedelta(days=1),_b64(server,True),(("privacy","privacy_reviewer",_b64(privacy)),("release","release_authorizer",_b64(release))))
    request=authz.issue_request(request_id="release-authorization-request:v1:"+"D"*43,case_id="release-case:v1:"+"A"*43,case_digest="sha256:"+"a"*64,privacy_decision_id="privacy-decision:v1:"+"B"*43,privacy_decision_digest="sha256:"+"b"*64,scope_digest="sha256:"+"c"*64,requested_by=requested_by,expires_at=expiry,at=at)
    case=type("Case",(),{"case_id":request.case_id,"digest":request.case_digest,"expires_at":expiry,"binding":type("Binding",(),{"candidate_artifact_digest":"sha256:"+"d"*64,"rights_digest":"e"*64,"contract_digest":"sha256:"+"f"*64,"recipient_commitment":"recipient-commitment:v1:"+"C"*43,"purpose_code":"evaluation"})()})()
    decision=type("Decision",(),{"decision_id":request.privacy_decision_id,"digest":request.privacy_decision_digest,"expires_at":expiry})()
    store=DevelopmentStore(); raw={"id":request.request_id,"kind":"release_authorization_request","tenant":"tenant-a","created_at":at.isoformat(),"expires_at":expiry.timestamp(),"size_bytes":1,"payload":{"request":request.to_record()}}
    monkeypatch.setattr(store,"get_release_authorization_request",lambda *args,**kwargs:raw); monkeypatch.setattr(store,"_live_authorization_basis",lambda **kwargs:(case,decision,"run-a"))
    approvals=[_approval(privacy,role="privacy_reviewer",subject="privacy",request=request,at=at,suffix="E"),_approval(release,role="release_authorizer",subject="release",request=request,at=at,suffix="F")]
    for item in approvals:store.controls["release_authorization_approval"][item.approval_id]={"id":item.approval_id,"kind":"release_authorization_approval","tenant":"tenant-a","created_at":at.isoformat(),"expires_at":expiry.timestamp(),"size_bytes":1,"payload":{"request_id":request.request_id,"case_id":item.case_id,"run_id":item.processing_run_id,"approval":item.to_record()}}
    readiness=signer(); return store,readiness,authz,request,approvals,at,expiry

def _readiness_data(authority,request,approvals,at,expiry,key="replay"):
    item=authority.issue(readiness_id=authority.readiness_id(request.request_id,key),case_id=request.case_id,case_digest=request.case_digest,privacy_decision_id=request.privacy_decision_id,privacy_decision_digest=request.privacy_decision_digest,request_id=request.request_id,request_digest=request.digest,scope_digest=request.scope_digest,processing_run_id="run-a",candidate_artifact_digest="sha256:"+"d"*64,rights_digest="e"*64,contract_digest="sha256:"+"f"*64,recipient_commitment="recipient-commitment:v1:"+"C"*43,purpose_code="evaluation",approval_digests=tuple(x.digest for x in approvals),assessed_at=at,expires_at=expiry)
    return {"id":item.readiness_id,"kind":"delivery_readiness","tenant":"tenant-a","created_at":at.isoformat(),"expires_at":expiry.timestamp(),"size_bytes":0,"payload":{"request_id":request.request_id,"idempotency_key":key,"readiness":item.to_record()}}

def test_store_matrix_replay_two_approvers_and_live_revocation(monkeypatch):
    store,authority,authz,request,approvals,at,expiry=_store_fixture(monkeypatch); data=_readiness_data(authority,request,approvals,at,expiry)
    saved,reused=store.record_delivery_readiness(tenant="tenant-a",data=data,actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    assert not reused
    # A clock-tick replay carries a new candidate, but persistence preserves the original signature/digest.
    replay=_readiness_data(authority,request,approvals,at+timedelta(seconds=1),expiry)
    again,reused=store.record_delivery_readiness(tenant="tenant-a",data=replay,actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    assert reused and again["id"]==saved["id"] and again["payload"]["readiness"]["digest"]==saved["payload"]["readiness"]["digest"]
    # Removing one approval is revocation: a read fails closed even though the sealed record remains stored.
    del store.controls["release_authorization_approval"][approvals[0].approval_id]
    with pytest.raises(HTTPException): store.get_delivery_readiness(saved["id"],"tenant-a",authority,object(),object(),authz)

def test_store_rejects_missing_duplicate_and_wrong_tenant_approvals(monkeypatch):
    store,authority,authz,request,approvals,at,expiry=_store_fixture(monkeypatch); data=_readiness_data(authority,request,approvals,at,expiry)
    del store.controls["release_authorization_approval"][approvals[1].approval_id]
    with pytest.raises(HTTPException): store.record_delivery_readiness(tenant="tenant-a",data=data,actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    store,authority,authz,request,approvals,at,expiry=_store_fixture(monkeypatch); data=_readiness_data(authority,request,approvals,at,expiry)
    store.controls["release_authorization_approval"]["extra"]={"id":"extra","kind":"release_authorization_approval","tenant":"tenant-a","created_at":at.isoformat(),"expires_at":expiry.timestamp(),"size_bytes":1,"payload":{"request_id":request.request_id,"case_id":approvals[0].case_id,"run_id":"run-a","approval":approvals[0].to_record()}}
    with pytest.raises(HTTPException): store.record_delivery_readiness(tenant="tenant-a",data=data,actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    with pytest.raises(HTTPException): store.record_delivery_readiness(tenant="tenant-b",data=data,actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    monkeypatch.setenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES", '[NaN]')
    with pytest.raises(DeliveryReadinessError): load_delivery_readiness_authorities()

def test_store_rechecks_requester_separation_and_stored_approval_row(monkeypatch):
    store,authority,authz,request,approvals,at,expiry=_store_fixture(monkeypatch,requested_by="privacy")
    with pytest.raises(HTTPException): store.record_delivery_readiness(tenant="tenant-a",data=_readiness_data(authority,request,approvals,at,expiry),actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)
    store,authority,authz,request,approvals,at,expiry=_store_fixture(monkeypatch)
    store.controls["release_authorization_approval"][approvals[0].approval_id]["payload"].pop("run_id")
    with pytest.raises(HTTPException): store.record_delivery_readiness(tenant="tenant-a",data=_readiness_data(authority,request,approvals,at,expiry),actor="reviewer",authority=authority,release_authority=object(),decision_authority=object(),authorization_authority=authz)

def test_endpoint_fails_closed_when_no_readiness_authority(monkeypatch):
    setup(monkeypatch,Path.cwd())
    monkeypatch.delenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES",raising=False)
    with TestClient(create_app()) as client:
        response=client.post("/release-authorization-requests/release-authorization-request:v1:"+"A"*43+"/delivery-readiness",headers={**auth("reviewer"),"Idempotency-Key":"closed"})
    assert response.status_code==409
