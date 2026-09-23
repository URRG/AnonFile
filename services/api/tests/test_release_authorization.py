"""M18 request/approval attestation and separation-of-duties regressions."""
import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.release_authorization import (ReleaseAuthorizationApproval,
    ReleaseAuthorizationControl, ReleaseAuthorizationError)
from app.repository import DevelopmentStore

D="sha256:"+"a"*64
CASE="release-case:v1:"+"A"*43
DECISION="privacy-decision:v1:"+"B"*43
REQUEST="release-authorization-request:v1:"+"C"*43

def b64(private):
    return base64.b64encode(private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode()
def public(private):
    return base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()

def control():
    global signer, privacy, authorizer
    signer=Ed25519PrivateKey.from_private_bytes(b"s"*32)
    privacy=Ed25519PrivateKey.from_private_bytes(b"p"*32)
    authorizer=Ed25519PrivateKey.from_private_bytes(b"r"*32)
    expiry=datetime.now(UTC).replace(microsecond=0)+timedelta(days=10)
    return ReleaseAuthorizationControl("tenant-a","authz-a",expiry,b64(signer),(("privacy-human","privacy_reviewer",public(privacy)),("release-human","release_authorizer",public(authorizer))))

def signed_approval(key, *, subject, role, now):
    provisional=ReleaseAuthorizationApproval("tenant-a","release-authorization-approval:v1:"+("D" if role=="privacy_reviewer" else "E")*43,REQUEST,CASE,"run-a",D,D,subject,role,now,now+timedelta(minutes=20),"release-authorization-approval-sig:v1:"+"A"*86)
    canonical=json.dumps(provisional.canonical(),ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")
    sig="release-authorization-approval-sig:v1:"+base64.urlsafe_b64encode(key.sign(b"release-authorization-approval-v1:"+canonical)).decode().rstrip("=")
    return ReleaseAuthorizationApproval(provisional.tenant,provisional.approval_id,provisional.request_id,provisional.case_id,provisional.processing_run_id,provisional.request_digest,provisional.scope_digest,provisional.approver_subject,provisional.approval_role,provisional.approved_at,provisional.expires_at,sig)

def test_ed25519_request_binds_every_scope_and_expires():
    item=control(); now=datetime.now(UTC).replace(microsecond=0)
    request=item.issue_request(request_id=REQUEST,case_id=CASE,case_digest=D,privacy_decision_id=DECISION,privacy_decision_digest=D,scope_digest=D,requested_by="requester",expires_at=now+timedelta(minutes=30),at=now)
    assert item.verifies_request(request,at=now)
    altered=request.to_record();altered["scope_digest"]="sha256:"+"b"*64
    with pytest.raises(ReleaseAuthorizationError): type(request).from_record(altered)
    assert not item.verifies_request(request,at=request.expires_at)

def test_human_signatures_are_role_bound_and_not_interchangeable():
    item=control(); now=datetime.now(UTC).replace(microsecond=0)
    approval=signed_approval(privacy,subject="privacy-human",role="privacy_reviewer",now=now)
    assert item.verify_approval(approval,at=now)
    wrong=signed_approval(privacy,subject="privacy-human",role="release_authorizer",now=now)
    assert not item.verify_approval(wrong,at=now)

def test_control_rejects_one_human_assigned_both_required_roles():
    private=Ed25519PrivateKey.from_private_bytes(b"x"*32)
    expiry=datetime.now(UTC).replace(microsecond=0)+timedelta(days=10)
    with pytest.raises(ReleaseAuthorizationError):
        ReleaseAuthorizationControl("tenant-a","authz-a",expiry,b64(private),(("same","privacy_reviewer",public(private)),("same","release_authorizer",public(private))))

def test_control_rejects_one_human_key_split_between_two_subjects_or_the_server():
    private=Ed25519PrivateKey.from_private_bytes(b"x"*32)
    other=Ed25519PrivateKey.from_private_bytes(b"y"*32)
    expiry=datetime.now(UTC).replace(microsecond=0)+timedelta(days=10)
    with pytest.raises(ReleaseAuthorizationError):
        ReleaseAuthorizationControl("tenant-a","authz-a",expiry,b64(other),(("privacy","privacy_reviewer",public(private)),("release","release_authorizer",public(private))))
    with pytest.raises(ReleaseAuthorizationError):
        ReleaseAuthorizationControl("tenant-a","authz-a",expiry,b64(private),(("privacy","privacy_reviewer",public(private)),("release","release_authorizer",public(other))))

def test_repository_rejects_request_outliving_live_case_or_decision(monkeypatch):
    authority=control(); instant=datetime.now(UTC).replace(microsecond=0)
    case=type("Case",(),{"case_id":CASE,"digest":D,"expires_at":instant+timedelta(minutes=5),"canonical":lambda self:{"case":"a"}})()
    reason=type("Reason",(),{"value":"INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED"})()
    decision=type("Decision",(),{"decision_id":DECISION,"digest":D,"expires_at":instant+timedelta(minutes=5),"canonical":lambda self:{"decision":"a"},"decision":type("Inner",(),{"outcome":type("Outcome",(),{"value":"INSUFFICIENT_EVIDENCE"})(),"reasons":(reason,)})()})()
    store=DevelopmentStore(); monkeypatch.setattr(store,"_live_authorization_basis",lambda **_: (case,decision,"run-a"))
    item=authority.issue_request(request_id=REQUEST,case_id=CASE,case_digest=D,privacy_decision_id=DECISION,privacy_decision_digest=D,scope_digest=store._authorization_scope_digest(case,decision),requested_by="requester",expires_at=instant+timedelta(minutes=10),at=instant)
    record={"id":item.request_id,"kind":"release_authorization_request","tenant":"tenant-a","created_at":instant.isoformat(),"expires_at":item.expires_at.timestamp(),"size_bytes":0,"payload":{"case_id":CASE,"decision_id":DECISION,"run_id":"run-a","idempotency_key":"m18-temporal","request":item.to_record()}}
    with pytest.raises(HTTPException) as caught:
        store.record_release_authorization_request(tenant="tenant-a",data=record,actor="requester",authority=authority,release_authority=object(),decision_authority=object())
    assert caught.value.status_code==503

def test_repository_rejects_future_or_outliving_human_approval(monkeypatch):
    authority=control(); instant=datetime.now(UTC).replace(microsecond=0)
    request=authority.issue_request(request_id=REQUEST,case_id=CASE,case_digest=D,privacy_decision_id=DECISION,privacy_decision_digest=D,scope_digest=D,requested_by="requester",expires_at=instant+timedelta(minutes=5),at=instant)
    request_data={"id":REQUEST,"kind":"release_authorization_request","tenant":"tenant-a","created_at":instant.isoformat(),"expires_at":request.expires_at.timestamp(),"size_bytes":0,"payload":{"case_id":CASE,"decision_id":DECISION,"run_id":"run-a","idempotency_key":"m18-temporal-approval","request":request.to_record()}}
    store=DevelopmentStore(); monkeypatch.setattr(store,"get_release_authorization_request",lambda *args,**kwargs: request_data)
    future=signed_approval(privacy,subject="privacy-human",role="privacy_reviewer",now=instant+timedelta(seconds=1))
    # Re-sign an approval whose expiry is also outside the request boundary.
    provisional=ReleaseAuthorizationApproval("tenant-a",future.approval_id,REQUEST,CASE,"run-a",D,D,"privacy-human","privacy_reviewer",instant+timedelta(seconds=1),instant+timedelta(minutes=10),"release-authorization-approval-sig:v1:"+"A"*86)
    canonical=json.dumps(provisional.canonical(),ensure_ascii=True,sort_keys=True,separators=(",",":")).encode("ascii")
    approval=ReleaseAuthorizationApproval(provisional.tenant,provisional.approval_id,provisional.request_id,provisional.case_id,provisional.processing_run_id,provisional.request_digest,provisional.scope_digest,provisional.approver_subject,provisional.approval_role,provisional.approved_at,provisional.expires_at,"release-authorization-approval-sig:v1:"+base64.urlsafe_b64encode(privacy.sign(b"release-authorization-approval-v1:"+canonical)).decode().rstrip("="))
    record={"id":approval.approval_id,"kind":"release_authorization_approval","tenant":"tenant-a","created_at":instant.isoformat(),"expires_at":approval.expires_at.timestamp(),"size_bytes":0,"payload":{"request_id":REQUEST,"case_id":CASE,"run_id":"run-a","approval":approval.to_record()}}
    with pytest.raises(HTTPException) as caught:
        store.record_release_authorization_approval(request_id=REQUEST,tenant="tenant-a",data=record,actor="privacy-human",authority=authority,release_authority=object(),decision_authority=object())
    assert caught.value.status_code==503
