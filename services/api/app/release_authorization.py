"""M18 signed, non-delivery release-authorization request controls.

This module deliberately models *requests and human attestations*, not a
release.  A request can only be rooted in a separately verified, live privacy
decision/case pair.  It contains opaque digests and identifiers only; there is
no artifact locator, credential, recipient value, or delivery capability.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_REQUEST_ID = re.compile(r"release-authorization-request:v1:[A-Za-z0-9_-]{43}\Z")
_APPROVAL_ID = re.compile(r"release-authorization-approval:v1:[A-Za-z0-9_-]{43}\Z")
_AUTHORITY_ID = re.compile(r"release-authorization-authority:v1:[A-Za-z0-9_-]{43}\Z")
_REQUEST_SIG = re.compile(r"release-authorization-request-sig:v1:[A-Za-z0-9_-]{86}\Z")
_APPROVAL_SIG = re.compile(r"release-authorization-approval-sig:v1:[A-Za-z0-9_-]{86}\Z")
_ROLES = frozenset({"privacy_reviewer", "release_authorizer"})


class ReleaseAuthorizationError(ValueError):
    def __init__(self): super().__init__("Invalid release authorization input")


def _fail(): raise ReleaseAuthorizationError()
def _canon(value):
    try: return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError): _fail()
def _id(value):
    if type(value) is not str or not _IDENTIFIER.fullmatch(value): _fail()
    return value
def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value): _fail()
    return value
def _time(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None: _fail()
    value = value.astimezone(UTC)
    if value.microsecond: _fail()
    return value
def _instant(value): return value.isoformat().replace("+00:00", "Z")
def _key(value, private):
    if type(value) is not str or len(value) != 44: _fail()
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value: _fail()
        return Ed25519PrivateKey.from_private_bytes(raw) if private else Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, UnicodeError): _fail()


@dataclass(frozen=True, slots=True)
class ReleaseAuthorizationRequest:
    tenant: str
    request_id: str
    case_id: str
    case_digest: str
    privacy_decision_id: str
    privacy_decision_digest: str
    scope_digest: str
    authority_id: str
    issuer_key_id: str
    requested_by: str
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    posture: str = "PENDING_INDEPENDENT_AUTHORIZATION"
    digest: str = field(init=False)

    def __post_init__(self):
        if type(self) is not ReleaseAuthorizationRequest: _fail()
        object.__setattr__(self, "tenant", _id(self.tenant)); object.__setattr__(self, "requested_by", _id(self.requested_by))
        if type(self.request_id) is not str or not _REQUEST_ID.fullmatch(self.request_id): _fail()
        if type(self.case_id) is not str or not self.case_id.startswith("release-case:v1:"): _fail()
        if type(self.privacy_decision_id) is not str or not self.privacy_decision_id.startswith("privacy-decision:v1:"): _fail()
        for name in ("case_digest", "privacy_decision_digest", "scope_digest"): object.__setattr__(self, name, _digest(getattr(self, name)))
        if type(self.authority_id) is not str or not _AUTHORITY_ID.fullmatch(self.authority_id): _fail()
        object.__setattr__(self, "issuer_key_id", _id(self.issuer_key_id)); object.__setattr__(self, "issued_at", _time(self.issued_at)); object.__setattr__(self, "expires_at", _time(self.expires_at))
        if self.expires_at <= self.issued_at or self.posture != "PENDING_INDEPENDENT_AUTHORIZATION" or type(self.signature) is not str or not _REQUEST_SIG.fullmatch(self.signature): _fail()
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(_canon({**self.canonical(), "signature": self.signature})).hexdigest())

    def canonical(self):
        return {"authority_id": self.authority_id, "case_digest": self.case_digest, "case_id": self.case_id,
                "expires_at": _instant(self.expires_at), "issued_at": _instant(self.issued_at), "issuer_key_id": self.issuer_key_id,
                "privacy_decision_digest": self.privacy_decision_digest, "privacy_decision_id": self.privacy_decision_id,
                "posture": self.posture, "requested_by": self.requested_by, "request_id": self.request_id,
                "scope_digest": self.scope_digest, "tenant": self.tenant}
    def to_record(self): return {**self.canonical(), "digest": self.digest, "signature": self.signature}
    @classmethod
    def from_record(cls, value):
        try:
            expected={"authority_id","case_digest","case_id","digest","expires_at","issued_at","issuer_key_id","privacy_decision_digest","privacy_decision_id","posture","requested_by","request_id","scope_digest","signature","tenant"}
            if type(value) is not dict or set(value) != expected: _fail()
            item=cls(value["tenant"],value["request_id"],value["case_id"],value["case_digest"],value["privacy_decision_id"],value["privacy_decision_digest"],value["scope_digest"],value["authority_id"],value["issuer_key_id"],value["requested_by"],datetime.fromisoformat(value["issued_at"].replace("Z","+00:00")),datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")),value["signature"],value["posture"])
            if item.digest != value["digest"]: _fail()
            return item
        except (KeyError, TypeError, ValueError, ReleaseAuthorizationError): _fail()


@dataclass(frozen=True, slots=True)
class ReleaseAuthorizationApproval:
    tenant: str
    approval_id: str
    request_id: str
    case_id: str
    processing_run_id: str
    request_digest: str
    scope_digest: str
    approver_subject: str
    approval_role: str
    approved_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    digest: str = field(init=False)

    def __post_init__(self):
        if type(self) is not ReleaseAuthorizationApproval: _fail()
        object.__setattr__(self,"tenant",_id(self.tenant)); object.__setattr__(self,"approver_subject",_id(self.approver_subject))
        if type(self.approval_id) is not str or not _APPROVAL_ID.fullmatch(self.approval_id): _fail()
        if type(self.request_id) is not str or not _REQUEST_ID.fullmatch(self.request_id): _fail()
        if type(self.case_id) is not str or not self.case_id.startswith("release-case:v1:"): _fail()
        object.__setattr__(self,"processing_run_id",_id(self.processing_run_id))
        object.__setattr__(self,"request_digest",_digest(self.request_digest)); object.__setattr__(self,"scope_digest",_digest(self.scope_digest))
        if self.approval_role not in _ROLES: _fail()
        object.__setattr__(self,"approved_at",_time(self.approved_at)); object.__setattr__(self,"expires_at",_time(self.expires_at))
        if self.expires_at <= self.approved_at or type(self.signature) is not str or not _APPROVAL_SIG.fullmatch(self.signature): _fail()
        object.__setattr__(self,"digest","sha256:"+hashlib.sha256(_canon({**self.canonical(),"signature":self.signature})).hexdigest())
    def canonical(self):
        return {"approval_id":self.approval_id,"approval_role":self.approval_role,"approved_at":_instant(self.approved_at),"approver_subject":self.approver_subject,"case_id":self.case_id,"expires_at":_instant(self.expires_at),"processing_run_id":self.processing_run_id,"request_digest":self.request_digest,"request_id":self.request_id,"scope_digest":self.scope_digest,"tenant":self.tenant}
    def to_record(self): return {**self.canonical(),"digest":self.digest,"signature":self.signature}
    @classmethod
    def from_record(cls,value):
        try:
            expected={"approval_id","approval_role","approved_at","approver_subject","case_id","digest","expires_at","processing_run_id","request_digest","request_id","scope_digest","signature","tenant"}
            if type(value) is not dict or set(value)!=expected:_fail()
            item=cls(value["tenant"],value["approval_id"],value["request_id"],value["case_id"],value["processing_run_id"],value["request_digest"],value["scope_digest"],value["approver_subject"],value["approval_role"],datetime.fromisoformat(value["approved_at"].replace("Z","+00:00")),datetime.fromisoformat(value["expires_at"].replace("Z","+00:00")),value["signature"])
            if item.digest!=value["digest"]:_fail()
            return item
        except (KeyError,TypeError,ValueError,ReleaseAuthorizationError):_fail()


@dataclass(frozen=True, slots=True)
class ReleaseAuthorizationControl:
    tenant: str
    issuer_key_id: str
    expires_at: datetime
    private_key_b64: str = field(repr=False, compare=False)
    approvers: tuple[tuple[str, str, str], ...] = field(repr=False)
    authority_id: str = field(init=False)
    _key: Ed25519PrivateKey = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self) is not ReleaseAuthorizationControl: _fail()
        tenant,issuer,expiry,key=_id(self.tenant),_id(self.issuer_key_id),_time(self.expires_at),_key(self.private_key_b64,True)
        now=datetime.now(UTC).replace(microsecond=0)
        if expiry<=now or (expiry-now).total_seconds()>366*24*3600 or type(self.approvers) is not tuple or not self.approvers: _fail()
        normalized=[]
        for subject,role,public_key in self.approvers:
            normalized.append((_id(subject), role, public_key)); _key(public_key,False)
        fingerprints={hashlib.sha256(base64.b64decode(public_key,validate=True)).hexdigest() for _,_,public_key in normalized}
        public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode("ascii")
        if (len(normalized)>32 or len(set(normalized))!=len(normalized) or len({x[0] for x in normalized})!=len(normalized)
                or len(fingerprints)!=len(normalized) or public in {value for _,_,value in normalized}
                or {x[1] for x in normalized} != _ROLES): _fail()
        aid="release-authorization-authority:v1:"+base64.urlsafe_b64encode(hashlib.sha256(_canon({"schema":"release-authorization-ed25519-v1","tenant":tenant,"issuer_key_id":issuer,"expires_at":_instant(expiry),"public_key":public,"approvers":[{"subject":s,"role":r,"public_key":p} for s,r,p in sorted(normalized)]})).digest()).decode("ascii").rstrip("=")
        object.__setattr__(self,"tenant",tenant);object.__setattr__(self,"issuer_key_id",issuer);object.__setattr__(self,"expires_at",expiry);object.__setattr__(self,"_key",key);object.__setattr__(self,"approvers",tuple(sorted(normalized)));object.__setattr__(self,"authority_id",aid)
    def is_active(self,*,at=None):
        try:return _time(datetime.now(UTC).replace(microsecond=0) if at is None else at)<self.expires_at
        except ReleaseAuthorizationError:return False
    def request_id(self,*,case_id,idempotency_key):
        if type(case_id) is not str or not case_id.startswith("release-case:v1:") or type(idempotency_key) is not str or not 1<=len(idempotency_key)<=200 or not idempotency_key.isascii() or any(x.isspace() for x in idempotency_key):_fail()
        raw=self._key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        return "release-authorization-request:v1:"+base64.urlsafe_b64encode(hmac.new(raw,b"m18-request-id-v1:\x00"+_canon({"case_id":case_id,"key":idempotency_key}),hashlib.sha256).digest()).decode("ascii").rstrip("=")
    def issue_request(self,*,request_id,case_id,case_digest,privacy_decision_id,privacy_decision_digest,scope_digest,requested_by,expires_at,at):
        moment,expiry=_time(at),_time(expires_at)
        if not self.is_active(at=moment) or expiry>self.expires_at:_fail()
        provisional=ReleaseAuthorizationRequest(self.tenant,request_id,case_id,case_digest,privacy_decision_id,privacy_decision_digest,scope_digest,self.authority_id,self.issuer_key_id,requested_by,moment,expiry,"release-authorization-request-sig:v1:"+"A"*86)
        sig="release-authorization-request-sig:v1:"+base64.urlsafe_b64encode(self._key.sign(b"release-authorization-request-v1:"+_canon(provisional.canonical()))).decode("ascii").rstrip("=")
        return ReleaseAuthorizationRequest(self.tenant,request_id,case_id,case_digest,privacy_decision_id,privacy_decision_digest,scope_digest,self.authority_id,self.issuer_key_id,requested_by,moment,expiry,sig)
    def verifies_request(self,item,*,at):
        try:
            moment=_time(at)
            if type(item) is not ReleaseAuthorizationRequest or not self.is_active(at=moment) or item.tenant!=self.tenant or item.authority_id!=self.authority_id or item.issuer_key_id!=self.issuer_key_id or item.expires_at<=moment or item.expires_at>self.expires_at:return False
            self._key.public_key().verify(base64.urlsafe_b64decode(item.signature.split(":",2)[2]+"=="),b"release-authorization-request-v1:"+_canon(item.canonical()));return True
        except (InvalidSignature,ValueError,UnicodeError,ReleaseAuthorizationError):return False
    def verify_approval(self,item,*,at):
        try:
            moment=_time(at)
            if type(item) is not ReleaseAuthorizationApproval or item.tenant!=self.tenant or item.expires_at<=moment or item.expires_at>self.expires_at:return False
            allowed={(s,r):p for s,r,p in self.approvers}; public=allowed.get((item.approver_subject,item.approval_role))
            if public is None:return False
            _key(public,False).verify(base64.urlsafe_b64decode(item.signature.split(":",2)[2]+"=="),b"release-authorization-approval-v1:"+_canon(item.canonical()));return True
        except (InvalidSignature,ValueError,UnicodeError,ReleaseAuthorizationError):return False


def load_release_authorization_controls():
    """Load explicit development-only signer and human verifier bindings.

    Missing configuration intentionally means the authorization foundation is
    unavailable.  The web-facing caller identity is checked again by the API;
    this loader only establishes which *independent* human signatures count.
    """
    raw=os.getenv("ANONFLOW_RELEASE_AUTHORIZATION_AUTHORITIES", "")
    if not raw:return ()
    if len(raw.encode("utf-8"))>65536:_fail()
    try:
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError
                result[key]=value
            return result
        entries=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries)>64:_fail()
        controls=[]; tenants=set()
        for item in entries:
            if type(item) is not dict or set(item)!={"tenant","issuer_key_id","expires_at","private_key","approvers"}:_fail()
            approvers=item["approvers"]
            if type(approvers) is not list or not approvers:_fail()
            pairs=[]
            for approver in approvers:
                if type(approver) is not dict or set(approver)!={"subject","approval_role","public_key"}:_fail()
                pairs.append((approver["subject"],approver["approval_role"],approver["public_key"]))
            control=ReleaseAuthorizationControl(item["tenant"],item["issuer_key_id"],datetime.fromisoformat(item["expires_at"].replace("Z","+00:00")),item["private_key"],tuple(pairs))
            if control.tenant in tenants:_fail()
            tenants.add(control.tenant);controls.append(control)
        return tuple(controls)
    except (TypeError,ValueError,UnicodeError,ReleaseAuthorizationError):_fail()


def control_for_tenant(controls, *, tenant, at=None):
    try:
        matches=[item for item in controls if type(item) is ReleaseAuthorizationControl and item.tenant==tenant and item.is_active(at=at)]
        if len(matches)!=1:_fail()
        return matches[0]
    except ReleaseAuthorizationError:_fail()
