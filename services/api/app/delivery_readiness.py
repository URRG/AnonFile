"""M21 source-safe delivery-readiness attestation.

This is deliberately a *control-plane observation*.  A positive record says
only that the exact live M14 case, clean M15 holding and both M18 signatures
were checked at one instant.  It has no artifact locator, URL, token, export
operation, recipient value, or transport instruction.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_ID=re.compile(r"delivery-readiness:v1:[A-Za-z0-9_-]{43}\Z"); _SIG=re.compile(r"delivery-readiness-sig:v1:[A-Za-z0-9_-]{86}\Z"); _D=re.compile(r"sha256:[0-9a-f]{64}\Z"); _I=re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z"); _CASE=re.compile(r"release-case:v1:[A-Za-z0-9_-]{43}\Z"); _DECISION=re.compile(r"privacy-decision:v1:[A-Za-z0-9_-]{43}\Z"); _REQUEST=re.compile(r"release-authorization-request:v1:[A-Za-z0-9_-]{43}\Z"); _RECIPIENT=re.compile(r"recipient-commitment:v1:[A-Za-z0-9_-]{43}\Z")
class DeliveryReadinessError(ValueError):
    def __init__(self): super().__init__("Invalid delivery readiness input")
def _fail(): raise DeliveryReadinessError()
def _canon(v):
    try:return json.dumps(v,ensure_ascii=True,allow_nan=False,sort_keys=True,separators=(",",":")).encode("ascii")
    except (TypeError,ValueError,UnicodeError,OverflowError,RecursionError):_fail()
def _time(v):
    if type(v) is not datetime or v.tzinfo is None or v.utcoffset() is None:_fail()
    v=v.astimezone(UTC)
    if v.microsecond:_fail()
    return v
def _instant(v):return v.isoformat().replace("+00:00","Z")
def _id(v):
    if type(v) is not str or not _I.fullmatch(v):_fail()
    return v
def _key(v):
    if type(v) is not str or len(v)!=44:_fail()
    try:
        raw=base64.b64decode(v,validate=True)
        if len(raw)!=32 or base64.b64encode(raw).decode()!=v:_fail()
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError,UnicodeError):_fail()
def _signature_bytes(value):
    if type(value) is not str or not _SIG.fullmatch(value):_fail()
    try:
        text=value.split(":",2)[2]; raw=base64.urlsafe_b64decode(text+"==")
        if len(raw)!=64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")!=text:_fail()
        return raw
    except (ValueError,UnicodeError):_fail()

@dataclass(frozen=True,slots=True)
class DeliveryReadiness:
    tenant:str; readiness_id:str; case_id:str; case_digest:str; privacy_decision_id:str; privacy_decision_digest:str; request_id:str; request_digest:str; scope_digest:str; processing_run_id:str; candidate_artifact_digest:str; rights_digest:str; contract_digest:str; recipient_commitment:str; purpose_code:str; approval_digests:tuple[str,str]; issuer_key_id:str; assessed_at:datetime; expires_at:datetime; signature:str=field(repr=False); posture:str="DELIVERY_READINESS_ONLY"; digest:str=field(init=False)
    def __post_init__(self):
        for n in ("tenant","issuer_key_id","purpose_code","processing_run_id"):object.__setattr__(self,n,_id(getattr(self,n)))
        if type(self.readiness_id) is not str or not _ID.fullmatch(self.readiness_id):_fail()
        for n in ("case_digest","privacy_decision_digest","request_digest","scope_digest","candidate_artifact_digest","contract_digest"):
            if type(getattr(self,n)) is not str or not _D.fullmatch(getattr(self,n)):_fail()
        if type(self.rights_digest) is not str or not re.fullmatch(r"[0-9a-f]{64}",self.rights_digest):_fail()
        if type(self.case_id) is not str or type(self.privacy_decision_id) is not str or type(self.request_id) is not str or not _CASE.fullmatch(self.case_id) or not _DECISION.fullmatch(self.privacy_decision_id) or not _REQUEST.fullmatch(self.request_id):_fail()
        if type(self.recipient_commitment) is not str or not _RECIPIENT.fullmatch(self.recipient_commitment):_fail()
        if type(self.approval_digests) is not tuple or len(self.approval_digests)!=2 or len(set(self.approval_digests))!=2 or any(type(x) is not str or not _D.fullmatch(x) for x in self.approval_digests):_fail()
        object.__setattr__(self,"approval_digests",tuple(sorted(self.approval_digests)));object.__setattr__(self,"assessed_at",_time(self.assessed_at));object.__setattr__(self,"expires_at",_time(self.expires_at))
        if self.expires_at<=self.assessed_at or self.posture!="DELIVERY_READINESS_ONLY" or type(self.signature) is not str or not _SIG.fullmatch(self.signature):_fail()
        object.__setattr__(self,"digest","sha256:"+hashlib.sha256(_canon({**self.canonical(),"signature":self.signature})).hexdigest())
    def canonical(self):return {k:(_instant(v) if isinstance(v,datetime) else list(v) if k=="approval_digests" else v) for k,v in {"tenant":self.tenant,"readiness_id":self.readiness_id,"case_id":self.case_id,"case_digest":self.case_digest,"privacy_decision_id":self.privacy_decision_id,"privacy_decision_digest":self.privacy_decision_digest,"request_id":self.request_id,"request_digest":self.request_digest,"scope_digest":self.scope_digest,"processing_run_id":self.processing_run_id,"candidate_artifact_digest":self.candidate_artifact_digest,"rights_digest":self.rights_digest,"contract_digest":self.contract_digest,"recipient_commitment":self.recipient_commitment,"purpose_code":self.purpose_code,"approval_digests":self.approval_digests,"issuer_key_id":self.issuer_key_id,"assessed_at":self.assessed_at,"expires_at":self.expires_at,"posture":self.posture}.items()}
    def to_record(self):return {**self.canonical(),"digest":self.digest,"signature":self.signature}
    @classmethod
    def from_record(cls,value):
        try:
            expected=set(cls.__dataclass_fields__) - {"digest"}
            expected.add("digest")
            if type(value) is not dict or set(value)!=expected:_fail()
            args=dict(value); args["assessed_at"]=datetime.fromisoformat(args["assessed_at"].replace("Z","+00:00"));args["expires_at"]=datetime.fromisoformat(args["expires_at"].replace("Z","+00:00"));args["approval_digests"]=tuple(args["approval_digests"]); args.pop("digest")
            item=cls(**args)
            if item.digest!=value["digest"]:_fail()
            return item
        except (KeyError,TypeError,ValueError,DeliveryReadinessError):_fail()

@dataclass(frozen=True,slots=True)
class DeliveryReadinessAuthority:
    tenant:str; issuer_key_id:str; expires_at:datetime; private_key_b64:str=field(repr=False); _key:Ed25519PrivateKey=field(init=False,repr=False)
    def __post_init__(self):
        t,k,e,key=_id(self.tenant),_id(self.issuer_key_id),_time(self.expires_at),_key(self.private_key_b64)
        current=datetime.now(UTC).replace(microsecond=0)
        if e<=current or (e-current).total_seconds()>366*24*3600:_fail()
        object.__setattr__(self,"tenant",t);object.__setattr__(self,"issuer_key_id",k);object.__setattr__(self,"expires_at",e);object.__setattr__(self,"_key",key)
    def active(self,at):
        try:return _time(at)<self.expires_at
        except DeliveryReadinessError:return False
    def readiness_id(self,request_id,key):
        if type(request_id) is not str or not _REQUEST.fullmatch(request_id) or type(key) is not str or not 1<=len(key)<=200 or not key.isascii() or any(x.isspace() for x in key):_fail()
        raw=self._key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        return "delivery-readiness:v1:"+base64.urlsafe_b64encode(hmac.new(raw,b"m21-readiness-id-v1:\0"+_canon({"request_id":request_id,"key":key}),hashlib.sha256).digest()).decode().rstrip("=")
    def issue(self,**values):
        at,expiry=_time(values.pop("assessed_at")),_time(values.pop("expires_at"))
        if at>datetime.now(UTC).replace(microsecond=0) or not self.active(at) or expiry>self.expires_at:_fail()
        blank="delivery-readiness-sig:v1:"+"A"*86
        item=DeliveryReadiness(tenant=self.tenant,issuer_key_id=self.issuer_key_id,assessed_at=at,expires_at=expiry,signature=blank,**values)
        sig="delivery-readiness-sig:v1:"+base64.urlsafe_b64encode(self._key.sign(b"delivery-readiness-v1:"+_canon(item.canonical()))).decode().rstrip("=")
        return DeliveryReadiness(tenant=self.tenant,issuer_key_id=self.issuer_key_id,assessed_at=at,expires_at=expiry,signature=sig,**values)
    def verifies(self,item,at):
        try:
            if type(item) is not DeliveryReadiness or item.tenant!=self.tenant or item.issuer_key_id!=self.issuer_key_id or not self.active(at) or item.assessed_at>_time(at) or item.expires_at<=_time(at) or item.expires_at>self.expires_at:return False
            self._key.public_key().verify(_signature_bytes(item.signature),b"delivery-readiness-v1:"+_canon(item.canonical()));return True
        except (InvalidSignature,ValueError,UnicodeError,DeliveryReadinessError):return False
def load_delivery_readiness_authorities():
    raw=os.getenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES","")
    if not raw:return ()
    if len(raw.encode("utf-8"))>65536:_fail()
    try:
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError
                result[key]=value
            return result
        values=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError())); out=[]
        if type(values) is not list or not values or len(values)>64:_fail()
        for x in values:
            if type(x) is not dict or set(x)!={"tenant","issuer_key_id","expires_at","private_key"}:_fail()
            out.append(DeliveryReadinessAuthority(x["tenant"],x["issuer_key_id"],datetime.fromisoformat(x["expires_at"].replace("Z","+00:00")),x["private_key"]))
        if len({x.tenant for x in out})!=len(out):_fail()
        return tuple(out)
    except (TypeError,ValueError,UnicodeError,DeliveryReadinessError):_fail()
def authority_for_tenant(values,*,tenant,at):
    found=[x for x in values if type(x) is DeliveryReadinessAuthority and x.tenant==tenant and x.active(at)]
    if len(found)!=1:_fail()
    return found[0]
