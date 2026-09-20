"""Tenant-owned Ed25519 V2 issuer for independent residual evidence."""
from __future__ import annotations
import base64, binascii, hashlib, json, os, re
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from typing import Iterable
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from app.residual_evidence import IndependentResidualReport, ResidualEvidenceError

_ID=re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z"); _DIGEST=re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_AUTH=re.compile(r"residual-authority:v2:[A-Za-z0-9_-]{43}\Z"); _SIG=re.compile(r"residual-sig:v2:[A-Za-z0-9_-]{86}\Z")
class ResidualEvidenceAuthorityError(ValueError):
    def __init__(self): super().__init__("Invalid residual-evidence authority")
def _fail(): raise ResidualEvidenceAuthorityError()
def _canon(v):
    try:return json.dumps(v,ensure_ascii=True,allow_nan=False,sort_keys=True,separators=(",",":")).encode("ascii")
    except (TypeError,ValueError,UnicodeError,OverflowError,RecursionError):_fail()
def _id(v):
    if type(v) is not str or not _ID.fullmatch(v):_fail()
    return v
def _digest(v):
    if type(v) is not str or not _DIGEST.fullmatch(v):_fail()
    return v
def _time(v):
    if not isinstance(v,datetime) or v.tzinfo is None or v.utcoffset() is None:_fail()
    v=v.astimezone(UTC)
    if v.microsecond:_fail()
    return v
def _instant(v):return v.isoformat().replace("+00:00","Z")
def _expiry(v):
    if type(v) is not str or not 20<=len(v)<=40 or not v.endswith("Z") or "+" in v[:-1]: _fail()
    try: return _time(datetime.fromisoformat(v[:-1]+"+00:00"))
    except (ValueError, OverflowError, ResidualEvidenceAuthorityError): _fail()
def _key(v):
    if type(v) is not str or len(v)!=44:_fail()
    try:
        raw=base64.b64decode(v,validate=True)
        if len(raw)!=32 or base64.b64encode(raw).decode("ascii")!=v:_fail()
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError,UnicodeError):_fail()

@dataclass(frozen=True,slots=True)
class ResidualEvidenceControlAuthority:
    tenant:str; issuer_key_id:str; expires_at:datetime; private_key_b64:InitVar[str]=field(repr=False,compare=False)
    authority_id:str=field(init=False); _private_key:Ed25519PrivateKey=field(init=False,repr=False,compare=False); _public_key:Ed25519PublicKey=field(init=False,repr=False,compare=False)
    def __post_init__(self, private_key_b64):
        if type(self) is not ResidualEvidenceControlAuthority:_fail()
        tenant=_id(self.tenant); issuer=_id(self.issuer_key_id); expiry=_time(self.expires_at); key=_key(private_key_b64)
        now=datetime.now(UTC).replace(microsecond=0)
        if expiry<=now or (expiry-now).total_seconds()>366*86400:_fail()
        pub=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode("ascii")
        aid="residual-authority:v2:"+base64.urlsafe_b64encode(hashlib.sha256(_canon({"schema":"independent-residual-ed25519-v2","tenant":tenant,"issuer_key_id":issuer,"expires_at":_instant(expiry),"public_key":pub})).digest()).decode("ascii").rstrip("=")
        if not _AUTH.fullmatch(aid):_fail()
        object.__setattr__(self,"tenant",tenant);object.__setattr__(self,"issuer_key_id",issuer);object.__setattr__(self,"expires_at",expiry);object.__setattr__(self,"authority_id",aid);object.__setattr__(self,"_private_key",key);object.__setattr__(self,"_public_key",key.public_key())
    def is_active(self,*,at=None):
        try:return _time(datetime.now(UTC).replace(microsecond=0) if at is None else at)<self.expires_at
        except ResidualEvidenceAuthorityError:return False
    def _message(self,*,tenant,run_id,processing_request_digest,candidate_artifact_digest,policy_digest,rights_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,idempotency_key,report):
        if type(report) is not IndependentResidualReport or tenant!=self.tenant:_fail()
        for v in (run_id,method_id,method_version):_id(v)
        for v in (processing_request_digest,candidate_artifact_digest,policy_digest,rights_digest,method_config_digest,taxonomy_mapping_digest):_digest(v)
        if type(idempotency_key) is not str or not 1<=len(idempotency_key)<=200 or not idempotency_key.isascii() or any(c.isspace() for c in idempotency_key) or report.candidate_artifact_digest!=candidate_artifact_digest:_fail()
        return _canon({"schema":"independent-residual-attestation-v2","authority_id":self.authority_id,"tenant":tenant,"run_id":run_id,"processing_request_digest":processing_request_digest,"candidate_artifact_digest":candidate_artifact_digest,"policy_digest":policy_digest,"rights_digest":rights_digest,"method_id":method_id,"method_version":method_version,"method_config_digest":method_config_digest,"taxonomy_mapping_digest":taxonomy_mapping_digest,"idempotency_key":idempotency_key,"report":report.to_record()})
    def sign_for_worker(self, *, at=None, **binding):
        if not self.is_active(at=at): _fail()
        return "residual-sig:v2:"+base64.urlsafe_b64encode(self._private_key.sign(b"independent-residual-attestation-v2:"+self._message(**binding))).decode("ascii").rstrip("=")
    def verify(self,*,signature,at=None,**binding):
        if type(signature) is not str or not _SIG.fullmatch(signature):return False
        try:
            if not self.is_active(at=at): return False
            raw=base64.urlsafe_b64decode(signature.split(":",2)[2]+"==")
            self._public_key.verify(raw,b"independent-residual-attestation-v2:"+self._message(**binding));return True
        except (ValueError,UnicodeError,InvalidSignature,ResidualEvidenceAuthorityError):return False

def load_residual_evidence_authorities():
    raw=os.getenv("ANONFLOW_RESIDUAL_EVIDENCE_AUTHORITIES","")
    if not raw:return ()
    try:
        def unique(pairs):
            out={}
            for key,value in pairs:
                if key in out: raise ValueError
                out[key]=value
            return out
        entries=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries)>64:_fail()
        if any(type(entry) is not dict or set(entry)!={"tenant","issuer_key_id","expires_at","private_key_b64"} for entry in entries): _fail()
        result=tuple(ResidualEvidenceControlAuthority(entry["tenant"],entry["issuer_key_id"],_expiry(entry["expires_at"]),entry["private_key_b64"]) for entry in entries)
        if len({x.tenant for x in result})!=len(result):_fail()
        return result
    except (TypeError,ValueError,ResidualEvidenceAuthorityError):_fail()
def authority_for_tenant(authorities:Iterable[ResidualEvidenceControlAuthority],*,tenant,at=None):
    found=[x for x in authorities if type(x) is ResidualEvidenceControlAuthority and x.tenant==tenant]
    if len(found)!=1 or not found[0].is_active(at=at):_fail()
    return found[0]
