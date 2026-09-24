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

def test_idempotency_identifier_is_scoped_to_request_and_key():
    authority=signer()
    assert authority.readiness_id("release-authorization-request:v1:"+"A"*43,"one") != authority.readiness_id("release-authorization-request:v1:"+"A"*43,"two")
    with pytest.raises(DeliveryReadinessError): authority.readiness_id("wrong","key")

def test_authority_config_rejects_duplicate_keys_and_non_finite_values(monkeypatch):
    monkeypatch.setenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES", '[{"tenant":"tenant-a","tenant":"tenant-b"}]')
    with pytest.raises(DeliveryReadinessError): load_delivery_readiness_authorities()
    monkeypatch.setenv("ANONFLOW_DELIVERY_READINESS_AUTHORITIES", '[NaN]')
    with pytest.raises(DeliveryReadinessError): load_delivery_readiness_authorities()
