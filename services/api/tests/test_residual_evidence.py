"""Independent residual evidence remains aggregate, complete, and V2-attested."""
from __future__ import annotations
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from app.main import create_app
from app.main import private_candidate_artifact
from app.candidate import CandidateArtifact, PayloadKind, SchemaContract
from app.residual_evidence import ResidualEvidenceError, ResidualEvidenceStatus, scan_independent_residual
from app.residual_evidence_authority import ResidualEvidenceAuthorityError, ResidualEvidenceControlAuthority
from app.residual_evidence_authority import authority_for_tenant
from test_access import auth
from test_control_plane_api import controls, ingested_dataset, run_request, setup

def artifact(value):
    return CandidateArtifact.create(run_id="run-residual",input_digest="sha256:"+"a"*64,policy_digest="sha256:"+"b"*64,transformed=value,schema=SchemaContract.from_value(value,kind=PayloadKind.TEXT if type(value) is str else PayloadKind.STRUCTURED))
def authority(expiry=None):
    raw=Ed25519PrivateKey.generate().private_bytes_raw()
    return ResidualEvidenceControlAuthority("tenant-a","residual-issuer",expiry or datetime.now(UTC).replace(microsecond=0)+timedelta(days=1),base64.b64encode(raw).decode("ascii"))
def binding(report):
    return dict(tenant="tenant-a",run_id="run-residual",processing_request_digest="sha256:"+"c"*64,candidate_artifact_digest=report.candidate_artifact_digest,policy_digest="sha256:"+"b"*64,rights_digest="sha256:"+"d"*64,method_id="rules",method_version="v1",method_config_digest="sha256:"+"e"*64,taxonomy_mapping_digest="sha256:"+"f"*64,idempotency_key="request-1",report=report)

def test_clean_complete_scan_is_lower_is_safer_ppm_and_never_exposes_candidate_values():
    report=scan_independent_residual(candidate=artifact([{"text":"synthetic safe"},{"text":"another safe"}]))
    assert report.status is ResidualEvidenceStatus.ASSESSED and report.maximum_residual_ppm == 0
    record=report.to_record(); assert record["assessed_categories"] == ["CREDENTIAL","PAYMENT","PII"]
    assert "synthetic safe" not in json.dumps(record)

def test_findings_are_maximum_family_ppm_not_sum_of_overlapping_family_counts():
    report=scan_independent_residual(candidate=artifact([{"text":"a@example.test Authorization: Bearer abcdefghijk"},{"text":"safe"}]))
    assert report.status is ResidualEvidenceStatus.ASSESSED and report.maximum_residual_ppm == 500_000

def test_top_level_structured_object_is_scanned_as_one_value_unit_not_its_keys():
    report=scan_independent_residual(candidate=artifact({"email":"person@example.test"}))
    assert report.status is ResidualEvidenceStatus.ASSESSED
    assert report.total_units == report.scanned_units == 1
    assert dict(report.residual_counts)["PII"] == 1 and report.maximum_residual_ppm == 1_000_000

def test_partial_scans_abstain_and_cannot_carry_a_pass_score():
    report=scan_independent_residual(candidate=artifact([{"nested": "safe"}]))
    # normal input is complete; forge an abstention wrapper to exercise the
    # strict report invariant instead of permitting a score on partial data.
    with pytest.raises(ResidualEvidenceError):
        replace(report,status=ResidualEvidenceStatus.ABSTAINED,abstained_units=1,maximum_residual_ppm=0)

def test_v2_ed25519_signature_binds_full_report_and_lifecycle_without_retaining_input_key():
    item=scan_independent_residual(candidate=artifact("safe")); issuer=authority(); args=binding(item)
    signature=issuer.sign_for_worker(**args)
    assert issuer.verify(signature=signature,**args)
    assert not hasattr(issuer, "private_key_b64")
    assert not issuer.verify(signature=signature,**{**args,"run_id":"other-run"})
    assert not issuer.verify(signature=signature,at=issuer.expires_at,**args)
    with pytest.raises(ResidualEvidenceAuthorityError): issuer.sign_for_worker(at=issuer.expires_at,**args)

def test_api_uses_server_worker_v2_evidence_with_replay_owner_and_tenant_boundaries(monkeypatch,tmp_path):
    setup(monkeypatch,tmp_path)
    raw=Ed25519PrivateKey.generate().private_bytes_raw()
    expiry=(datetime.now(UTC).replace(microsecond=0)+timedelta(days=90)).isoformat().replace("+00:00","Z")
    monkeypatch.setenv("ANONFLOW_RESIDUAL_EVIDENCE_AUTHORITIES",json.dumps([{"tenant":"tenant-a","issuer_key_id":"residual-v2","expires_at":expiry,"private_key_b64":base64.b64encode(raw).decode("ascii")}]))
    with TestClient(create_app()) as client:
        dataset=ingested_dataset(client); policy,rights=controls(client)
        response=client.post("/processing-runs",headers={**auth(),"Idempotency-Key":"m16-run-0001"},json=run_request(dataset,policy["id"],rights["id"])); assert response.status_code==201,response.text
        run=response.json()
        assert client.post(f"/processing-runs/{run['id']}/execute",headers=auth()).status_code==200
        private, stored_run=client.app.state.store.private_candidate_for_run(run["id"],"tenant-a")
        report=scan_independent_residual(candidate=private_candidate_artifact(private["payload"]))
        issuer=authority_for_tenant(client.app.state.residual_evidence_authorities,tenant="tenant-a")
        issuer.sign_for_worker(tenant="tenant-a",run_id=run["id"],processing_request_digest=stored_run["payload"]["request_digest"],candidate_artifact_digest=report.candidate_artifact_digest,policy_digest=stored_run["payload"]["policy_digest"],rights_digest=stored_run["payload"]["rights_digest"],method_id=stored_run["payload"]["method_id"],method_version=stored_run["payload"]["method_version"],method_config_digest=stored_run["payload"]["method_config_digest"],taxonomy_mapping_digest=stored_run["payload"]["taxonomy_mapping_digest"],idempotency_key="m16-evidence",report=report)
        first=client.post(f"/processing-runs/{run['id']}/independent-residual-evidence",headers={**auth(),"Idempotency-Key":"m16-evidence"})
        assert first.status_code==201,first.text
        item=first.json(); assert item["report"]["status"]=="ASSESSED" and item["report"]["maximum_residual_ppm"]==0
        assert client.post(f"/processing-runs/{run['id']}/independent-residual-evidence",headers={**auth(),"Idempotency-Key":"m16-evidence"}).status_code==200
        assert client.get(f"/processing-runs/{run['id']}/independent-residual-evidence/{item['id']}",headers=auth("reviewer")).status_code==200
        assert client.post(f"/processing-runs/{run['id']}/independent-residual-evidence",headers={**auth("other"),"Idempotency-Key":"other"}).status_code==404
