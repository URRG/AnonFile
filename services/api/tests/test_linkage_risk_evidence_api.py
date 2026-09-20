"""M12 server-owned linkage-risk evidence control path."""
from __future__ import annotations

import base64
from dataclasses import replace
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.linkage_risk import LinkageRiskReport
from app.linkage_risk_authority import LinkageRiskAuthorityError, LinkageRiskControlAuthority
from app.main import control_record, create_app, linkage_risk_evidence_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request, setup


def executed_run(client, *, key="m12-run-0001"):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": key},
                      json=run_request(dataset_id, policy["id"], rights["id"])).json()
    response = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert response.status_code == 200, response.text
    return response.json()


def assess(client, run_id, *, key="m12-linkage-0001", content=None, name="processor"):
    return client.post(f"/processing-runs/{run_id}/linkage-risk-evidence",
                       headers={**auth(name), "Idempotency-Key": key}, content=content)


def test_server_owned_reference_retains_only_signed_aggregate_evidence_without_lifecycle_authority(client):
    run = executed_run(client, key="m12-run-0002")
    before = client.get(f"/processing-runs/{run['id']}", headers=auth()).json()
    response = assess(client, run["id"])
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["run_id"] == run["id"]
    assert item["processing_request_digest"] == run["request_digest"]
    assert item["candidate_artifact_digest"] == run["candidate"]["artifact_digest"]
    assert item["posture"] == "OBSERVATIONAL_ONLY"
    assert "NO_RELEASE_AUTHORIZATION" in item["limitations"]
    assert item["report"]["digest"] == item["report_digest"]
    assert item["report"]["candidate_artifact_digest"] == run["candidate"]["artifact_digest"]
    assert item["report"]["linkage_key_commitment"].startswith("linkcfg:v1:")
    assert item["report"]["reference_commitment"].startswith("linkref:v1:")
    for forbidden in ("synthetic@example.test", "code", "001", "development-linkage-a", "linksig:"):
        assert forbidden not in response.text
    # This evidence is observational: it never changes candidate or release
    # lifecycle state and it cannot grant delivery or release authority.
    assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == before
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    rendered = json.dumps(stored)
    assert "body" not in rendered and "reference_records" not in rendered and "linkage_key_fields" not in rendered
    assert "linksig:" in rendered
    assert assess(client, run["id"]).status_code == 200


def test_no_client_reference_keys_or_candidate_material_and_access_boundaries(client):
    run = executed_run(client)
    secret = "private-reference/customer@example.test"
    for payload in ({}, {"reference": [{"code": "001"}]}, {"linkage_keys": ["code"]},
                    {"candidate": secret}, {"key": "x" * 32},
                    {"report": {"matched_record_count": 1}}):
        response = assess(client, run["id"], content=json.dumps(payload).encode())
        assert response.status_code == 422
        assert secret not in response.text
    assert not client.app.state.store.controls["linkage_risk_evidence"]
    created = assess(client, run["id"], key="m12-access-view")
    assert created.status_code == 201
    item = created.json()
    assert assess(client, run["id"], name="reviewer", key="m12-reviewer").status_code == 403
    assert assess(client, run["id"], name="other", key="m12-other").status_code == 404
    endpoint = f"/processing-runs/{run['id']}/linkage-risk-evidence/{item['id']}"
    assert client.get(endpoint, headers=auth("reviewer")).json() == item
    assert client.get(endpoint, headers=auth("buyer")).status_code == 401
    assert client.get(endpoint, headers=auth("other")).status_code == 404
    assert client.get(f"/processing-runs/not-the-run/linkage-risk-evidence/{item['id']}",
                      headers=auth("reviewer")).status_code == 404


def test_absent_invalid_or_expired_server_authority_fails_closed_without_report(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.delenv("ANONFLOW_LINKAGE_RISK_AUTHORITIES")
    with TestClient(create_app()) as isolated:
        run = executed_run(isolated)
        assert assess(isolated, run["id"]).status_code == 409
        assert not isolated.app.state.store.controls["linkage_risk_evidence"]
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANONFLOW_LINKAGE_RISK_AUTHORITIES", "[{]")
    with pytest.raises(RuntimeError):
        create_app()
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANONFLOW_LINKAGE_RISK_AUTHORITIES", json.dumps([{
        "tenant": "tenant-a", "key_id": "development-linkage-a", "expires_at": "2020-01-01T00:00:00Z",
        "linkage_key_fields": ["code"], "reference_records": [{"code": "001"}],
        "key": base64.b64encode(b"l" * 32).decode(),
    }]))
    with TestClient(create_app()) as isolated:
        run = executed_run(isolated)
        assert assess(isolated, run["id"], key="m12-expired-authority").status_code == 409
        assert not isolated.app.state.store.controls["linkage_risk_evidence"]


def test_tampering_or_reference_configuration_drift_makes_evidence_unavailable_and_deletion_tombstones(client):
    run = executed_run(client)
    item = assess(client, run["id"]).json()
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    stored["payload"]["report"]["matched_record_count"] = 9
    with pytest.raises(HTTPException) as error:
        linkage_risk_evidence_view(stored, linkage_risk_authorities=client.app.state.linkage_risk_authorities)
    assert error.value.status_code == 503
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    stored["payload"]["attestation_signature"] = "linksig:v1:" + "A" * 43
    with pytest.raises(HTTPException):
        linkage_risk_evidence_view(stored, linkage_risk_authorities=client.app.state.linkage_risk_authorities)
    authority = client.app.state.linkage_risk_authorities[0]
    drifted_keys = authority._authority.issue_key_config(["contact"])
    drifted_reference = authority._authority.create_reference([{"contact": "synthetic@example.test"}], linkage_keys=drifted_keys)
    drifted = replace(authority, _linkage_keys=drifted_keys, _reference=drifted_reference)
    assert drifted.linkage_config_revision != authority.linkage_config_revision
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    with pytest.raises(HTTPException):
        linkage_risk_evidence_view(stored, linkage_risk_authorities=(drifted,))
    run = executed_run(client, key="m12-run-0003")
    item = assess(client, run["id"], key="m12-linkage-0002").json()
    assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
    assert client.get(f"/processing-runs/{run['id']}/linkage-risk-evidence/{item['id']}", headers=auth()).status_code == 404


def test_active_authority_and_repository_reject_reports_bound_to_another_config_or_unsigned_forgery(client):
    run = executed_run(client)
    item = assess(client, run["id"]).json()
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    report = LinkageRiskReport.from_record(stored["payload"]["report"])
    forged = replace(report, linkage_key_commitment="linkcfg:v1:" + "A" * 43)
    authority = client.app.state.linkage_risk_authorities[0]
    with pytest.raises(LinkageRiskAuthorityError):
        authority.sign_for_worker(
            tenant="tenant-a", run_id=run["id"], processing_request_digest=stored["payload"]["processing_request_digest"],
            candidate_artifact_digest=stored["payload"]["candidate_artifact_digest"],
            policy_digest=stored["payload"]["policy_digest"], rights_digest=stored["payload"]["rights_digest"],
            method_id=stored["payload"]["method_id"], method_version=stored["payload"]["method_version"],
            method_config_digest=stored["payload"]["method_config_digest"],
            taxonomy_mapping_digest=stored["payload"]["taxonomy_mapping_digest"],
            idempotency_key=stored["payload"]["idempotency_key"],
            linkage_config_revision=authority.linkage_config_revision, report=forged)
    wrong_method = replace(report, methodology_digest="sha256:" + "f" * 64)
    with pytest.raises(LinkageRiskAuthorityError):
        authority.sign_for_worker(
            tenant="tenant-a", run_id=run["id"], processing_request_digest=stored["payload"]["processing_request_digest"],
            candidate_artifact_digest=stored["payload"]["candidate_artifact_digest"],
            policy_digest=stored["payload"]["policy_digest"], rights_digest=stored["payload"]["rights_digest"],
            method_id=stored["payload"]["method_id"], method_version=stored["payload"]["method_version"],
            method_config_digest=stored["payload"]["method_config_digest"],
            taxonomy_mapping_digest=stored["payload"]["taxonomy_mapping_digest"],
            idempotency_key=stored["payload"]["idempotency_key"],
            linkage_config_revision=authority.linkage_config_revision, report=wrong_method)
    # A self-consistent aggregate digest is insufficient: repository admission
    # requires a current trusted-worker attestation of the entire report.
    payload = {**stored["payload"], "idempotency_key": "m12-forged-0001", "report": forged.to_record()}
    record = control_record(kind="linkage_risk_evidence", identifier="m12-forged", tenant="tenant-a", payload=payload,
                            expires_at=stored["expires_at"])
    with pytest.raises(HTTPException) as error:
        client.app.state.store.record_linkage_risk_evidence(run["id"], "tenant-a", record, "processor", authority)
    assert error.value.status_code == 503
    # Candidate schema is also a private-run binding.  Even an otherwise valid
    # authority signature cannot attach a report to a different schema.
    wrong_schema = replace(report, candidate_schema_digest="sha256:" + "e" * 64)
    schema_payload = {**stored["payload"], "idempotency_key": "m12-schema-forged-1", "report": wrong_schema.to_record()}
    schema_payload["attestation_signature"] = authority.sign_for_worker(
        tenant="tenant-a", run_id=run["id"], processing_request_digest=schema_payload["processing_request_digest"],
        candidate_artifact_digest=schema_payload["candidate_artifact_digest"], policy_digest=schema_payload["policy_digest"],
        rights_digest=schema_payload["rights_digest"], method_id=schema_payload["method_id"], method_version=schema_payload["method_version"],
        method_config_digest=schema_payload["method_config_digest"], taxonomy_mapping_digest=schema_payload["taxonomy_mapping_digest"],
        idempotency_key=schema_payload["idempotency_key"], linkage_config_revision=schema_payload["linkage_config_revision"],
        report=wrong_schema)
    schema_record = control_record(kind="linkage_risk_evidence", identifier="m12-schema-forged", tenant="tenant-a",
                                   payload=schema_payload, expires_at=stored["expires_at"])
    with pytest.raises(HTTPException) as error:
        client.app.state.store.record_linkage_risk_evidence(run["id"], "tenant-a", schema_record, "processor", authority)
    assert error.value.status_code == 503


def test_authority_subclasses_cannot_bypass_control_admission_or_evidence_retrieval(client):
    class ForgedAuthority(LinkageRiskControlAuthority):
        pass

    run = executed_run(client, key="m12-subclass-run")
    item = assess(client, run["id"], key="m12-subclass-evidence").json()
    stored = client.app.state.store.get_control("linkage_risk_evidence", item["id"], "tenant-a")
    authority = client.app.state.linkage_risk_authorities[0]
    # Construction itself is refused; use an uninitialized forged instance to
    # exercise boundaries without relying on subclass-controlled attributes.
    with pytest.raises(LinkageRiskAuthorityError):
        ForgedAuthority(authority.tenant, authority.key_id, authority.expires_at,
                        authority._authority, authority._linkage_keys, authority._reference)
    forged = object.__new__(ForgedAuthority)
    with pytest.raises(HTTPException) as error:
        client.app.state.store.record_linkage_risk_evidence(run["id"], "tenant-a", stored, "processor", forged)
    assert error.value.status_code == 503
    with pytest.raises(HTTPException) as error:
        linkage_risk_evidence_view(stored, linkage_risk_authorities=(forged,))
    assert error.value.status_code == 503
