"""M2b control-plane integration, using generated synthetic-only fixtures."""
import base64
import json
import secrets

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from test_access import TOKENS, auth


def setup(monkeypatch, tmp_path, mode="memory"):
    entries = [
        {"token": TOKENS["processor"], "subject": "processor", "tenant": "tenant-a", "roles": ["processor"]},
        {"token": TOKENS["reviewer"], "subject": "reviewer", "tenant": "tenant-a", "roles": ["reviewer"]},
        {"token": TOKENS["other"], "subject": "other", "tenant": "tenant-b", "roles": ["processor"]},
        {"token": TOKENS["evaluator"], "subject": "evaluator", "tenant": "tenant-a", "roles": ["evaluator"]},
        {"token": TOKENS["evaluator-other"], "subject": "evaluator-other", "tenant": "tenant-b", "roles": ["evaluator"]},
        {"token": TOKENS["dual"], "subject": "dual", "tenant": "tenant-a", "roles": ["processor", "evaluator"]},
    ]
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "dev-token")
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", mode)
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps(entries))
    monkeypatch.setenv("ANONFLOW_DB_PATH", str(tmp_path / "controls.db"))
    monkeypatch.setenv("ANONFLOW_STORAGE_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("ANONFLOW_EVALUATOR_AUTHORITIES", json.dumps([{
        "subject": "evaluator", "tenant": "tenant-a", "evaluator_id": "m8-harness", "evaluator_version": "v1",
        "evaluator_config_digest": "sha256:" + "a" * 64, "corpus_digests": ["sha256:" + "d" * 64],
        "key": base64.b64encode(b"e" * 32).decode(),
    }]))
    monkeypatch.setenv("ANONFLOW_UTILITY_EVIDENCE_AUTHORITIES", json.dumps([{
        "tenant": "tenant-a", "key_id": "development-utility-a",
        "expires_at": "2030-01-01T00:00:00Z",
        "key": base64.b64encode(b"u" * 32).decode(),
    }]))


@pytest.fixture(params=["memory", "sqlite"])
def client(request, monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, request.param)
    with TestClient(create_app()) as result:
        yield result


def policy_payload():
    return {
        "policy_id": "support-exports", "version": "v1",
        "release_modes": ["external_anonymized"], "formats": ["csv"], "languages": ["en"],
        "rules": [
            {"category": "CREDENTIAL", "action": "block", "priority": 0},
            {"category": "PAYMENT", "action": "suppress", "priority": 10},
            {"category": "HEALTH_SENSITIVE", "action": "suppress", "priority": 20},
            {"category": "PII", "action": "suppress", "priority": 30},
            {"category": "BUSINESS_CONFIDENTIAL", "action": "review", "priority": 40},
            {"category": "QUASI_IDENTIFIER", "action": "generalize", "priority": 50},
        ],
    }


def rights_payload(**changes):
    result = {"profile_id": "supplier-rights", "version": "v1", "permitted_purposes": ["model-training"],
              "permitted_recipients": ["buyer-a"], "expires_at": "2030-01-01T00:00:00Z", "resale_allowed": True}
    result.update(changes)
    return result


def controls(client):
    policy = client.post("/policy-snapshots", headers=auth(), json=policy_payload())
    rights = client.post("/rights-profiles", headers=auth(), json=rights_payload())
    assert policy.status_code == rights.status_code == 201
    return policy.json(), rights.json()


def ingested_dataset(client):
    response = client.post("/ingestions", headers=auth(), json={"name": "synthetic", "format": "csv", "content": "contact,code\nsynthetic@example.test,001\n"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_processing_run_preflight_allows_idempotency_key(client):
    response = client.options("/processing-runs", headers={"Origin": "http://localhost:3000",
                                                             "Access-Control-Request-Method": "POST",
                                                             "Access-Control-Request-Headers": "Idempotency-Key"})
    assert response.status_code == 200
    assert "idempotency-key" in response.headers["access-control-allow-headers"].lower()


def run_request(dataset_id, policy_id, rights_id, **changes):
    result = {"dataset_id": dataset_id, "policy_snapshot_id": policy_id, "rights_profile_id": rights_id,
              "recipient": "buyer-a", "purpose": "model-training", "release_mode": "external_anonymized",
              "language": "en", "method_id": "rules-v1"}
    result.update(changes)
    return result


def test_registered_run_binds_policy_rights_and_source_without_output(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    payload = run_request(dataset_id, policy["id"], rights["id"])
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0001"}, json=payload)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["state"] == "REGISTERED" and run["attempts"] == 0
    assert run["events"] == [{"sequence": 1, "state": "REGISTERED", "action": "REGISTERED", "attempt": 0, "occurred_at": run["events"][0]["occurred_at"]}]
    assert run["policy_digest"].startswith("sha256:") and len(run["rights_digest"]) == 64
    assert "output" not in run and "synthetic@example.test" not in response.text
    replay = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0001"}, json=payload)
    assert replay.status_code == 200 and replay.json() == run
    unsupported = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0001"}, json=run_request(dataset_id, policy["id"], rights["id"], method_id="rules-v2"))
    assert unsupported.status_code == 422
    assert run["method_id"] == "rules-v1" and run["language"] == "en"
    assert client.get(f"/processing-runs/{run['id']}", headers=auth("reviewer")).json() == run
    assert client.get(f"/processing-runs/{run['id']}", headers=auth("other")).status_code == 404
    actions = [event["action"] for event in client.get("/audit", headers=auth("reviewer")).json()["events"]]
    assert actions == ["dataset.created", "policy_snapshot.created", "rights_profile.created", "processing_run.created"]


@pytest.mark.parametrize("change", [
    {"recipient": "buyer-b"}, {"purpose": "evaluation"}, {"release_mode": "restricted_pseudonymized"}, {"language": "fr"},
])
def test_unpermitted_or_unsupported_run_never_registers(client, change):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0002"}, json=run_request(dataset_id, policy["id"], rights["id"], **change))
    assert response.status_code in {409, 422}
    assert "synthetic@example.test" not in response.text
    assert client.get("/processing-runs", headers=auth()).json() == []


def test_controls_are_metadata_only_tenant_scoped_and_stale_data_never_runs(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    assert client.get(f"/policy-snapshots/{policy['id']}", headers=auth("other")).status_code == 404
    assert client.get(f"/rights-profiles/{rights['id']}", headers=auth("other")).status_code == 404
    legacy = client.post("/datasets", headers=auth(), json={"name": "legacy", "content": "synthetic@example.test"}).json()["id"]
    no_provenance = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0003"}, json=run_request(legacy, policy["id"], rights["id"]))
    assert no_provenance.status_code == 409
    assert client.post("/rights-profiles", headers=auth(), json=rights_payload(permitted_recipients=["buyer-a", "buyer-a"])).status_code == 422
    assert client.post("/rights-profiles", headers=auth(), json=rights_payload(expires_at="not-a-time" )).status_code == 422
    malformed = client.post("/processing-runs", headers=auth(), json=run_request(dataset_id, policy["id"], rights["id"]))
    assert malformed.status_code == 422


def test_sqlite_restart_retains_registered_controls(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, "sqlite")
    with TestClient(create_app()) as first:
        dataset_id = ingested_dataset(first)
        policy, rights = controls(first)
        run = first.post("/processing-runs", headers={**auth(), "Idempotency-Key": "control-run-0004"}, json=run_request(dataset_id, policy["id"], rights["id"])).json()
    with TestClient(create_app()) as second:
        assert second.get(f"/policy-snapshots/{policy['id']}", headers=auth()).json() == policy
        assert second.get(f"/rights-profiles/{rights['id']}", headers=auth()).json() == rights
        restored = second.get(f"/processing-runs/{run['id']}", headers=auth()).json()
        assert restored == run and restored["state"] == "REGISTERED"


def test_dataset_deletion_invalidates_registered_run_and_its_retry(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    request = run_request(dataset_id, policy["id"], rights["id"])
    headers = {**auth(), "Idempotency-Key": "control-run-0005"}
    created = client.post("/processing-runs", headers=headers, json=request)
    assert created.status_code == 201
    assert client.delete(f"/datasets/{dataset_id}", headers=auth()).status_code == 204
    assert client.get(f"/processing-runs/{created.json()['id']}", headers=auth()).status_code == 404
    retry = client.post("/processing-runs", headers=headers, json=request)
    assert retry.status_code == 404
    assert client.get("/processing-runs", headers=auth()).json() == []
