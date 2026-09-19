"""Release metadata never authorizes delivery or exposes internal candidates."""
import pytest
from test_access import auth, client, dataset, release

@pytest.mark.parametrize("mode", ["external_anonymized", "restricted_pseudonymized"])
@pytest.mark.parametrize("source", ["Contact example@example.test", "A person lives in a small village.", "No obvious identifiers"])
def test_unqualified_candidates_not_approved_or_returned(client, mode, source):
    item = release(client, dataset(client, content=source), release_mode=mode)
    assert item["eligibility"] == "REVIEW_REQUIRED"
    assert item["output"] is None
    assert item["card"]["scores"] is None
    assert item["card"]["evidence_status"] == "INSUFFICIENT_EVIDENCE"
    assert item["card"]["limitations"]
    assert "signature" not in item["card"] and "output_sha256" not in item["card"]
    assert "confidence" not in str(item["card"]["findings"])
    assert source not in str(item)
    stored = client.app.state.store.releases[item["id"]]
    assert "output" not in stored and "candidate" not in stored
    for suffix in ("", "/card"):
        response = client.get(f"/releases/{item['id']}{suffix}", headers=auth("reviewer"))
        assert response.status_code == 200
        assert source not in response.text
        assert response.headers["cache-control"] == "no-store"

def test_critical_blocks_without_leakage(client):
    item = release(client, dataset(client, records=[{"password": "synthetic-secret", "email": "example@example.test"}]))
    assert item["eligibility"] == "BLOCKED"
    assert item["output"] is None
    assert "synthetic-secret" not in str(item)
    assert "example@example.test" not in str(item)
    assert any(f["severity"] == "critical" for f in item["card"]["findings"])

def test_review_approval_cannot_bypass_qualification(client):
    item = release(client, dataset(client))
    response = client.post(f"/reviews/{item['id']}/decision", headers=auth("reviewer"), json={"decision": "approve", "reviewer": "forged", "note": "private"})
    assert response.status_code == 409
    assert "private" not in response.text
    assert client.get(f"/releases/{item['id']}", headers=auth()).json()["eligibility"] == "REVIEW_REQUIRED"

def test_rejection_new_snapshot_server_actor_no_note_echo(client):
    item = release(client, dataset(client))
    old_card = client.app.state.store.releases[item["id"]]["card"]
    response = client.post(f"/reviews/{item['id']}/decision", headers=auth("reviewer"), json={"decision": "reject", "reviewer": "forged", "note": "sensitive-note"})
    assert response.status_code == 200
    changed = response.json()
    assert changed["eligibility"] == "BLOCKED" and changed["output"] is None
    assert changed["card"]["revision"] == 2
    assert changed["review"]["reviewer"] == "reviewer"
    assert "sensitive-note" not in response.text and "forged" not in response.text
    assert old_card["eligibility"] == "REVIEW_REQUIRED"
    events = client.app.state.store.releases[item["id"]]["events"]
    assert len(events) == 2 and events[0]["card"]["eligibility"] == "REVIEW_REQUIRED"
    assert client.post(f"/reviews/{item['id']}/decision", headers=auth("reviewer"), json={"decision": "reject"}).status_code == 409

@pytest.mark.parametrize("payload", [{"policy_version": "made-up"}, {"release_mode": "raw"}, {"release_mode": "restricted_pseudonymized", "policy_version": "external-release-v1"}, {"release_mode": "external_anonymized", "policy_version": "restricted-pseudonymized-v1"}])
def test_policy_profiles_checked(client, payload):
    identifier = dataset(client)
    response = client.post("/releases", headers=auth(), json={"dataset_id": identifier, **payload})
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"}

def test_disabling_review_never_approves(client):
    assert release(client, dataset(client), allow_review=False)["eligibility"] == "BLOCKED"

def test_server_assigns_owner(client):
    identifier = dataset(client, owner="forged", content="x")
    assert client.app.state.store.datasets[identifier]["owner"] == "processor"

def test_no_auth_missing_object_does_not_disclose_existence(client):
    assert client.get("/releases/unknown").status_code == 401
    assert client.get("/releases/unknown", headers=auth()).status_code == 404
