from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def create_dataset(content: str) -> str:
    response = client.post("/datasets", json={"name": "test-dataset", "content": content})
    assert response.status_code == 201
    return response.json()["id"]


def test_external_release_blocks_credentials_and_removes_direct_identifier() -> None:
    dataset_id = create_dataset("Contact a@example.com. api_key=super-secret")
    response = client.post("/releases", json={"dataset_id": dataset_id, "release_mode": "external_anonymized"})
    assert response.status_code == 201
    release = response.json()
    assert release["eligibility"] == "BLOCKED"
    assert "a@example.com" not in release["output"]
    assert "[REDACTED_CREDENTIAL]" in release["output"]


def test_restricted_mode_is_consistent_within_a_release() -> None:
    dataset_id = create_dataset("a@example.com notified a@example.com")
    response = client.post("/releases", json={"dataset_id": dataset_id, "release_mode": "restricted_pseudonymized"})
    assert response.status_code == 201
    release = response.json()
    assert release["eligibility"] == "APPROVED_RESTRICTED"
    assert release["output"].count("[EMAIL_0001]") == 2


def test_external_mode_does_not_emit_a_stable_pseudonym() -> None:
    dataset_id = create_dataset("a@example.com notified a@example.com")
    response = client.post("/releases", json={"dataset_id": dataset_id, "release_mode": "external_anonymized"})
    assert response.status_code == 201
    assert "[EMAIL] notified [EMAIL]" == response.json()["output"]
