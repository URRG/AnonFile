"""Opt-in, synthetic-only rules-preview API contracts."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import DEMO_MAX_BYTES, create_app
from test_access import TOKENS, auth, client


@pytest.fixture
def demo_client(monkeypatch):
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "dev-token")
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", "memory")
    monkeypatch.setenv("ANONFLOW_DEMO_MODE", "enabled")
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps([
        {"token": TOKENS["processor"], "subject": "processor", "tenant": "tenant-a", "roles": ["processor"]},
        {"token": TOKENS["reviewer"], "subject": "reviewer", "tenant": "tenant-a", "roles": ["reviewer"]},
    ]))
    with TestClient(create_app()) as result:
        yield result


@pytest.mark.parametrize(("format", "content", "expected_preview"), [
    ("text", "Contact demo@example.test with password=fictional-secret", "Contact [REDACTED_EMAIL] with [REDACTED_CREDENTIAL]"),
    ("csv", "email,city\ndemo@example.test,Pune\n", '[{"city":"Pune","email":"[REDACTED_EMAIL]"}]'),
    ("json", '[{"email":"demo@example.test","city":"Pune"}]', '[{"city":"Pune","email":"[REDACTED_EMAIL]"}]'),
    ("jsonl", '{"email":"demo@example.test","city":"Pune"}\n', '[{"city":"Pune","email":"[REDACTED_EMAIL]"}]'),
])
def test_synthetic_inspection_returns_only_rules_preview_without_persistence(demo_client, format, content, expected_preview):
    response = demo_client.post("/demo/inspect", headers=auth(), json={
        "format": format, "content": content, "synthetic_only": True,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["posture"] == "SYNTHETIC_DEMO_ONLY"
    assert body["format"] == format
    assert body["release_authorized"] is False
    assert body["transformed_preview"] == expected_preview
    assert all(set(item) == {"entity_type", "severity", "count"} for item in body["findings"])
    assert all(set(item) == {"entity_type", "action", "count"} for item in body["operations"])
    assert "fictional-secret" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert demo_client.app.state.store.datasets == {}
    assert demo_client.app.state.store.releases == {}
    assert all(values == {} for values in demo_client.app.state.store.controls.values())
    assert demo_client.app.state.store._audit == {}


def test_demo_endpoint_is_absent_without_explicit_opt_in(client):
    assert client.post("/demo/inspect", headers=auth(), json={
        "format": "text", "content": "demo@example.test", "synthetic_only": True,
    }).status_code == 404


@pytest.mark.parametrize("payload", [
    {"format": "text", "content": "demo@example.test"},
    {"format": "text", "content": "demo@example.test", "synthetic_only": False},
    {"format": "xml", "content": "demo@example.test", "synthetic_only": True},
    {"format": "text", "content": "x" * (DEMO_MAX_BYTES + 1), "synthetic_only": True},
])
def test_demo_rejects_invalid_or_unattested_input_without_leaking_it(demo_client, payload):
    response = demo_client.post("/demo/inspect", headers=auth(), json=payload)
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"} or response.json() == {"detail": "Unsupported payload"}
    assert "example.test" not in response.text
    assert demo_client.app.state.store.datasets == {}


def test_demo_requires_processor_role(demo_client):
    response = demo_client.post("/demo/inspect", headers=auth("reviewer"), json={
        "format": "text", "content": "demo@example.test", "synthetic_only": True,
    })
    assert response.status_code == 403


def test_synthetic_airline_fixture_masks_identifiers_but_retains_booking_reference(demo_client):
    source = (Path(__file__).resolve().parents[3] / "demo-data" / "synthetic-airline-passengers.csv").read_text(encoding="utf-8")
    response = demo_client.post("/demo/inspect", headers=auth(), json={
        "format": "csv", "content": source, "synthetic_only": True,
    })
    assert response.status_code == 200, response.text
    preview = json.loads(response.json()["transformed_preview"])
    assert preview[0]["full_name"] == "[REDACTED_PERSON_NAME]"
    assert preview[0]["email"] == "[REDACTED_EMAIL]"
    assert preview[0]["phone"] == "[REDACTED_PHONE]"
    assert preview[0]["passport_number"] == "[REDACTED_GOVERNMENT_ID]"
    assert preview[0]["date_of_birth"] == "[REDACTED_DATE_OF_BIRTH]"
    assert preview[0]["booking_reference"] == "DEMO-BOOKING-001"
    assert "Alex Example" not in response.text
    assert "alex@example.test" not in response.text


def test_demo_flag_does_not_expose_demo_route_in_production(monkeypatch):
    # The production guard runs before authentication.  Substitute only the
    # verifier loader so this focused route-registration test needs no JWKS
    # fixture; production JWT configuration is covered by token-auth tests.
    monkeypatch.setattr("app.token_auth.load_jwt_verifier", lambda: object())
    monkeypatch.setenv("ANONFLOW_ENV", "production")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "jwt")
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", "memory")
    monkeypatch.setenv("ANONFLOW_DEMO_MODE", "enabled")
    with TestClient(create_app()) as production_client:
        response = production_client.post("/demo/inspect", json={
            "format": "text", "content": "demo@example.test", "synthetic_only": True,
        })
    assert response.status_code == 503
    assert response.json() == {"detail": "Production workflow is unavailable"}
