"""Synthetic end-to-end intake, storage, release and lifecycle contracts."""
import base64
import json
import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.storage_config import create_store
from test_access import TOKENS, auth


@pytest.fixture(params=["memory", "sqlite"])
def configured(request, monkeypatch, tmp_path):
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "dev-token")
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", request.param)
    monkeypatch.setenv("ANONFLOW_DB_PATH", str(tmp_path / "source.db"))
    monkeypatch.setenv("ANONFLOW_STORAGE_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps([
        {"token": TOKENS[n], "subject": n, "tenant": "b" if n == "other" else "a",
         "roles": ["processor" if n == "other" else n]}
        for n in ("processor", "reviewer", "other", "buyer")]))
    return request.param


SOURCES = [("text", "contact synthetic@example.test", 1),
           ("json", '[{"note":"synthetic@example.test"},{"note":"hello"}]', 2),
           ("jsonl", '{"note":"synthetic@example.test"}\n\n{"note":"hello"}', 2),
           ("csv", 'note,code\r\n"synthetic@example.test",001\r\nhello,002\r\n', 2)]


@pytest.mark.parametrize("format,source,count", SOURCES)
def test_ingest_release_review_delete(configured, format, source, count):
    with TestClient(create_app()) as client:
        response = client.post("/ingestions", headers=auth(), json={"format": format, "content": source, "name": "fixture"})
        assert response.status_code == 201, response.text
        identifier = response.json()["id"]
        assert response.json()["record_count"] == count
        assert source not in response.text
        assert client.app.state.store.get_dataset(identifier, "a")["original_source"] == source
        evidence = client.get(f"/datasets/{identifier}/manifest", headers=auth("reviewer"))
        assert evidence.status_code == 200
        assert evidence.json()["manifest"]["record_count"] == count
        assert "synthetic@example.test" not in evidence.text
        assert client.get(f"/datasets/{identifier}/manifest", headers=auth("other")).status_code == 404
        release = client.post("/releases", headers=auth(), json={"dataset_id": identifier})
        assert release.status_code == 201, release.text
        rid = release.json()["id"]
        assert release.json()["output"] is None
        assert client.post(f"/reviews/{rid}/decision", headers=auth("reviewer"), json={"decision": "approve"}).status_code == 409
        assert client.post(f"/reviews/{rid}/decision", headers=auth("reviewer"), json={"decision": "reject"}).status_code == 200
        assert client.delete(f"/datasets/{identifier}", headers=auth("other")).status_code == 404
        assert client.delete(f"/datasets/{identifier}", headers=auth("reviewer")).status_code == 403
        deleted = client.delete(f"/datasets/{identifier}", headers=auth())
        assert deleted.status_code == 204 and deleted.content == b""
        assert client.get(f"/releases/{rid}", headers=auth()).status_code == 404
        assert client.get("/datasets", headers=auth()).json() == []
        audit = client.get("/audit", headers=auth("reviewer"))
        assert audit.status_code == 200
        actions = [e["action"] for e in audit.json()["events"]]
        assert actions == ["dataset.created", "release.created", "review.rejected", "dataset.deleted"]
        assert "synthetic@example.test" not in audit.text
        assert client.get("/audit", headers=auth()).status_code == 403


@pytest.mark.parametrize("format,source", [("json", '[{"note":"secret","note":"x"}]'),
    ("jsonl", '{"note":"ok"}\nBROKEN-secret'), ("csv", 'a,a\nsecret,x'),
    ("csv", 'contact\n"unclosed-secret'), ("json", '[{"synthetic@example.test":"x"}]'),
    ("text", "\ud800"), ("text", " "), ("xml", "secret")])
def test_invalid_intake_no_partial_commit(configured, format, source):
    with TestClient(create_app()) as client:
        response = client.post(
            "/ingestions", headers={**auth(), "Content-Type": "application/json"},
            content=json.dumps({"format": format, "content": source, "name": "fixture"}))
        assert response.status_code == 422, response.text
        assert "secret" not in response.text and "input" not in response.text
        assert client.get("/datasets", headers=auth()).json() == []
        assert client.get("/audit", headers=auth("reviewer")).json()["events"] == []


def test_restart_retains_only_durable_state(configured):
    with TestClient(create_app()) as client:
        item = client.post("/ingestions", headers=auth(), json={"format": "csv", "content": "code\n001", "name": "fixture"}).json()
        release = client.post("/releases", headers=auth(), json={"dataset_id": item["id"]}).json()
    with TestClient(create_app()) as reopened:
        records = reopened.get("/datasets", headers=auth()).json()
        assert len(records) == (1 if configured == "sqlite" else 0)
        if configured == "sqlite":
            assert reopened.get(f"/releases/{release['id']}", headers=auth()).json()["output"] is None
            assert reopened.app.state.store.get_dataset(item["id"], "a")["records"] == [{"code": "001"}]


@pytest.mark.parametrize("mode,key,path", [("unknown", "x", "x"), ("sqlite", "", "x"),
    ("sqlite", "not-base64", "x"), ("sqlite", base64.b64encode(b"short").decode(), "x"),
    ("sqlite", base64.b64encode(b"x" * 32).decode(), "")])
def test_storage_config_safe(monkeypatch, mode, key, path):
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", mode)
    monkeypatch.setenv("ANONFLOW_STORAGE_KEY", key)
    monkeypatch.setenv("ANONFLOW_DB_PATH", path)
    with pytest.raises(RuntimeError, match="^Invalid storage configuration$"):
        create_store()


def test_jwt_identity_with_full_intake_and_storage(configured, monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public["kid"] = "synthetic-key"
    jwks = tmp_path / "public.json"
    jwks.write_text(json.dumps({"keys": [public]}), encoding="utf-8")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "jwt")
    monkeypatch.setenv("ANONFLOW_JWT_ISSUER", "https://issuer.example.test")
    monkeypatch.setenv("ANONFLOW_JWT_AUDIENCE", "anonflow-test")
    monkeypatch.setenv("ANONFLOW_JWKS_PATH", str(jwks))
    monkeypatch.setenv("ANONFLOW_JWT_BINDINGS", json.dumps([
        {"subject": "operator", "tenant": "a", "roles": ["processor"]},
        {"subject": "reviewer", "tenant": "a", "roles": ["reviewer"]}]))
    def signed(subject):
        now = int(time.time())
        token = jwt.encode({"sub": subject, "iss": "https://issuer.example.test", "aud": "anonflow-test",
                            "iat": now, "nbf": now, "exp": now + 300,
                            "tenant": "forged", "roles": ["reviewer", "processor"]}, key,
                           algorithm="RS256", headers={"kid": "synthetic-key", "typ": "at+jwt"})
        return {"Authorization": "Bearer " + token}
    with TestClient(create_app()) as client:
        response = client.post("/ingestions", headers=signed("operator"), json={"name": "fixture", "format": "csv", "content": "code\n001"})
        assert response.status_code == 201, response.text
        did = response.json()["id"]
        assert client.app.state.store.get_dataset(did, "a")["owner"] == "operator"
        assert client.get("/audit", headers=signed("operator")).status_code == 403
        assert client.post("/ingestions", headers=signed("reviewer"), json={"name": "fixture", "format": "text", "content": "text"}).status_code == 403
        assert client.get("/datasets", headers=auth()).status_code == 401
        assert client.get("/datasets", headers=signed("unbound")).status_code == 403
        assert client.get("/audit", headers=signed("reviewer")).status_code == 200
