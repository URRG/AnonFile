"""Authz, resource and input boundaries, entirely synthetic/local fixtures."""
import asyncio
import json
import pytest
from fastapi.testclient import TestClient
from app.main import BodyLimitMiddleware, create_app

TOKENS = {name: name.ljust(40, "-") for name in ("processor", "reviewer", "buyer", "other", "dual")}

@pytest.fixture
def client(monkeypatch):
    entries = [{"token": TOKENS[name], "subject": name, "tenant": "tenant-b" if name == "other" else "tenant-a",
                "roles": ["processor", "reviewer"] if name == "dual" else ["processor" if name == "other" else name]} for name in TOKENS]
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps(entries))
    with TestClient(create_app()) as result:
        yield result

def auth(name="processor"):
    return {"Authorization": "Bearer " + TOKENS[name]}

def dataset(client, name="processor", **payload):
    response = client.post("/datasets", headers=auth(name), json={"name": "synthetic", **(payload or {"content": "example@example.test"})})
    assert response.status_code == 201, response.text
    return response.json()["id"]

def release(client, identifier, name="processor", **payload):
    response = client.post("/releases", headers=auth(name), json={"dataset_id": identifier, **payload})
    assert response.status_code == 201, response.text
    return response.json()

def test_missing_config_fails_closed(monkeypatch):
    monkeypatch.delenv("ANONFLOW_DEV_PRINCIPALS", raising=False)
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    assert TestClient(create_app()).get("/datasets").status_code == 503

@pytest.mark.parametrize("mode", ["production", "staging", "", "Development"])
def test_non_development_mode_refused(monkeypatch, mode):
    monkeypatch.setenv("ANONFLOW_ENV", mode)
    with pytest.raises(RuntimeError, match="Only explicit development"):
        create_app()

@pytest.mark.parametrize("config", ["not-json-secret", "{}", '[{"token":"short"}]', '[{"token":"a"}]', "null"])
def test_malformed_config_safe(monkeypatch, config):
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", config)
    with pytest.raises(RuntimeError) as error:
        create_app()
    assert str(error.value) == "Invalid development authentication configuration"
    assert config not in str(error.value)

@pytest.mark.parametrize("header", [None, "Bearer invalid", "Basic processor", "Bearer å"])
def test_authentication_required(client, header):
    # httpx restricts header values to ASCII; send invalid unicode as UTF8 bytes.
    headers = {} if header is None else {"Authorization": header.encode("utf-8")}
    assert client.get("/datasets", headers=headers).status_code == 401

def test_tenant_isolation_all_object_routes(client):
    identifier = dataset(client)
    item = release(client, identifier)
    assert client.get("/datasets", headers=auth("other")).json() == []
    assert client.post("/releases", headers=auth("other"), json={"dataset_id": identifier}).status_code == 404
    for suffix in ("", "/card"):
        assert client.get(f"/releases/{item['id']}{suffix}", headers=auth("other")).status_code == 404
    assert client.get("/datasets", headers=auth()).json()[0]["owner"] == "processor"

def test_buyer_no_candidate_or_source_access(client):
    identifier = dataset(client)
    item = release(client, identifier)
    assert client.get("/datasets", headers=auth("buyer")).status_code == 403
    assert client.post("/datasets", headers=auth("buyer"), json={"name": "x", "content": "x"}).status_code == 403
    assert client.post("/releases", headers=auth("buyer"), json={"dataset_id": identifier}).status_code == 403
    for suffix in ("", "/card"):
        assert client.get(f"/releases/{item['id']}{suffix}", headers=auth("buyer")).status_code == 403
    assert client.get(f"/releases/{item['id']}/download", headers=auth("buyer")).status_code == 404

def test_creator_cannot_review_own_release(client):
    item = release(client, dataset(client, "dual"), "dual")
    assert client.post(f"/reviews/{item['id']}/decision", headers=auth("dual"), json={"decision": "reject"}).status_code == 403

def test_processor_cannot_review(client):
    item = release(client, dataset(client))
    assert client.post(f"/reviews/{item['id']}/decision", headers=auth(), json={"decision": "reject"}).status_code == 403

@pytest.mark.parametrize("payload", [{}, {"content": "x", "records": [{}]}, {"content": ""}, {"content": "  "}, {"records": []}, {"records": ["not-record"]}, {"content": "x", "tenant": "forged"}])
def test_exact_payload_and_schema(client, payload):
    response = client.post("/datasets", headers=auth(), json={"name": "sensitive-name", **payload})
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"}

def test_nested_size_depth_and_unicode(client):
    nested = "value"
    for _ in range(34):
        nested = {"nest": nested}
    for payload in ({"records": [{"value": "x" * 2_000_001}]}, {"records": [{"value": nested}]}, {"content": "é" * 1_000_001}):
        response = client.post("/datasets", headers=auth(), json={"name": "x", **payload})
        assert response.status_code in (413, 422)
        assert "value" not in response.text

def test_errors_never_echo_values_or_json_paths(client):
    response = client.post("/datasets", headers={**auth(), "Content-Type": "application/json"}, content='{"name":"very-private-person","records":[{"secret-email@example.test":NaN}]}')
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"}
    assert "private" not in response.text and "@" not in response.text

@pytest.mark.parametrize("body", [
    '{"name":"x","content":"password=synthetic-secret","content":"ok"}',
    '{"name":"x","records":[{"password":"synthetic-secret","password":"ok"}]}',
    '{"name":"x","records":[{"password":"synthetic-secret","pass\\u0077ord":"ok"}]}',
    '{"name":"x","content":"ok","name":"other"}',
    '{"name":"x","records":[{"nested":{"value":1,"value":2}}]}',
])
def test_duplicate_json_keys_rejected_before_any_source_is_stored(client, body):
    response = client.post("/datasets", headers={**auth(), "Content-Type": "application/json"}, content=body)
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"}
    assert not client.app.state.store.datasets

@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_all_nonfinite_json_numbers_rejected(client, value):
    response = client.post("/datasets", headers={**auth(), "Content-Type": "application/json"}, content='{"name":"x","records":[{"value":' + value + '}]}')
    assert response.status_code == 422
    assert response.json() == {"detail": "Request validation failed"}
    assert not client.app.state.store.datasets

def test_deep_malformed_and_invalid_encoding_safe(client):
    bodies = [b'{"name":"private","content":', b'{"name":"x","content":"\xff"}', ('{"name":"x","records":' + '[' * 2000 + '0' + ']' * 2000 + '}').encode()]
    for body in bodies:
        response = client.post("/datasets", headers={**auth(), "Content-Type": "application/json"}, content=body)
        assert response.status_code == 422
        assert response.json() == {"detail": "Request validation failed"}

def test_sensitive_keys_rejected_before_retention(client):
    for records in [[{"example@example.test": "x"}], [{"safe": {"password=synthetic-secret": "x"}}]]:
        response = client.post("/datasets", headers=auth(), json={"name": "x", "records": records})
        assert response.status_code == 422
        assert response.json() == {"detail": "Request validation failed"}
        assert not client.app.state.store.datasets

def test_content_length_limit(client):
    response = client.post("/datasets", headers={**auth(), "Content-Length": "2100001"}, content="x")
    assert response.status_code == 413

def test_surrogates_in_metadata_and_payload_are_safe_rejections(client):
    for body in ('{"name":"\\ud800","content":"ok"}', '{"name":"ok","records":[{"\\ud800":"ok"}]}', '{"name":"ok","content":"\\ud800"}'):
        response = client.post("/datasets", headers={**auth(), "Content-Type": "application/json"}, content=body)
        assert response.status_code == 422
        assert response.json() == {"detail": "Request validation failed"}

def test_reviewer_cannot_ingest_and_untrusted_claim_headers_ignored(client):
    assert client.post("/datasets", headers=auth("reviewer"), json={"name": "x", "content": "x"}).status_code == 403
    identifier = dataset(client)
    response = client.post("/releases", headers={**auth("other"), "X-Tenant": "tenant-a", "X-Roles": "reviewer,processor"}, json={"dataset_id": identifier})
    assert response.status_code == 404

@pytest.mark.parametrize("mutation", ["duplicate-token", "duplicate-identity", "invalid-role"])
def test_ambiguous_config_rejected(monkeypatch, mutation):
    first = {"token": "a" * 40, "subject": "first", "tenant": "tenant", "roles": ["processor"]}
    second = {"token": "b" * 40, "subject": "second", "tenant": "tenant", "roles": ["reviewer"]}
    if mutation == "duplicate-token":
        second["token"] = first["token"]
    elif mutation == "duplicate-identity":
        second["subject"] = first["subject"]
    else:
        second["roles"] = ["administrator"]
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps([first, second]))
    with pytest.raises(RuntimeError, match="Invalid development authentication configuration"):
        create_app()

def test_streaming_limit_before_parser():
    reached, sent = [], []
    async def downstream(scope, receive, send):
        reached.append(True)
    chunks = iter([{"type": "http.request", "body": b"abc", "more_body": True}, {"type": "http.request", "body": b"def", "more_body": False}])
    async def receive():
        return next(chunks)
    async def send(message):
        sent.append(message)
    asyncio.run(BodyLimitMiddleware(downstream, max_bytes=5)({"type": "http", "headers": []}, receive, send))
    assert not reached
    assert sent[0]["status"] == 413

def test_capacity_and_expiry_cascade(client):
    store = client.app.state.store
    store.MAX_DATASETS_PER_TENANT = 1
    identifier = dataset(client)
    item = release(client, identifier)
    assert client.post("/datasets", headers=auth(), json={"name": "x", "content": "x"}).status_code == 429
    store.datasets[identifier]["expires_at"] = 0
    assert client.get(f"/releases/{item['id']}", headers=auth()).status_code == 404
    assert client.post("/releases", headers=auth(), json={"dataset_id": identifier}).status_code == 404
    assert not store.datasets and not store.releases

def test_release_and_byte_quota(client):
    store = client.app.state.store
    identifier = dataset(client)
    store.MAX_RELEASES_PER_TENANT = 0
    assert client.post("/releases", headers=auth(), json={"dataset_id": identifier}).status_code == 429
    store.MAX_TENANT_SOURCE_BYTES = 1
    assert client.post("/datasets", headers=auth(), json={"name": "x", "content": "x"}).status_code == 429
