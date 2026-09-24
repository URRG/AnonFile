"""Offline synthetic RSA/access-token tests, not an OIDC deployment evaluation."""
import base64
import hashlib
import hmac
import json
import socket
import time
import urllib.request

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.main import create_app
from app.security import configure_auth, require_roles


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def jwk(private_key, kid="synthetic-key"):
    numbers = private_key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "key_ops": ["verify"],
            "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))}


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def config(monkeypatch, tmp_path, private_key):
    monkeypatch.setenv("ANONFLOW_ENV", "development")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "jwt")
    monkeypatch.setenv("ANONFLOW_JWT_ISSUER", "https://issuer.example.invalid")
    monkeypatch.setenv("ANONFLOW_JWT_AUDIENCE", "synthetic-api")
    monkeypatch.setenv("ANONFLOW_JWT_BINDINGS", json.dumps([
        {"subject": "synthetic-subject", "tenant": "server-tenant", "roles": ["processor"]},
        {"subject": "reviewer-subject", "tenant": "server-tenant", "roles": ["reviewer"]},
        {"subject": "evaluator-subject", "tenant": "server-tenant", "roles": ["evaluator"]}]))
    path = tmp_path / "public-jwks.json"
    path.write_text(json.dumps({"keys": [jwk(private_key)]}), encoding="utf-8")
    monkeypatch.setenv("ANONFLOW_JWKS_PATH", str(path))
    return path


def app():
    result = FastAPI()
    configure_auth(result)

    @result.get("/identity")
    def identity(principal=Depends(require_roles("processor", "reviewer"))):
        return {"subject": principal.subject, "tenant": principal.tenant, "roles": sorted(principal.roles)}

    @result.get("/processor")
    def processor(principal=Depends(require_roles("processor"))):
        return {"ok": True}

    @result.get("/evaluator")
    def evaluator(principal=Depends(require_roles("evaluator"))):
        return {"subject": principal.subject, "roles": sorted(principal.roles)}

    return result


def claims(**changes):
    now = int(time.time())
    result = {"iss": "https://issuer.example.invalid", "aud": "synthetic-api",
              "sub": "synthetic-subject", "iat": now - 10, "nbf": now - 10, "exp": now + 300}
    result.update(changes)
    return result


def token(private_key, payload=None, headers=None):
    return signed_raw(private_key,
                      json.dumps({"alg": "RS256", "kid": "synthetic-key", "typ": "at+jwt", **(headers or {})}),
                      json.dumps(claims() if payload is None else payload))


def request(client, value, path="/identity"):
    return client.get(path, headers={"Authorization": "Bearer " + value})


def assert_auth_failure(response):
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    assert response.headers["www-authenticate"] == "Bearer"


def signed_raw(private_key, header_raw, payload_raw):
    message = b64(header_raw.encode()) + "." + b64(payload_raw.encode())
    signature = private_key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
    return message + "." + b64(signature)


def test_valid_token_uses_server_binding_not_token_authority(config, private_key):
    value = token(private_key, claims(tenant="forged-tenant", roles=["buyer", "reviewer"]))
    response = request(TestClient(app()), value)
    assert response.status_code == 200
    assert response.json() == {"subject": "synthetic-subject", "tenant": "server-tenant", "roles": ["processor"]}


def test_evaluator_role_is_accepted_only_from_server_jwt_binding(config, private_key):
    value = token(private_key, claims(sub="evaluator-subject", roles=["processor"]))
    response = request(TestClient(app()), value, "/evaluator")
    assert response.status_code == 200
    assert response.json() == {"subject": "evaluator-subject", "roles": ["evaluator"]}


@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "exp", "iat", "nbf"])
def test_all_required_claims(config, private_key, missing):
    payload = claims()
    payload.pop(missing)
    assert_auth_failure(request(TestClient(app()), token(private_key, payload)))


@pytest.mark.parametrize("changes", [
    {"iss": "https://evil.example.invalid"}, {"aud": "another-api"},
    {"aud": ["synthetic-api"]}, {"aud": ["another-api", "synthetic-api"]},
    {"iss": ["https://issuer.example.invalid"]}, {"sub": ""}, {"sub": 1},
    {"sub": "x" * 161}, {"sub": "private\nsubject"},
    {"exp": 1}, {"nbf": 253402300799}, {"iat": 253402300799},
    {"iat": -1}, {"nbf": -1}, {"exp": 253402300800},
])
def test_bad_claims(config, private_key, changes):
    assert_auth_failure(request(TestClient(app()), token(private_key, claims(**changes))))


@pytest.mark.parametrize("name", ["exp", "iat", "nbf"])
@pytest.mark.parametrize("value", [True, False, "12345", None, [], {}, float("inf"), float("nan")])
def test_numeric_claims_no_coercion(config, private_key, name, value):
    assert_auth_failure(request(TestClient(app()), token(private_key, claims(**{name: value}))))


def test_numeric_fractional_claims_validated(config, private_key):
    now = time.time()
    value = token(private_key, claims(iat=now - 10.5, nbf=now - 10.5, exp=now + 300.5))
    assert request(TestClient(app()), value).status_code == 200


@pytest.mark.parametrize("headers", [
    {"typ": "JWT"}, {"typ": "id+jwt"}, {"typ": None}, {"kid": "unknown-key"},
    {"kid": ""}, {"kid": ["synthetic-key"]},
    {"jku": "https://example.invalid/jwks"}, {"x5u": "https://example.invalid/key"},
    {"jwk": {"kty": "RSA"}}, {"crit": []}, {"crit": ["exp"]},
    {"b64": False}, {"cty": "JWT"},
])
def test_strict_headers(config, private_key, headers):
    # Raw signing permits malformed headers that the JWT producer rightly rejects.
    header = {"alg": "RS256", "kid": "synthetic-key", "typ": "at+jwt", **headers}
    value = signed_raw(private_key, json.dumps(header), json.dumps(claims()))
    assert_auth_failure(request(TestClient(app()), value))


def test_missing_kid(config, private_key):
    value = signed_raw(private_key, '{"alg":"RS256","typ":"at+jwt"}', json.dumps(claims()))
    assert_auth_failure(request(TestClient(app()), value))


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS512", "PS256"])
def test_algorithm_confusion_rejected(config, private_key, algorithm):
    if algorithm == "none":
        key = None
    elif algorithm == "HS256":
        key = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        key = private_key
    if algorithm == "HS256":
        message = b64(json.dumps({"alg": algorithm, "kid": "synthetic-key", "typ": "at+jwt"}).encode()) + "." + b64(json.dumps(claims()).encode())
        value = message + "." + b64(hmac.new(key, message.encode(), hashlib.sha256).digest())
    else:
        value = jwt.encode(claims(), key, algorithm=algorithm, headers={"kid": "synthetic-key", "typ": "at+jwt"})
    assert_auth_failure(request(TestClient(app()), value))


def test_bad_signature(config, private_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert_auth_failure(request(TestClient(app()), token(other)))


def test_unbound_subject_is_forbidden_only_after_signature_verification(config, private_key):
    client = TestClient(app())
    response = request(client, token(private_key, claims(sub="unbound-subject")))
    assert response.status_code == 403
    assert response.json() == {"detail": "Access denied"}
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert_auth_failure(request(client, token(other, claims(sub="unbound-subject"))))


def test_bound_reviewer_cannot_acquire_processor_role_from_claims(config, private_key):
    response = request(TestClient(app()), token(private_key, claims(sub="reviewer-subject", roles=["processor"])), "/processor")
    assert response.status_code == 403


@pytest.mark.parametrize("location", ["header", "claims"])
def test_duplicate_json_members_rejected(config, private_key, location):
    header = '{"alg":"RS256","kid":"synthetic-key","typ":"at+jwt"}'
    payload = json.dumps(claims())
    if location == "header":
        header = header[:-1] + ',"alg":"RS256"}'
    else:
        payload = payload[:-1] + ',"sub":"synthetic-subject"}'
    assert_auth_failure(request(TestClient(app()), signed_raw(private_key, header, payload)))


@pytest.mark.parametrize("value", ["not-a-jwt", "a.b.c.d", "x" * 16385, "a.b.c", "..", "a=.b.c", "a.b.c\t"])
def test_malformed_and_bounded_tokens(config, value):
    assert_auth_failure(request(TestClient(app()), value))


def test_duplicate_authorization_headers_rejected(config, private_key):
    value = "Bearer " + token(private_key)
    response = TestClient(app()).get("/identity", headers=[("Authorization", value), ("Authorization", value)])
    assert_auth_failure(response)


@pytest.mark.parametrize("change", [
    "duplicate-kid", "duplicate-public-key", "private-key", "weak-key", "empty",
    "wrong-alg", "wrong-use", "wrong-ops", "unknown-member", "noncanonical-n", "invalid-e", "oversized",
])
def test_bad_jwks_configuration_safe(config, private_key, change):
    key = jwk(private_key)
    rows = [key]
    if change == "duplicate-kid":
        rows.append(dict(key))
    elif change == "duplicate-public-key":
        rows.append({**key, "kid": "another-kid"})
    elif change == "private-key":
        key["d"] = "private-key-material"
    elif change == "weak-key":
        rows = [jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024))]
    elif change == "empty":
        rows = []
    elif change == "wrong-alg":
        key["alg"] = "HS256"
    elif change == "wrong-use":
        key["use"] = "enc"
    elif change == "wrong-ops":
        key["key_ops"] = ["sign"]
    elif change == "unknown-member":
        key["x5u"] = "https://example.invalid/key"
    elif change == "noncanonical-n":
        key["n"] += "="
    elif change == "invalid-e":
        key["e"] = b64(b"\x02")
    config.write_text(json.dumps({"keys": rows}) if change != "oversized" else " " * 128001, encoding="utf-8")
    with pytest.raises(RuntimeError) as error:
        app()
    assert str(error.value) == "Invalid JWT authentication configuration"


def test_duplicate_jwks_member_rejected(config, private_key):
    key = json.dumps(jwk(private_key))
    config.write_text('{"keys":[' + key[:-1] + ',"kid":"synthetic-key"}]}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="^Invalid JWT authentication configuration$"):
        app()


@pytest.mark.parametrize("name,value", [
    ("ANONFLOW_JWT_ISSUER", ""), ("ANONFLOW_JWT_AUDIENCE", ""),
    ("ANONFLOW_JWKS_PATH", "https://example.invalid/jwks"),
    ("ANONFLOW_JWKS_PATH", "\\\\server\\share\\jwks.json"),
    ("ANONFLOW_JWKS_PATH", "//server/share/jwks.json"),
    ("ANONFLOW_JWKS_PATH", "/\\server/share/jwks.json"),
    ("ANONFLOW_JWT_BINDINGS", "[]"), ("ANONFLOW_JWT_BINDINGS", "not-json-secret"),
    pytest.param("ANONFLOW_JWT_BINDINGS", "x" * 32001, id="oversized-bindings"),
])
def test_bad_configuration_fixed_errors(config, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError) as error:
        app()
    assert str(error.value) == "Invalid JWT authentication configuration"


@pytest.mark.parametrize("name", ["ANONFLOW_JWT_ISSUER", "ANONFLOW_JWT_AUDIENCE", "ANONFLOW_JWKS_PATH", "ANONFLOW_JWT_BINDINGS"])
def test_missing_configuration_fails_startup(config, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(RuntimeError, match="^Invalid JWT authentication configuration$"):
        app()


@pytest.mark.parametrize("mutation", ["duplicate-subject", "unknown-role", "empty-role", "duplicate-role", "extra-key"])
def test_ambiguous_or_invalid_bindings_rejected(config, monkeypatch, mutation):
    row = {"subject": "synthetic-subject", "tenant": "server-tenant", "roles": ["processor"]}
    rows = [row]
    if mutation == "duplicate-subject":
        rows.append({**row, "tenant": "another-tenant"})
    elif mutation == "unknown-role":
        row["roles"] = ["admin"]
    elif mutation == "empty-role":
        row["roles"] = []
    elif mutation == "duplicate-role":
        row["roles"] = ["processor", "processor"]
    else:
        row["extra"] = "secret"
    monkeypatch.setenv("ANONFLOW_JWT_BINDINGS", json.dumps(rows))
    with pytest.raises(RuntimeError, match="^Invalid JWT authentication configuration$"):
        app()


def test_no_network_calls_during_load_or_validation(config, private_key, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Network attempt")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    verifier = app().state.jwt_verifier
    assert verifier.authenticate(token(private_key)).subject == "synthetic-subject"
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        verifier.authenticate(token(private_key, headers={"jku": "https://example.invalid/jwks"}))
    assert error.value.status_code == 401


def test_modes_never_fall_back(config, monkeypatch, private_key):
    dev_token = "synthetic-development-token".ljust(40, "-")
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps([
        {"token": dev_token, "subject": "dev-user", "tenant": "dev-tenant", "roles": ["processor"]}]))
    assert_auth_failure(request(TestClient(app()), dev_token))
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "dev-token")
    client = TestClient(app())
    assert request(client, dev_token).status_code == 200
    assert_auth_failure(request(client, token(private_key)))
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "jwt")
    monkeypatch.delenv("ANONFLOW_JWT_ISSUER")
    with pytest.raises(RuntimeError, match="^Invalid JWT authentication configuration$"):
        app()


def test_production_requires_explicit_jwt_configuration(config, monkeypatch, private_key):
    monkeypatch.setenv("ANONFLOW_ENV", "production")
    assert TestClient(app()).get("/identity", headers={"Authorization": "Bearer " + token(private_key)}).status_code == 200
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "dev-token")
    with pytest.raises(RuntimeError, match="^Production requires JWT authentication$"):
        app()


def test_production_exposes_only_health_and_identity(config, monkeypatch, private_key):
    monkeypatch.setenv("ANONFLOW_ENV", "production")
    client = TestClient(create_app())
    authorization = {"Authorization": "Bearer " + token(private_key)}
    assert client.get("/health").json() == {
        "status": "ok", "service": "anonflow-api", "mode": "production", "production_ready": False,
    }
    assert client.get("/identity", headers=authorization).json() == {
        "subject": "synthetic-subject", "tenant": "server-tenant", "roles": ["processor"],
    }
    for path, payload in (
        ("/datasets", {"name": "synthetic", "content": "example@example.test"}),
        ("/processing-runs", {}),
        ("/release-cases/missing/privacy-decisions", {}),
        ("/release-cases/missing/release-authorization-requests", {}),
        ("/release-authorization-requests/missing/approvals", {}),
    ):
        response = client.post(path, headers=authorization, json=payload)
        assert response.status_code == 503
        assert response.json() == {"detail": "Production workflow is unavailable"}


def test_pinned_jwks_rotation_and_revocation_take_effect_per_request(config, private_key):
    client = TestClient(app())
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_token = token(private_key)
    replacement_token = signed_raw(
        replacement,
        json.dumps({"alg": "RS256", "kid": "replacement-key", "typ": "at+jwt"}),
        json.dumps(claims()),
    )
    assert request(client, old_token).status_code == 200

    # A single trusted, locally managed bundle can overlap keys during an
    # atomic rotation; token data cannot nominate another bundle or algorithm.
    config.write_text(json.dumps({"keys": [jwk(private_key), jwk(replacement, "replacement-key")]}), encoding="utf-8")
    assert request(client, replacement_token).status_code == 200

    # Removing the old public key is a revocation: an already-created client
    # must no longer authenticate signatures from that key.
    config.write_text(json.dumps({"keys": [jwk(replacement, "replacement-key")]}), encoding="utf-8")
    assert_auth_failure(request(client, old_token))
    assert request(client, replacement_token).status_code == 200


def test_invalid_auth_mode_fails_closed(config, monkeypatch):
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "auto")
    with pytest.raises(RuntimeError, match="^Invalid authentication mode$"):
        app()


def test_bindings_are_a_startup_snapshot_but_jwks_changes_fail_closed(config, private_key, monkeypatch):
    client = TestClient(app())
    monkeypatch.setenv("ANONFLOW_JWT_BINDINGS", "[]")
    assert request(client, token(private_key)).status_code == 200
    config.write_text('{"keys":[]}', encoding="utf-8")
    assert_auth_failure(request(client, token(private_key)))
    with pytest.raises(RuntimeError, match="^Invalid JWT authentication configuration$"):
        app()
