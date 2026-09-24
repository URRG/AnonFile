import base64
import json
import socket
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.openbao_transit import (OpenBaoTransitConfig, OpenBaoTransitEd25519,
                                 OpenBaoTransitError, TransitEd25519Signature, _envelope)


PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"p" * 32)
PUBLIC_KEY = base64.b64encode(PRIVATE_KEY.public_key().public_bytes_raw()).decode("ascii")
SIGNATURE = "vault:v7:" + base64.b64encode(b"s" * 64).decode("ascii")


def signature_for(message):
    return "vault:v7:" + base64.b64encode(PRIVATE_KEY.sign(message)).decode("ascii")


class Response:
    def __init__(self, status=200, body=b'{"data":{}}'):
        self.status, self.body = status, body
    def read(self, amount):
        return self.body
    def __enter__(self): return self
    def __exit__(self, *args): return False


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.request, self.timeout, self.requests = response, error, None, None, []
    def open(self, request, timeout):
        self.request, self.timeout = request, timeout
        self.requests.append(request)
        if self.error: raise self.error
        if isinstance(self.response, list): return self.response.pop(0)
        return self.response


def client(transport):
    return OpenBaoTransitEd25519(OpenBaoTransitConfig("https://bao.example", "transit", "audit-key", 7, PUBLIC_KEY, 1.5), transport=transport)


def metadata(): return Response(body=b'{"data":{"type":"ed25519","exportable":false,"allow_plaintext_backup":false}}')


def test_standard_openbao_null_envelope_fields_are_accepted_without_accepting_wrapped_auth():
    ordinary = {"data": {}, "auth": None, "wrap_info": None, "warnings": None,
                "lease_id": "", "lease_duration": 0, "renewable": False}
    assert _envelope(ordinary)
    assert not _envelope({**ordinary, "auth": {"client_token": "secret"}})
    assert not _envelope({**ordinary, "wrap_info": {"token": "wrapped"}})


def test_sign_and_verify_use_only_pinned_transit_endpoints_and_bind_version():
    real_signature = signature_for(b"record")
    transport = FakeTransport([metadata(), Response(body=json.dumps({"data": {"signature": real_signature, "key_version": 7}}).encode()), Response(body=b'{"data":{"valid":true}}')])
    signer = client(transport)
    signature = signer.sign(message=b"record", token="short-lived-token")
    assert signature == TransitEd25519Signature(real_signature, 7)
    assert transport.requests[1].full_url == "https://bao.example/v1/transit/sign/audit-key"
    assert transport.timeout == 1.5
    assert transport.request.get_header("X-vault-token") == "short-lived-token"
    assert json.loads(transport.requests[1].data) == {"input": "cmVjb3Jk", "key_version": 7}
    transport.response = [metadata(), Response(body=b'{"data":{"valid":true}}')]
    assert signer.verify(message=b"record", signature=signature, token="short-lived-token") is True
    assert transport.request.full_url.endswith("/transit/verify/audit-key")


@pytest.mark.parametrize("response", [
    Response(302, b""), Response(body=b"not json"), Response(body=b'{"data":{"signature":"vault:v6:' + base64.b64encode(b"s" * 64) + b'"}}'),
    Response(body=b'{"data":{"signature":"' + SIGNATURE.encode() + b'","extra":true}}'),
    Response(body=b'{"data":{"signature":"' + SIGNATURE.encode() + b'"},"warnings":[]}'),
])
def test_sign_rejects_redirect_and_malformed_or_forged_responses(response):
    with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
        client(FakeTransport([metadata(), response])).sign(message=b"x", token="token")


@pytest.mark.parametrize("error", [socket.timeout(), TimeoutError(), HTTPError("https://bao.example", 307, "redirect", {}, None)])
def test_transport_timeout_or_redirect_fail_closed(error):
    with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
        client(FakeTransport(error=error)).sign(message=b"x", token="token")


def test_verify_rejects_forged_response_and_wrong_signature_binding():
    signature = TransitEd25519Signature(signature_for(b"x"), 7)
    with pytest.raises(OpenBaoTransitError, match="^verification unavailable$"):
        client(FakeTransport([metadata(), Response(body=b'{"data":{"valid":1}}')])).verify(message=b"x", signature=signature, token="token")
    with pytest.raises(ValueError, match="^invalid OpenBao Transit signature$"):
        client(FakeTransport(Response())).verify(message=b"x", signature=TransitEd25519Signature("vault:v8:" + base64.b64encode(b"s" * 64).decode(), 8), token="token")


def test_verify_rejects_signature_that_fails_pinned_public_key_without_contacting_service():
    transport = FakeTransport(Response())
    assert client(transport).verify(message=b"x", signature=TransitEd25519Signature(SIGNATURE, 7), token="token") is False
    assert transport.request is None


def test_rejects_key_not_ed25519_or_exportable_and_sign_response_unverified():
    for bad in ({"type":"rsa-2048","exportable":False,"allow_plaintext_backup":False}, {"type":"ed25519","exportable":True,"allow_plaintext_backup":False}, {"type":"ed25519","exportable":False,"allow_plaintext_backup":True}):
        with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
            client(FakeTransport(Response(body=json.dumps({"data":bad}).encode()))).sign(message=b"x", token="token")
    with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
        client(FakeTransport([metadata(), Response(body=json.dumps({"data":{"signature":signature_for(b"x"),"key_version":7}}).encode()), Response(body=b'{"data":{"valid":false}}')])).sign(message=b"x", token="token")


def test_config_and_call_bounds_reject_bad_service_and_secrets():
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("http://bao.example", "transit", "key", 1, PUBLIC_KEY)
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("https://bao.example", "transit/../sys", "key", 1, PUBLIC_KEY)
    signer = client(FakeTransport(Response()))
    with pytest.raises(ValueError, match="^invalid signing input$"):
        signer.sign(message=b"x" * (64 * 1024 + 1), token="token")
    with pytest.raises(ValueError, match="^invalid OpenBao Transit token$"):
        signer.sign(message=b"x", token="secret\nleak")
    with pytest.raises(ValueError, match="^invalid OpenBao Transit token$"):
        signer.sign(message=b"x", token="secret token")


def test_sign_rejects_a_well_formed_signature_not_matching_pinned_public_key():
    with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
        client(FakeTransport([metadata(), Response(body=json.dumps({"data":{"signature":SIGNATURE,"key_version":7}}).encode())])).sign(message=b"x", token="token")


def test_sign_rejects_mismatched_transit_version_or_public_key():
    signature = signature_for(b"x")
    for data in ({"signature": signature, "key_version": 8},
                 {"signature": signature, "key_version": 7, "public_key": base64.b64encode(b"z" * 32).decode("ascii")}):
        with pytest.raises(OpenBaoTransitError, match="^signing unavailable$"):
            client(FakeTransport([metadata(), Response(body=json.dumps({"data": data}).encode())])).sign(message=b"x", token="token")


def test_config_rejects_noncanonical_public_key_and_non_string_url():
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig(["https://bao.example"], "transit", "key", 1, PUBLIC_KEY)
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("https://bao.example", "transit", "key", 1, base64.b64encode(b"x" * 31).decode())
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("https://bao.example/proxy", "transit", "key", 1, PUBLIC_KEY)
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("https://bao.example:not-a-port", "transit", "key", 1, PUBLIC_KEY)
    with pytest.raises(ValueError, match="^invalid OpenBao Transit configuration$"):
        OpenBaoTransitConfig("https://[bad", "transit", "key", 1, PUBLIC_KEY)


def test_signature_rejects_base64_unused_bit_alias():
    encoded = base64.b64encode(b"s" * 64).decode("ascii")
    alias = encoded[:-3] + "x" + encoded[-2:]
    assert base64.b64decode(alias, validate=True) == base64.b64decode(encoded, validate=True)
    with pytest.raises(ValueError, match="^invalid OpenBao Transit signature$"):
        TransitEd25519Signature("vault:v7:" + alias, 7)
