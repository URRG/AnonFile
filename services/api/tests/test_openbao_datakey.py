import base64
import json
import socket
from urllib.error import HTTPError

import pytest

from app.openbao_datakey import (OpenBaoDataKeyConfig, OpenBaoDataKeyError,
                                 OpenBaoTransitDataKey, TransitDataKey)


WRAPPED = "vault:v7:" + base64.b64encode(b"w" * 60).decode("ascii")
PLAIN = base64.b64encode(b"p" * 32).decode("ascii")
KEY_REF = "keyref:v1:production-data-key"


class Response:
    def __init__(self, status=200, body=b'{"data":{}}'):
        self.status, self.body = status, body
    def read(self, amount): return self.body
    def __enter__(self): return self
    def __exit__(self, *args): return False


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.requests, self.timeout = response, error, [], None
    def open(self, request, timeout):
        self.requests.append(request)
        self.timeout = timeout
        if self.error: raise self.error
        if isinstance(self.response, list): return self.response.pop(0)
        return self.response


def metadata(**changes):
    data = {"type": "aes256-gcm96", "derived": False, "exportable": False,
            "allow_plaintext_backup": False, "deletion_allowed": False,
            "supports_encryption": True, "supports_decryption": True,
            "latest_version": 7, "min_decryption_version": 1, "min_encryption_version": 7}
    data.update(changes)
    return Response(body=json.dumps({"data": data}).encode("ascii"))


def client(transport):
    config = OpenBaoDataKeyConfig("https://bao.example", "transit", "envelope-key",
                                  KEY_REF, 7, 1.5)
    return OpenBaoTransitDataKey(config, transport=transport)


def test_generate_uses_only_pinned_plaintext_datakey_path_and_aad():
    transport = FakeTransport([metadata(), Response(body=json.dumps({"data": {"plaintext": PLAIN, "ciphertext": WRAPPED}}).encode())])
    result = client(transport).generate(key_ref=KEY_REF, context=b"tenant/a/object/b", token="short-lived")
    assert result == TransitDataKey(b"p" * 32, WRAPPED, 7)
    assert [request.full_url for request in transport.requests] == [
        "https://bao.example/v1/transit/keys/envelope-key",
        "https://bao.example/v1/transit/datakey/plaintext/envelope-key",
    ]
    assert json.loads(transport.requests[1].data) == {"bits": 256, "associated_data": "dGVuYW50L2Evb2JqZWN0L2I="}
    assert transport.requests[1].get_header("X-vault-token") == "short-lived"
    assert transport.timeout == 1.5


def test_unwrap_accepts_only_the_pinned_ref_version_and_aad():
    transport = FakeTransport([metadata(), Response(body=json.dumps({"data": {"plaintext": PLAIN}}).encode())])
    assert client(transport).unwrap(key_ref=KEY_REF, wrapped_key=WRAPPED, context=b"aad", token="token") == b"p" * 32
    assert transport.requests[1].full_url == "https://bao.example/v1/transit/decrypt/envelope-key"
    assert json.loads(transport.requests[1].data) == {"ciphertext": WRAPPED, "associated_data": "YWFk"}
    with pytest.raises(ValueError, match="^invalid Transit key reference$"):
        client(FakeTransport()).unwrap(key_ref="keyref:v1:another", wrapped_key=WRAPPED, context=b"aad", token="token")
    with pytest.raises(ValueError, match="^invalid Transit wrapped key$"):
        client(FakeTransport()).unwrap(key_ref=KEY_REF, wrapped_key=WRAPPED.replace("v7", "v8"), context=b"aad", token="token")


@pytest.mark.parametrize("bad", [
    {"derived": True}, {"exportable": True}, {"allow_plaintext_backup": True},
    {"deletion_allowed": True}, {"supports_encryption": False}, {"supports_decryption": False},
    {"latest_version": 8}, {"min_decryption_version": 8}, {"min_encryption_version": 8},
])
def test_key_policy_drift_fails_closed(bad):
    with pytest.raises(OpenBaoDataKeyError, match="^data-key generation unavailable$"):
        client(FakeTransport(metadata(**bad))).generate(key_ref=KEY_REF, context=b"aad", token="token")


@pytest.mark.parametrize("response", [
    Response(302, b""), Response(body=b"not-json"),
    Response(body=b'{"auth":{"client_token":"secret"},"data":{}}'),
    Response(body=b'{"data":{},"wrap_info":{"token":"wrapped"}}'),
    Response(body=b"{" + b"x" * (16 * 1024 + 1) + b"}"),
    Response(body=json.dumps({"data": {"plaintext": PLAIN, "ciphertext": WRAPPED.replace("v7", "v8")}}).encode()),
    Response(body=json.dumps({"data": {"plaintext": PLAIN, "ciphertext": WRAPPED, "extra": True}}).encode()),
    Response(body=json.dumps({"data": {"plaintext": base64.b64encode(b"x" * 31).decode(), "ciphertext": WRAPPED}}).encode()),
])
def test_malformed_or_unexpected_generation_responses_fail_closed(response):
    with pytest.raises(OpenBaoDataKeyError, match="^data-key generation unavailable$"):
        client(FakeTransport([metadata(), response])).generate(key_ref=KEY_REF, context=b"aad", token="token")


def test_rejects_invalid_config_inputs_context_tokens_and_redirects():
    with pytest.raises(ValueError, match="^invalid OpenBao data-key configuration$"):
        OpenBaoDataKeyConfig("http://bao.example", "transit", "key", KEY_REF, 1)
    with pytest.raises(ValueError, match="^invalid OpenBao data-key configuration$"):
        OpenBaoDataKeyConfig("https://bao.example", "transit/../sys", "key", KEY_REF, 1)
    with pytest.raises(ValueError, match="^invalid OpenBao data-key configuration$"):
        OpenBaoDataKeyConfig("https://bao.example", "transit", "key", "not-a-production-key-ref", 1)
    for context in (b"", b"x" * 4097, "text"):
        with pytest.raises(ValueError, match="^invalid Transit key context$"):
            client(FakeTransport()).generate(key_ref=KEY_REF, context=context, token="token")
    with pytest.raises(ValueError, match="^invalid OpenBao data-key token$"):
        client(FakeTransport()).generate(key_ref=KEY_REF, context=b"aad", token="bad token")
    with pytest.raises(OpenBaoDataKeyError, match="^data-key generation unavailable$"):
        client(FakeTransport(error=socket.timeout())).generate(key_ref=KEY_REF, context=b"aad", token="token")
    with pytest.raises(OpenBaoDataKeyError, match="^data-key generation unavailable$"):
        client(FakeTransport(error=HTTPError("https://bao.example", 307, "redirect", {}, None))).generate(key_ref=KEY_REF, context=b"aad", token="token")


def test_plaintext_is_not_representable_in_the_wrapped_key_or_response_contract():
    with pytest.raises(ValueError, match="^invalid Transit data key$"):
        TransitDataKey(bytearray(b"p" * 32), WRAPPED, 7)
    with pytest.raises(OpenBaoDataKeyError, match="^data-key unwrap unavailable$"):
        client(FakeTransport([metadata(), Response(body=json.dumps({"data": {"plaintext": PLAIN, "ciphertext": WRAPPED}}).encode())])).unwrap(key_ref=KEY_REF, wrapped_key=WRAPPED, context=b"aad", token="token")
