"""Bounded OpenBao Transit Ed25519 signing boundary.

This module intentionally exposes only Transit key-metadata ``read`` plus
``sign`` and ``verify``. It does not create, rotate, export, import, or
otherwise handle key material. An operator pins the HTTPS OpenBao address,
mount and key name; the caller supplies a short-lived token from its secret
manager.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
import socket
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


_MAX_INPUT_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024
_KEY_PART = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_SIGNATURE = re.compile(r"vault:v([1-9][0-9]{0,8}):([A-Za-z0-9+/]{86}==)\Z")


class OpenBaoTransitError(RuntimeError):
    """A fixed error that never incorporates responses, URLs, or tokens."""


class _Transport(Protocol):
    def open(self, request: Request, timeout: float): ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class OpenBaoTransitConfig:
    """Operator-owned pin for one HTTPS Transit Ed25519 signing key."""

    base_url: str
    mount_path: str
    key_name: str
    key_version: int
    public_key: str
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.base_url) if type(self.base_url) is str else None
            port = parsed.port if parsed is not None else None
        except ValueError:
            parsed, port = None, None
        valid_url = (parsed is not None and parsed.scheme == "https" and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None and not parsed.query
                 and not parsed.fragment and parsed.path in ("", "/")
                 and (port is None or 1 <= port <= 65535))
        parts = self.mount_path.split("/") if type(self.mount_path) is str else []
        valid_path = bool(parts) and all(_KEY_PART.fullmatch(part) for part in parts)
        valid = (valid_url and valid_path and type(self.key_name) is str and _KEY_PART.fullmatch(self.key_name)
                 and type(self.key_version) is int and not isinstance(self.key_version, bool)
                 and 1 <= self.key_version <= 999_999_999 and type(self.timeout_seconds) in (int, float)
                 and not isinstance(self.timeout_seconds, bool) and 0 < self.timeout_seconds <= 10
                 and _public_key(self.public_key) is not None)
        if not valid:
            raise ValueError("invalid OpenBao Transit configuration")

    @property
    def endpoint_root(self) -> str:
        parsed = urlsplit(self.base_url)
        base_path = parsed.path.rstrip("/")
        path = base_path + "/v1/" + self.mount_path + "/"
        return urlunsplit(("https", parsed.netloc, path, "", ""))


def _public_key(value: object) -> Ed25519PublicKey | None:
    if type(value) is not str or len(value) != 44:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, UnicodeError):
        return None


@dataclass(frozen=True)
class TransitEd25519Signature:
    """A Transit signature bound to the exact configured key version."""

    value: str
    key_version: int

    def __post_init__(self) -> None:
        match = _SIGNATURE.fullmatch(self.value) if type(self.value) is str else None
        if (match is None or type(self.key_version) is not int or isinstance(self.key_version, bool)
                or int(match.group(1)) != self.key_version):
            raise ValueError("invalid OpenBao Transit signature")
        try:
            raw = base64.b64decode(match.group(2), validate=True)
            if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != match.group(2):
                raise ValueError
        except (ValueError, UnicodeError):
            raise ValueError("invalid OpenBao Transit signature") from None


class OpenBaoTransitEd25519:
    """One bounded sign/verify client; tokens are never stored on the instance."""

    def __init__(self, config: OpenBaoTransitConfig, *, transport: _Transport | None = None) -> None:
        if type(config) is not OpenBaoTransitConfig:
            raise ValueError("invalid OpenBao Transit configuration")
        self._config = config
        self._public_key = _public_key(config.public_key)
        self._transport = transport or build_opener(_NoRedirect())

    def sign(self, *, message: bytes, token: str) -> TransitEd25519Signature:
        encoded_input = self._input(message)
        self._assert_key_metadata(token, "signing unavailable")
        payload = {"input": encoded_input, "key_version": self._config.key_version}
        data = self._request("sign", payload, token, "signing unavailable")
        if (type(data) is not dict or set(data) not in
                ({"signature", "key_version"}, {"signature", "key_version", "public_key"})
                or type(data["key_version"]) is not int
                or data["key_version"] != self._config.key_version
                or ("public_key" in data and data["public_key"] != self._config.public_key)):
            raise OpenBaoTransitError("signing unavailable")
        try:
            signature = TransitEd25519Signature(data["signature"], self._config.key_version)
        except ValueError:
            raise OpenBaoTransitError("signing unavailable") from None
        try:
            self._public_key.verify(base64.b64decode(signature.value.rsplit(":", 1)[1], validate=True), message)
        except (InvalidSignature, ValueError, UnicodeError):
            raise OpenBaoTransitError("signing unavailable") from None
        # Do not accept a signature solely because a sign response supplied it.
        # Transit must also affirm this exact message/signature/key binding.
        if not self._verify(message, signature, token, "signing unavailable"):
            raise OpenBaoTransitError("signing unavailable")
        return signature

    def verify(self, *, message: bytes, signature: TransitEd25519Signature, token: str) -> bool:
        self._input(message)
        if type(signature) is not TransitEd25519Signature or signature.key_version != self._config.key_version:
            raise ValueError("invalid OpenBao Transit signature")
        try:
            self._public_key.verify(base64.b64decode(signature.value.rsplit(":", 1)[1], validate=True), message)
        except (InvalidSignature, ValueError, UnicodeError):
            return False
        self._assert_key_metadata(token, "verification unavailable")
        return self._verify(message, signature, token, "verification unavailable")

    def _verify(self, message: bytes, signature: TransitEd25519Signature, token: str, error: str) -> bool:
        payload = {"input": self._input(message), "signature": signature.value}
        data = self._request("verify", payload, token, error)
        if type(data) is not dict or set(data) != {"valid"} or type(data["valid"]) is not bool:
            raise OpenBaoTransitError(error)
        return data["valid"]

    def _assert_key_metadata(self, token: str, error: str) -> None:
        data = self._request("keys", None, token, error)
        if (type(data) is not dict or data.get("type") != "ed25519"
                or data.get("exportable") is not False or data.get("allow_plaintext_backup") is not False):
            raise OpenBaoTransitError(error)

    def _input(self, message: object) -> str:
        if type(message) is not bytes or len(message) > _MAX_INPUT_BYTES:
            raise ValueError("invalid signing input")
        return base64.b64encode(message).decode("ascii")

    def _request(self, operation: str, payload: dict[str, object] | None, token: object, error: str) -> dict[str, object]:
        if (type(token) is not str or not token or len(token) > 4096
                or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ValueError("invalid OpenBao Transit token")
        body = None if payload is None else json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        url = self._config.endpoint_root + operation + "/" + quote(self._config.key_name, safe="")
        headers = {
            "Content-Type": "application/json", "Accept": "application/json", "X-Vault-Token": token,
        }
        request = Request(url, data=body, method="GET" if payload is None else "POST", headers=headers)
        try:
            with self._transport.open(request, timeout=self._config.timeout_seconds) as response:
                if getattr(response, "status", None) != 200:
                    raise OpenBaoTransitError(error)
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if type(raw) is not bytes or len(raw) > _MAX_RESPONSE_BYTES:
                raise OpenBaoTransitError(error)
            decoded = json.loads(raw.decode("utf-8"))
            if not _envelope(decoded):
                raise OpenBaoTransitError(error)
            return decoded["data"]
        except OpenBaoTransitError:
            raise
        except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, UnicodeError, ValueError,
                json.JSONDecodeError):
            raise OpenBaoTransitError(error) from None


def _envelope(value: object) -> bool:
    """Accept only bounded, documented non-secret Vault response envelope fields."""
    if type(value) is not dict or "data" not in value or type(value["data"]) is not dict:
        return False
    permitted = {"data", "request_id", "lease_id", "renewable", "lease_duration",
                 "warnings", "mount_type", "auth", "wrap_info"}
    if not set(value).issubset(permitted):
        return False
    # OpenBao's ordinary response envelope carries these fields as null.
    # A wrapped response or auth material must never be interpreted as a
    # normal Transit result.
    if any(name in value and value[name] is not None for name in ("auth", "wrap_info")):
        return False
    scalar_strings = ("request_id", "lease_id", "mount_type")
    if any(name in value and (type(value[name]) is not str or len(value[name]) > 256) for name in scalar_strings):
        return False
    if "renewable" in value and type(value["renewable"]) is not bool:
        return False
    if "lease_duration" in value and (type(value["lease_duration"]) is not int or isinstance(value["lease_duration"], bool) or not 0 <= value["lease_duration"] <= 86_400):
        return False
    return ("warnings" not in value or value["warnings"] is None or type(value["warnings"]) is list
            and len(value["warnings"]) <= 16 and all(type(item) is str and len(item) <= 256 for item in value["warnings"]))
