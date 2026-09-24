"""Fail-closed OpenBao Transit envelope data-key boundary.

The adapter is deliberately not connected to HTTP routes, repositories, or
logging.  It only calls the exact, operator-pinned Transit metadata, plaintext
datakey and decrypt paths.  A caller owns the short-lived token and must keep
the returned plaintext data-encryption key in its immediate cryptographic
operation; this module has no persistence facility for it.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import re
import socket
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


_MAX_CONTEXT_BYTES = 4096
_MAX_RESPONSE_BYTES = 16 * 1024
_KEY_PART = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_KEY_REF = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_WRAPPED_KEY = re.compile(r"vault:v([1-9][0-9]{0,8}):([A-Za-z0-9+/]{80})\Z")


class OpenBaoDataKeyError(RuntimeError):
    """A fixed error that never incorporates a token, URL, or response."""


class _Transport(Protocol):
    def open(self, request: Request, timeout: float): ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class OpenBaoDataKeyConfig:
    """Operator pin for one non-derived AES-256-GCM Transit wrapping key."""

    base_url: str
    mount_path: str
    key_name: str
    key_ref: str
    key_version: int
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.base_url) if type(self.base_url) is str else None
            port = parsed.port if parsed is not None else None
        except ValueError:
            parsed, port = None, None
        valid_url = (parsed is not None and parsed.scheme == "https" and bool(parsed.hostname)
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment and parsed.path in ("", "/")
                     and (port is None or 1 <= port <= 65535))
        parts = self.mount_path.split("/") if type(self.mount_path) is str else []
        valid_path = bool(parts) and all(_KEY_PART.fullmatch(part) for part in parts)
        valid = (valid_url and valid_path and type(self.key_name) is str
                 and _KEY_PART.fullmatch(self.key_name) and type(self.key_ref) is str
                 and _KEY_REF.fullmatch(self.key_ref) and type(self.key_version) is int
                 and not isinstance(self.key_version, bool) and 1 <= self.key_version <= 999_999_999
                 and type(self.timeout_seconds) in (int, float)
                 and not isinstance(self.timeout_seconds, bool) and 0 < self.timeout_seconds <= 10)
        if not valid:
            raise ValueError("invalid OpenBao data-key configuration")

    @property
    def endpoint_root(self) -> str:
        parsed = urlsplit(self.base_url)
        return urlunsplit(("https", parsed.netloc,
                           parsed.path.rstrip("/") + "/v1/" + self.mount_path + "/", "", ""))


@dataclass(frozen=True)
class TransitDataKey:
    """Ephemeral plaintext DEK paired with its opaque Transit-wrapped form."""

    plaintext_key: bytes = field(repr=False)
    wrapped_key: str
    key_version: int

    def __post_init__(self) -> None:
        if type(self.plaintext_key) is not bytes or len(self.plaintext_key) != 32:
            raise ValueError("invalid Transit data key")
        if _wrapped_key_version(self.wrapped_key) != self.key_version:
            raise ValueError("invalid Transit data key")


class OpenBaoTransitDataKey:
    """Generate and unwrap one AES-256 envelope key for an exact opaque key ref."""

    def __init__(self, config: OpenBaoDataKeyConfig, *, transport: _Transport | None = None) -> None:
        if type(config) is not OpenBaoDataKeyConfig:
            raise ValueError("invalid OpenBao data-key configuration")
        self._config = config
        self._transport = transport or build_opener(_NoRedirect())

    def generate(self, *, key_ref: str, context: bytes, token: str) -> TransitDataKey:
        self._key_ref(key_ref)
        associated_data = self._context(context)
        self._assert_key_metadata(token, "data-key generation unavailable")
        data = self._request("datakey/plaintext", {"bits": 256, "key_version": self._config.key_version,
                                                     "associated_data": associated_data},
                             token, "data-key generation unavailable")
        if (type(data) is not dict or set(data) != {"plaintext", "ciphertext", "key_version"}
                or type(data["key_version"]) is not int
                or data["key_version"] != self._config.key_version):
            raise OpenBaoDataKeyError("data-key generation unavailable")
        plaintext = _base64_bytes(data["plaintext"], 32)
        version = _wrapped_key_version(data["ciphertext"])
        if plaintext is None or version != self._config.key_version:
            raise OpenBaoDataKeyError("data-key generation unavailable")
        return TransitDataKey(plaintext, data["ciphertext"], version)

    def unwrap(self, *, key_ref: str, wrapped_key: str, context: bytes, token: str) -> bytes:
        self._key_ref(key_ref)
        associated_data = self._context(context)
        if _wrapped_key_version(wrapped_key) != self._config.key_version:
            raise ValueError("invalid Transit wrapped key")
        self._assert_key_metadata(token, "data-key unwrap unavailable")
        data = self._request("decrypt", {"ciphertext": wrapped_key, "associated_data": associated_data},
                             token, "data-key unwrap unavailable")
        if type(data) is not dict or set(data) != {"plaintext"}:
            raise OpenBaoDataKeyError("data-key unwrap unavailable")
        plaintext = _base64_bytes(data["plaintext"], 32)
        if plaintext is None:
            raise OpenBaoDataKeyError("data-key unwrap unavailable")
        return plaintext

    def _key_ref(self, value: object) -> None:
        if value != self._config.key_ref:
            raise ValueError("invalid Transit key reference")

    def _context(self, value: object) -> str:
        if type(value) is not bytes or not value or len(value) > _MAX_CONTEXT_BYTES:
            raise ValueError("invalid Transit key context")
        return base64.b64encode(value).decode("ascii")

    def _assert_key_metadata(self, token: str, error: str) -> None:
        data = self._request("keys", None, token, error)
        if (type(data) is not dict or data.get("type") != "aes256-gcm96"
                or data.get("derived") is not False or data.get("exportable") is not False
                or data.get("allow_plaintext_backup") is not False
                or data.get("deletion_allowed") is not False
                or data.get("supports_encryption") is not True or data.get("supports_decryption") is not True
                or data.get("latest_version") != self._config.key_version
                or type(data.get("min_decryption_version")) is not int
                or type(data.get("min_encryption_version")) is not int
                or not 0 <= data["min_decryption_version"] <= self._config.key_version
                or not 0 <= data["min_encryption_version"] <= self._config.key_version):
            raise OpenBaoDataKeyError(error)

    def _request(self, operation: str, payload: dict[str, object] | None, token: object, error: str) -> dict[str, object]:
        if (type(token) is not str or not token or len(token) > 4096
                or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ValueError("invalid OpenBao data-key token")
        body = None if payload is None else json.dumps(payload, ensure_ascii=True, allow_nan=False,
                                                       separators=(",", ":")).encode("ascii")
        suffix = operation + "/" + quote(self._config.key_name, safe="")
        request = Request(self._config.endpoint_root + suffix, data=body,
                          method="GET" if payload is None else "POST",
                          headers={"Content-Type": "application/json", "Accept": "application/json",
                                   "X-Vault-Token": token})
        try:
            with self._transport.open(request, timeout=self._config.timeout_seconds) as response:
                if getattr(response, "status", None) != 200:
                    raise OpenBaoDataKeyError(error)
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if type(raw) is not bytes or len(raw) > _MAX_RESPONSE_BYTES:
                raise OpenBaoDataKeyError(error)
            decoded = json.loads(raw.decode("utf-8"))
            if not _envelope(decoded):
                raise OpenBaoDataKeyError(error)
            return decoded["data"]
        except OpenBaoDataKeyError:
            raise
        except (HTTPError, URLError, TimeoutError, socket.timeout, OSError, UnicodeError, ValueError,
                json.JSONDecodeError):
            raise OpenBaoDataKeyError(error) from None


def _base64_bytes(value: object, expected_length: int) -> bytes | None:
    if type(value) is not str:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
        return decoded if len(decoded) == expected_length and base64.b64encode(decoded).decode("ascii") == value else None
    except (ValueError, UnicodeError):
        return None


def _wrapped_key_version(value: object) -> int | None:
    match = _WRAPPED_KEY.fullmatch(value) if type(value) is str else None
    if match is None:
        return None
    try:
        decoded = base64.b64decode(match.group(2), validate=True)
        if len(decoded) != 60 or base64.b64encode(decoded).decode("ascii") != match.group(2):
            return None
        return int(match.group(1))
    except (ValueError, UnicodeError):
        return None


def _envelope(value: object) -> bool:
    if type(value) is not dict or "data" not in value or type(value["data"]) is not dict:
        return False
    permitted = {"data", "request_id", "lease_id", "renewable", "lease_duration", "warnings",
                 "mount_type", "auth", "wrap_info"}
    if not set(value).issubset(permitted) or any(name in value and value[name] is not None for name in ("auth", "wrap_info")):
        return False
    if any(name in value and (type(value[name]) is not str or len(value[name]) > 256)
           for name in ("request_id", "lease_id", "mount_type")):
        return False
    if "renewable" in value and type(value["renewable"]) is not bool:
        return False
    if "lease_duration" in value and (type(value["lease_duration"]) is not int
                                       or isinstance(value["lease_duration"], bool)
                                       or not 0 <= value["lease_duration"] <= 86_400):
        return False
    return ("warnings" not in value or value["warnings"] is None or type(value["warnings"]) is list
            and len(value["warnings"]) <= 16
            and all(type(item) is str and len(item) <= 256 for item in value["warnings"]))
