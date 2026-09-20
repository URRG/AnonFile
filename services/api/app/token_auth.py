"""Offline JWT resource-server adapter for synthetic/local development only.

This is not OIDC discovery, login, refresh, introspection or online key rotation.
The operator supplies a trusted local public JWKS and restarts to change keys or
bindings. No token header can select a URL, algorithm, or authority. Only the
deliberately narrow RS256/at+jwt access-token profile is supported.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.security import Principal

MAX_TOKEN_BYTES = 16_384
MAX_CONFIG_BYTES = 32_000
MAX_JWKS_BYTES = 128_000
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_ROLES = frozenset({"processor", "reviewer", "buyer", "evaluator"})


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError


def _strict_json(raw: str | bytes):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_no_constant)


def _identifier(value, maximum=160):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or not value.isprintable()):
        raise ValueError
    value.encode("utf-8")
    return value


def _decode_segment(value: str) -> bytes:
    if not _BASE64URL.fullmatch(value):
        raise ValueError
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError
    return raw


def _config_env(name, maximum=MAX_CONFIG_BYTES):
    value = os.environ.get(name)
    if value is None or len(value.encode("utf-8")) > maximum:
        raise ValueError
    return value


def _load_keys(path: str) -> Mapping[str, rsa.RSAPublicKey]:
    # Reject remote/UNC/device paths. Only an explicit ordinary local file is read.
    if not path or "://" in path or path.replace("\\", "/").startswith("//") or "\x00" in path:
        raise ValueError
    candidate = Path(path)
    if not candidate.is_file():
        raise ValueError
    with candidate.open("rb") as stream:
        raw = stream.read(MAX_JWKS_BYTES + 1)
    if len(raw) > MAX_JWKS_BYTES:
        raise ValueError
    document = _strict_json(raw)
    if not isinstance(document, dict) or set(document) != {"keys"}:
        raise ValueError
    keys = document["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 16:
        raise ValueError
    result = {}
    seen_numbers = set()
    for key in keys:
        if (not isinstance(key, dict) or not {"kty", "kid", "n", "e"} <= set(key)
                or not set(key) <= {"kty", "kid", "n", "e", "alg", "use", "key_ops"}
                or key["kty"] != "RSA" or key.get("alg", "RS256") != "RS256"
                or key.get("use", "sig") != "sig"
                or ("key_ops" in key and key["key_ops"] != ["verify"])):
            raise ValueError
        kid = _identifier(key["kid"], 128)
        if kid in result or not isinstance(key["n"], str) or not isinstance(key["e"], str):
            raise ValueError
        modulus, exponent = _decode_segment(key["n"]), _decode_segment(key["e"])
        if (not 256 <= len(modulus) <= 1024 or not 1 <= len(exponent) <= 5
                or modulus[0] == 0 or exponent[0] == 0):
            raise ValueError
        n, e = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
        if not 2048 <= n.bit_length() <= 8192 or e < 3 or e % 2 == 0 or e > 2**32 + 1:
            raise ValueError
        if (n, e) in seen_numbers:
            raise ValueError
        seen_numbers.add((n, e))
        result[kid] = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    return MappingProxyType(result)


def _load_bindings(raw: str) -> Mapping[str, Principal]:
    rows = _strict_json(raw)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise ValueError
    result = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"subject", "tenant", "roles"}:
            raise ValueError
        subject, tenant = _identifier(row["subject"]), _identifier(row["tenant"])
        roles = row["roles"]
        if (subject in result or not isinstance(roles, list) or not 1 <= len(roles) <= 3
                or any(not isinstance(role, str) or role not in _ROLES for role in roles)
                or len(set(roles)) != len(roles)):
            raise ValueError
        result[subject] = Principal(subject, tenant, frozenset(roles))
    return MappingProxyType(result)


@dataclass(frozen=True)
class JWTVerifier:
    issuer: str
    audience: str
    keys: Mapping[str, rsa.RSAPublicKey]
    bindings: Mapping[str, Principal]

    def authenticate(self, token: str) -> Principal:
        try:
            if not isinstance(token, str) or not token.isascii() or not 1 <= len(token) <= MAX_TOKEN_BYTES:
                raise ValueError
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError
            header_bytes, claims_bytes, signature = (_decode_segment(part) for part in parts)
            if len(header_bytes) > 1024 or not 256 <= len(signature) <= 1024:
                raise ValueError
            header, claims = _strict_json(header_bytes), _strict_json(claims_bytes)
            if (not isinstance(header, dict) or set(header) != {"alg", "typ", "kid"}
                    or header["alg"] != "RS256" or header["typ"] != "at+jwt"):
                raise ValueError
            kid = _identifier(header["kid"], 128)
            key = self.keys.get(kid)
            if key is None or not isinstance(claims, dict):
                raise ValueError
            if not {"iss", "aud", "sub", "exp", "iat", "nbf"} <= set(claims):
                raise ValueError
            if (claims["iss"] != self.issuer or not isinstance(claims["aud"], str)
                    or claims["aud"] != self.audience):
                raise ValueError
            subject = _identifier(claims["sub"])
            for name in ("exp", "iat", "nbf"):
                value = claims[name]
                if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 253_402_300_799:
                    raise ValueError
            if not claims["iat"] < claims["exp"] or not claims["nbf"] < claims["exp"]:
                raise ValueError
            # The algorithm and key come only from trusted configuration. PyJWT
            # checks the signature and claims; strict checks above avoid coercion.
            jwt.decode(token, key=key, algorithms=["RS256"], issuer=self.issuer,
                       audience=self.audience, leeway=0,
                       options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf"], "strict_aud": True})
            now = time.time()
            if claims["exp"] <= now or claims["iat"] > now or claims["nbf"] > now:
                raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError,
                binascii.Error, jwt.PyJWTError):
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"}) from None
        principal = self.bindings.get(subject)
        if principal is None:
            raise HTTPException(403, "Access denied")
        return principal


def load_jwt_verifier() -> JWTVerifier:
    try:
        issuer = _identifier(_config_env("ANONFLOW_JWT_ISSUER", 2048), 2048)
        audience = _identifier(_config_env("ANONFLOW_JWT_AUDIENCE", 512), 512)
        keys = _load_keys(_config_env("ANONFLOW_JWKS_PATH", 4096))
        bindings = _load_bindings(_config_env("ANONFLOW_JWT_BINDINGS"))
        return JWTVerifier(issuer, audience, keys, bindings)
    except (ValueError, TypeError, KeyError, UnicodeError, OSError, RecursionError, OverflowError):
        raise RuntimeError("Invalid JWT authentication configuration") from None
