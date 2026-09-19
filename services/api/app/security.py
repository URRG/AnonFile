"""Development-only authentication dispatch; no production identity claims."""
from __future__ import annotations
import hmac
import json
import os
from dataclasses import dataclass
from fastapi import HTTPException, Request

@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    roles: frozenset[str]

def load_principals() -> tuple[tuple[str, Principal], ...]:
    if os.getenv("ANONFLOW_ENV", "development") != "development":
        raise RuntimeError("Only explicit development mode is supported")
    raw = os.getenv("ANONFLOW_DEV_PRINCIPALS")
    if not raw:
        return ()
    try:
        if len(raw.encode("utf-8")) > 100_000:
            raise ValueError
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        entries = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError
        result, seen, identities = [], set(), set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"token", "subject", "tenant", "roles"}:
                raise ValueError
            token, subject, tenant, roles = (entry[k] for k in ("token", "subject", "tenant", "roles"))
            if not isinstance(token, str) or not 32 <= len(token) <= 512 or not token.isascii() or any(c.isspace() for c in token) or token in seen:
                raise ValueError
            if any(not isinstance(v, str) or not v.strip() or len(v) > 160 or not v.isprintable() for v in (subject, tenant)):
                raise ValueError
            if not isinstance(roles, list) or not roles or any(not isinstance(r, str) or r not in {"processor", "reviewer", "buyer"} for r in roles):
                raise ValueError
            if (tenant, subject) in identities:
                raise ValueError
            seen.add(token)
            identities.add((tenant, subject))
            result.append((token, Principal(subject, tenant, frozenset(roles))))
        return tuple(result)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise RuntimeError("Invalid development authentication configuration") from None


def configure_auth(app) -> None:
    """Choose one explicit auth adapter at startup, never fall back on errors."""
    if os.getenv("ANONFLOW_ENV", "development") != "development":
        raise RuntimeError("Only explicit development mode is supported")
    mode = os.getenv("ANONFLOW_AUTH_MODE", "dev-token")
    if mode not in {"dev-token", "jwt"}:
        raise RuntimeError("Invalid authentication mode")
    if mode == "jwt":
        from app.token_auth import load_jwt_verifier
        verifier = load_jwt_verifier()
        principals = ()
    else:
        principals = load_principals()
        verifier = None
    app.state.auth_mode = mode
    app.state.principals = principals
    app.state.jwt_verifier = verifier


def require_roles(*roles: str):
    def authorize(request: Request) -> Principal:
        mode = getattr(request.app.state, "auth_mode", "dev-token")
        principals = getattr(request.app.state, "principals", ())
        if mode == "dev-token" and not principals:
            raise HTTPException(503, "Development authentication is not configured")
        if mode not in {"dev-token", "jwt"}:
            raise HTTPException(503, "Authentication is not configured")
        authorization_headers = request.headers.getlist("authorization")
        if len(authorization_headers) != 1:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
        authorization = authorization_headers[0]
        scheme, _, token = authorization.partition(" ")
        maximum = 16_384 if mode == "jwt" else 512
        if (scheme.lower() != "bearer" or not token or not token.isascii()
                or len(token) > maximum or any(c.isspace() for c in token)):
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
        if mode == "jwt":
            verifier = getattr(request.app.state, "jwt_verifier", None)
            if verifier is None:
                raise HTTPException(503, "Authentication is not configured")
            principal = verifier.authenticate(token)
        else:
            principal = None
            for expected, candidate in principals:
                if hmac.compare_digest(expected, token):
                    principal = candidate
        if principal is None:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
        if not principal.roles.intersection(roles):
            raise HTTPException(403, "Access denied")
        return principal
    return authorize
