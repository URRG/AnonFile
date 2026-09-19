"""Explicit local-development principals; never a production identity provider."""
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
        entries = json.loads(raw)
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
    except (ValueError, TypeError, KeyError, RecursionError):
        raise RuntimeError("Invalid development authentication configuration") from None

def require_roles(*roles: str):
    def authorize(request: Request) -> Principal:
        principals = request.app.state.principals
        if not principals:
            raise HTTPException(503, "Development authentication is not configured")
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.isascii() or len(token) > 512:
            raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
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
