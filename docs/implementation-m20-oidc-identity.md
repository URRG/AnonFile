# M20: OIDC/OAuth access-token identity foundation

This increment is a narrow, fail-closed resource-server identity foundation.
It does not enable customer processing, customer-data admission, export,
approval, delivery, or a production deployment.  Existing release and output
gates remain closed; durable storage, KMS/HSM custody, network isolation,
operations, and independent security review are still required.

## Explicit configuration

`ANONFLOW_ENV` must be exactly `development` or `production`.  In production,
`ANONFLOW_AUTH_MODE=jwt` is mandatory: `dev-token` is rejected at startup and
there is no fallback between adapters.  Configure all of the following from a
deployment secret/configuration system:

- `ANONFLOW_JWT_ISSUER` — the one exact trusted issuer string.
- `ANONFLOW_JWT_AUDIENCE` — the one exact resource audience string.
- `ANONFLOW_JWKS_PATH` — an operator-pinned ordinary local file containing
  only the public JWKS accepted for this resource server.  It cannot be an
  HTTP(S), UNC, or token-provided location.
- `ANONFLOW_JWT_BINDINGS` — JSON bindings of exact `subject`, `tenant`, and
  allowed `roles`.  Tenant and role claims in an access token never grant
  authority; only this server configuration does.

The verifier accepts only a signed `RS256` `typ=at+jwt` access token with an
explicit configured `kid`, exact issuer/audience, subject, and finite
`exp`/`iat`/`nbf` claims.  It rejects duplicate JOSE/claim members, duplicate
Authorization headers, unsupported critical or token-selected JOSE fields,
wrong algorithms, expired/not-yet-valid tokens, untrusted issuers/audiences,
and unbound subjects.  Invalid authentication is a fixed 401 response;
signature-valid but unbound or unauthorized identities receive 403.

## Public-key rotation and revocation

The local JWKS path is the pin.  Use atomic replace to publish a complete
bundle.  During rotation, publish both old and new public keys; after all
valid old access tokens have expired, remove the old key.  The verifier reads
the pinned bundle for every authentication, so additions and removals take
effect without restart.  A malformed, unavailable, or partially published
replacement fails the affected authentication closed.  Do not rely on this
mechanism for issuer-side token revocation by subject or session: use short
access-token lifetimes and the identity provider's lifecycle controls.

This adapter intentionally performs no discovery, remote JWKS download,
introspection, login, refresh, or token exchange.  Those capabilities require
a separately reviewed production identity integration.
