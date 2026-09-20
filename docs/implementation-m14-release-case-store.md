# M14: controlled release-case persistence

This slice persists the M13 immutable `ReleaseCase` as a narrow control-plane
record. It does not approve a release, evaluate privacy evidence, expose a
candidate, create a delivery, or create a download URL.

`POST /processing-runs/{run_id}/release-cases` takes no JSON body. A processor
must send exactly one idempotency key. The server obtains the current private
candidate and processing run, then derives all signed scope from those live
controls: candidate digest, run/request/mode/policy provenance, source-safe
ingestion metadata digest, rights digest, purpose, and method provenance. The
recipient and contract scope come only from local tenant authority
configuration; they are never request fields. `GET /release-cases/{case_id}`
is available only to that tenant's processor or reviewer and re-verifies the
case against the current authority and every dependency.

The stored payload contains a signed case plus its run ID/idempotency key. It
contains no source/candidate bytes, raw recipient, contract value, delivery
handle, authorization state, or policy outcome. The API view returns only
opaque/digest-based identifiers and permanently states
`NO_RELEASE_AUTHORIZATION`.

Authority configuration is opt-in. `ANONFLOW_RELEASE_CASE_AUTHORITIES` is a
JSON array, one entry per tenant:

```text
[{"tenant":"synthetic","issuer_key_id":"release-case-2026-01","expires_at":"2027-01-01T00:00:00Z","private_key":"<base64-ed25519-32-byte-private-key>","recipient_commitment_salt":"<base64-random-32-byte-salt>","contract_reference":"contract-reference:v1:<43-base64url-chars>","contract_digest":"sha256:<64-lowercase-hex>","contract_expires_at":"2027-01-01T00:00:00Z"}]
```

The authority key and recipient salt must remain in a secret manager in real
deployments. This local development loader is not KMS/HSM custody. Missing,
malformed, expired, rotated, or tenant-mismatched authority configuration fails
closed. Cases expire at the earliest candidate, run, rights, contract,
authority, or local-control lifetime. Dataset/policy/rights deletion or expiry
tombstones the dependent run, candidate evidence, and release cases; a
qualification transition to quarantine tombstones existing cases as well.

The tests cover memory and encrypted SQLite stores, idempotency, tenant/role
isolation, rejected request bodies, authority absence/expiry, tampering,
configuration drift, cross-run replay, and dependency invalidation.
