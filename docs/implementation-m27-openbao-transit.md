# M27 OpenBao Transit Ed25519 adapter

`app.openbao_transit` is a deliberately isolated worker-side adapter for a
pre-provisioned OpenBao Transit `ed25519` key. It reads only its configured
key metadata and calls `POST /v1/:mount/sign/:key` and
`POST /v1/:mount/verify/:key`, matching the official
[Transit sign/verify API](https://openbao.org/docs/api/secret/transit/). It is
not wired into API routes, existing issuers, persistence, or release controls.

## Operator contract

Operators configure an HTTPS origin `base_url` (no proxy path), Transit mount path, key name, exact
positive key version, canonical base64 raw Ed25519 public key for that version,
and a timeout no longer than ten seconds. The adapter
does not accept an endpoint, key, or version from a work request. It sends the
configured `key_version` to sign and accepts only `vault:v<that-version>:`
Ed25519 signatures (64-byte payload); verification accepts only that bound
signature object. Before either operation it requires key metadata to report
`type=ed25519`, `exportable=false`, and `allow_plaintext_backup=false`; after
signing it verifies the exact message/signature locally using the pinned public
key and independently calls Transit verify before returning. Transit envelopes
may include only bounded standard response metadata in addition to `data`;
unexpected fields fail closed. TLS certificate validation remains the standard Python HTTPS
validation, redirects are rejected, requests are single-item only, input is at
most 64 KiB, and response bodies are at most 16 KiB.

The caller provides a short-lived `X-Vault-Token` value from its secret manager
for each invocation. The adapter neither stores it nor includes it, a response
body, or the service URL in errors. Failures are fixed `signing unavailable` or
`verification unavailable` errors. Any malformed/non-200/oversize response,
network error, timeout, or redirect fails closed.

## Key custody and operations

Provision the key separately in the self-hosted OpenBao deployment as type
`ed25519`; grant the service policy only `read` on the exact configured
`transit/keys/:name` metadata path plus `update` on the exact configured sign
and verify paths. The metadata read is required before every operation to
confirm the key remains Ed25519, non-exportable, and without plaintext backup;
it does not retrieve or retain private key material. Manage rotation/version retention
outside this adapter. This code intentionally performs no key creation,
rotation, deletion, import, export, backup, restore, or raw private-key
handling. Rotate by a separately approved operator process, then deploy a
configuration pinned to the new version only after dependent signatures have a
defined retention/migration plan.

Unit tests use a fake HTTP transport for success, redirects, timeouts, malformed
payloads, oversized or forged responses, and signature-version mismatch. The
separate M29 integration harness verifies interoperability with a genuine,
disposable OpenBao server; see `implementation-m29-openbao-integration.md`.
