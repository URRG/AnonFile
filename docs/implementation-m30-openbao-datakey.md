# M30 OpenBao Transit envelope data keys

`app.openbao_datakey` is an isolated worker-side adapter for envelope data
keys. It has no route, repository, logging, storage, or release-gate wiring.
It calls the documented OpenBao Transit `POST /transit/datakey/plaintext/:name`
and `POST /transit/decrypt/:name` endpoints, with a pre-flight read of the
configured key. The Transit API documents that `plaintext` datakey calls return
both a high-entropy data key and its wrapped counterpart; `associated_data` is
authenticated by AEAD ciphers on both paths. See the official
[Transit API](https://openbao.org/docs/api/secret/transit/).

## Caller contract

An operator pins HTTPS `base_url`, mount path, key name, opaque `key_ref` in
the existing `keyref:v1:<lowercase-name>` production-substrate format, and
one Transit key version. The configured Transit key must be `aes256-gcm96`,
non-derived, non-exportable, not plaintext-backup-enabled, not deletable,
support encryption/decryption, and report the configured version as its latest
version. Version drift fails closed. The adapter sends a fixed `bits=256` and a
required 1--4096 byte caller context as base64 `associated_data`, and the
configured `key_version` in the datakey request. The context
must be canonical, tenant/object/envelope-specific AAD supplied by the caller;
the adapter does not derive it from untrusted paths or accept a different key
reference.

`generate(key_ref=..., context=..., token=...)` returns immutable
`TransitDataKey(plaintext_key, wrapped_key, key_version)`. `plaintext_key` is
exactly 32 bytes, and `wrapped_key` is an opaque canonical Transit ciphertext.
The adapter requires both the server's `key_version` response field and the
ciphertext's embedded version to equal the configured version. `unwrap(...)` accepts
only that same opaque `key_ref`, exact ciphertext version, and context, and
returns only an exact 32-byte plaintext key. Callers must use the plaintext key
immediately for local authenticated encryption/decryption and must never persist
or log it. Python cannot guarantee memory zeroization, so this module makes no
such claim. The temporary result's representation redacts the plaintext key;
that is defense in depth, not permission to log result objects. M31 may persist only `wrapped_key` inside its authenticated ciphertext
envelope, never in metadata.

## Exact least-privilege policy

Issue a short-lived caller token whose policy contains only these literal paths
for the pinned mount/key; do not grant `create`, `delete`, `sudo`, list, export,
rotate, or wildcard transit capabilities:

```hcl
path "transit/keys/envelope-key" { capabilities = ["read"] }
path "transit/datakey/plaintext/envelope-key" { capabilities = ["update"] }
path "transit/decrypt/envelope-key" { capabilities = ["update"] }
```

The client requires HTTPS with normal certificate validation, a no-redirect
transport, no proxy path or credentials in the configured URL, a 10-second
maximum timeout, 16 KiB maximum response, canonical base64, and fixed errors
that exclude tokens, URLs, plaintext, and server bodies. OpenBao key creation,
rotation, deletion, importing/exporting, backup/restore, policy issuance, and
object storage are intentionally outside M30.
