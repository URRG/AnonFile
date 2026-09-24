# M31 — fail-closed encrypted object envelopes

`app.encrypted_object_store` is a bounded cryptographic boundary for raw,
working, quarantine, and release object bytes.  It does not register a route,
provide a concrete S3 client, configure credentials, or make a production
deployment claim.

`EncryptedObjectStore.put` receives a strictly shaped tenant reference, object
reference, key reference, immutable `PublicationPayloadBinding`, and at most
32 MiB of bytes. It recomputes the domain-separated payload digest and exact
size **before** asking KMS or S3 to do anything. The resulting canonical v3
envelope is bounded to 48 MiB, including Base64 expansion and the bounded
wrapped-key field; that remains below the companion transport's 64 MiB cap. It
asks an injected
`DataKeyProvider` for an ephemeral AES-256 data key and a wrapped-key string,
then stores one canonical JSON envelope through an injected
`EncryptedByteTransport`.  The envelope contains version, publication ref,
binding digest, payload digest, payload size, serialization identifier,
wrapped data key, 96-bit nonce, and AES-GCM ciphertext-plus-tag. Its digest and exact byte size
are recorded in `production_substrate.EncryptedObjectReference`; neither the
reference nor the control plane contains the wrapped key, nonce, ciphertext,
plaintext, or plaintext data key.
The temporary generated-key object's representation redacts its plaintext key,
but workers still must not log or retain that object.

Both Transit key operations and AES-GCM use the same canonical
domain-separated context: envelope version, tenant reference, object
reference, key reference, and immutable binding digest. Reads and recovery require the caller tenant to equal the
reference tenant, verify the exact stored-envelope digest and size, reject
noncanonical envelopes, unwrap the key with the same context, and authenticate
the GCM tag.  Any malformed input, provider/transport exception, digest
mismatch, binding/payload mismatch, context mismatch, or authentication failure becomes the fixed
`Encrypted object operation failed` error, without payload or key material.

Envelope versions before v3 are deliberately unreadable. Recovery decrypts,
recomputes the exact payload commitment, and verifies every embedded binding
field before returning a reference carrying the binding digest.

The data-key provider and byte transport are intentional integration seams.
A future OpenBao provider must bind its wrapped-data-key generation and unwrap
operations to the supplied context. A future S3-compatible transport must
atomically create (not overwrite) and exactly return the supplied envelope
under the prevalidated tenant/object reference and expected digest. This
increment has no concrete provider/transport,
streaming/multipart support, retry/idempotency protocol, lifecycle erasure,
access-control policy, or live infrastructure test; it is not a production
object-store integration.
