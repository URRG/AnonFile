# M31 — fail-closed encrypted object envelopes

`app.encrypted_object_store` is a bounded cryptographic boundary for raw,
working, quarantine, and release object bytes.  It does not register a route,
provide a concrete S3 client, configure credentials, or make a production
deployment claim.

`EncryptedObjectStore.put` receives a strictly shaped tenant reference, object
reference, key reference, and at most 32 MiB of bytes. The resulting canonical
envelope is bounded to 48 MiB, including Base64 expansion and the bounded
wrapped-key field; that remains below the companion transport's 64 MiB cap. It
asks an injected
`DataKeyProvider` for an ephemeral AES-256 data key and a wrapped-key string,
then stores one canonical JSON envelope through an injected
`EncryptedByteTransport`.  The envelope has only version, wrapped data key,
96-bit nonce, and AES-GCM ciphertext-plus-tag.  Its digest and exact byte size
are recorded in `production_substrate.EncryptedObjectReference`; neither the
reference nor the control plane contains the wrapped key, nonce, ciphertext,
plaintext, or plaintext data key.

Both Transit key operations and AES-GCM use the same canonical
domain-separated context: envelope version, tenant reference, object
reference, and key reference.  Reads require the caller tenant to equal the
reference tenant, verify the exact stored-envelope digest and size, reject
noncanonical envelopes, unwrap the key with the same context, and authenticate
the GCM tag.  Any malformed input, provider/transport exception, digest
mismatch, context mismatch, or authentication failure becomes the fixed
`Encrypted object operation failed` error, without payload or key material.

The data-key provider and byte transport are intentional integration seams.
A future OpenBao provider must bind its wrapped-data-key generation and unwrap
operations to the supplied context. A future S3-compatible transport must
atomically create (not overwrite) and exactly return the supplied envelope
under the prevalidated tenant/object reference and expected digest. This
increment has no concrete provider/transport,
streaming/multipart support, retry/idempotency protocol, lifecycle erasure,
access-control policy, or live infrastructure test; it is not a production
object-store integration.
