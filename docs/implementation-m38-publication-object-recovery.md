# M38: publication-bound object recovery

M38 addresses one narrow uncertainty: a conditional S3 `PutObject` can have
created an encrypted object even when the caller loses the success response.
It does not claim an atomic PostgreSQL/S3 transaction, start a worker, or
delete any object.

## Version break and binding

Encrypted-object envelopes and references are now version 3. A mandatory
`publicationref:v1:<43-base64url-chars>` is stored in the reference, in the
canonical envelope, in AES-GCM/OpenBao associated data, and as exact S3 object
metadata alongside the envelope SHA-256:

```text
anonflow-publication-ref = publicationref:v1:...
anonflow-sha256          = <lowercase envelope sha256>
```

The v1/v2 envelope shape is deliberately not read as v3. It fails
closed. Existing PostgreSQL metadata documents whose encrypted-object object
lacks `publication_ref` or a payload-binding digest likewise fail closed during decode; M38 provides no
automatic migration because assigning a publication identity after the fact
would falsely claim ownership. Operators must retain an old reader during any
controlled migration or explicitly re-encrypt/re-publish under a newly
authorized publication. No envelope, wrapped key, plaintext, ciphertext
bytes, S3 URL, or S3 key is stored in PostgreSQL metadata.

## Recovery contract

`WorkerEncryptedObjects.put` remains create-only. A duplicate is an error.
`put_or_recover` is the explicit ambiguous-result operation and may recover
only after the caller has already durably bound the publication ref, object
ref, key ref, immutable input plan, exact payload digest, byte size, and
serialization identifier. M39 supplies that intent and fencing
protocol; using this method without it is not a durable handoff.
Initial creation verifies the exact binding before KMS/S3 I/O. Recovery uses
the same binding to authenticate and recompute the stored payload commitment
without exposing recovered plaintext to compare a retry.

On a 409/412, recovery fetches only the derived private object key and accepts
it only when all of the following hold:

1. the exact publication metadata matches;
2. metadata SHA-256 is canonical and matches the bounded body bytes;
3. the canonical v3 envelope repeats every payload-binding field;
4. OpenBao unwrap succeeds under AAD containing the immutable binding digest;
5. AES-GCM authenticates; and
6. decrypted bytes recompute to the exact bound digest and byte size before a
   reconstructed reference is returned.

A wrong marker, tenant-derived key, digest, malformed envelope, wrong key/AAD,
or authentication failure is a fixed fail-closed error. M38 never overwrites
an existing key, never accepts the marker by itself as proof, and never
silently adopts an object through ordinary `put`.

## Remaining M39 requirement

There is still no cross-system atomicity. M39 must persist publication intent
before M38 I/O, fence final metadata attachment with the current worker claim,
and atomically finalize PostgreSQL metadata plus acknowledgement. An orphan or
CAS-conflicted object must be quarantined/retained for controlled remediation;
M38 intentionally performs no automatic deletion or retry policy.
