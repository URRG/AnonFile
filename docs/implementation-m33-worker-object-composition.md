# M33: bounded worker encrypted-object composition

`app.worker_encrypted_objects` composes the prior isolated M30, M31, and M32
boundaries for a worker. It remains outside HTTP routes, repositories,
delivery, and production deployment claims.

Construction accepts deployment-owned, configured `OpenBaoTransitDataKey` and
`S3CiphertextTransport` instances only. A worker calls `put`, `get`, recovery,
or create-or-recover with an exact immutable payload binding and an
explicit short-lived OpenBao token for that one operation. The composition
creates a call-scoped `DataKeyProvider` which forwards the M31 canonical AAD
unchanged into M30's `generate` or `unwrap`. The long-lived worker composition
does not store a token, and the returned M31 reference exposes neither it nor
a plaintext data key. `get` intentionally returns the retrieved plaintext to
its immediate worker caller. Python cannot guarantee memory zeroization;
callers must not retain the token or returned plaintext longer than their
immediate operation.

The private M31 byte-transport adapter converts its full `sha256:<hex>`
reference digest to M32's raw hexadecimal digest. It sends only M31's encrypted
envelope bytes to M32, validates M32's returned opaque key, digest, and size,
and never returns that S3 key or any URL. On reads it independently verifies
the returned key and digest before M31 performs its own canonical-envelope and
AES-GCM checks. Misuse, token/KMS/S3 failures, duplicate objects, tenant or AAD
mismatches, payload-commitment mismatches, and malformed adapter results fail closed.
The binding check runs before KMS/S3 on initial creation; recovery authenticates
the encrypted bytes against the same binding without exposing them for a retry comparison.

M38 adds an explicit publication-bound create-or-recover operation above this
composition; see [M38](implementation-m38-publication-object-recovery.md).
This is still not a production release path. It has no worker scheduler, token
issuer, credential rotation, object lifecycle/erasure, multipart support,
durable publication intent/fencing, route wiring, deployment configuration, or
end-to-end infrastructure certification.
