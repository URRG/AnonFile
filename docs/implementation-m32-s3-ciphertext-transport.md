# M32: S3-compatible ciphertext transport

This bounded adapter writes an already-encrypted byte sequence to one
deployment-configured S3-compatible endpoint and bucket. It is deliberately
not wired into API routes and does not create a claim that production object
storage is complete.

## Boundary

- The deployment injects a preconfigured S3 SDK client; its endpoint,
  credentials, TLS trust policy, and bucket are fixed outside request data.
  The adapter requires the SDK client's `meta.endpoint_url` to normalize to
  the same configured HTTPS endpoint; an HTTP or different endpoint fails at
  construction. Certificate validation and timeouts remain SDK deployment
  responsibilities and are not inferred from a configuration flag.
- `S3CiphertextTransportConfig` accepts HTTPS only and a portable
  DNS-compatible bucket name. The application must configure the injected
  SDK client with TLS certificate validation enabled. No client is constructed
  from an untrusted endpoint or request credentials.
- Tenant and object identifiers must be the exact
  `tenantref:v1:<43-base64url-chars>` and
  `objectref:v1:<43-base64url-chars>` forms and are hashed into the sole
  permitted key shape:
  `anonflow-ciphertext-v1/<tenant-sha256>/<object-sha256>`. They cannot provide
  a path, bucket, prefix, ACL, or delivery URL.
- `store` accepts bytes called `ciphertext`, checks a caller-provided lowercase
  SHA-256 against those exact bytes, adds that digest as metadata, and enforces
  a 64 MiB ceiling. It never receives plaintext or cryptographic keys.
- It issues one `PutObject` with `IfNoneMatch="*"` and `ACL="private"`.
  A 409/412 or the corresponding SDK condition codes is an existing-object
  failure. There is no HEAD-then-PUT or overwrite fallback.
- The adapter ignores ETag entirely. ETags are not a universal content digest,
  including for multipart or encrypted S3 writes. The independently supplied
  SHA-256 is the integrity assertion.
- A bounded `load` requests only that derived key. It validates the 200
  response's exact digest metadata and declared `ContentLength` before reading
  at most the configured maximum plus one byte, verifies the bytes again, and
  closes the SDK streaming body on every path. Partial (206), malformed,
  oversized, short, or digest-mismatched responses fail closed.

## Operational requirements and limitations

Use credentials whose policy is limited to `PutObject` on this private prefix,
and whose object store supports conditional `PutObject`. S3-compatible
providers differ: deploy-time interoperability tests must demonstrate that a
second identical write returns a conflict and never overwrites data.
This adapter does not certify any provider or configuration (including
SeaweedFS): prove repeated and concurrent create-only behavior against the
exact deployed version and settings before adoption.

The success envelope is bounded and checked only for a 200 status; response
fields such as ETag are never trusted as integrity evidence. This milestone has
no listing, deletion, lifecycle, multipart upload, retention lock,
server-side encryption policy, or delivery integration. Those require separate
threat modelling and end-to-end tests before a production release path can use
this adapter.

Primary semantics: [AWS PutObject conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html) and [PutObject response fields](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html).

M34 adds a CI-only [pinned interoperability gate](implementation-m34-s3-interoperability-ci.md)
for one disposable S3-compatible configuration. It is not a provider
certification and does not relax these deployment-specific requirements.
