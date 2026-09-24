# M34: pinned S3-compatible interoperability gate

The M32 adapter relies on an S3 endpoint to atomically honor
`PutObject(If-None-Match: *)`. Unit fakes cannot establish that property for a
real deployment. CI therefore starts one disposable MinIO server over TLS and
executes the M32 adapter against it.

## Exact test boundary

- The workflow uses only
  `quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2`.
  That release's official notes include conditional-write fixes. The pin is
  intentional: a mutable tag, a different MinIO release, clustered mode, or
  any other provider is outside this result.
- The script creates random, masked, CI-only root credentials and an ephemeral
  certificate with `localhost` and `127.0.0.1` SANs. The SDK verifies that
  certificate; it never disables verification or falls back to HTTP.
- It creates a bucket, writes and reads ciphertext through M32, verifies that a
  repeat fails without overwriting the original, and sends eight concurrent
  create-only requests for a new key. Exactly one may succeed.
- It also proves valid-but-wrong tenant or object references cannot retrieve
  another scope's ciphertext, then simulates an out-of-band privileged
  overwrite and confirms M32's SHA-256 check fails closed.

This is an interoperability regression test for one server image and CI
configuration, **not** certification of MinIO or any S3-compatible provider.
Every production candidate must run equivalent repeated and concurrent
non-overwrite tests against its exact release, topology, versioning, object
lock, IAM/ACL, TLS, proxy, and storage-backend configuration before M32 is
enabled in a release path.

SeaweedFS is deliberately not used for this gate: its own
[compatibility report](https://github.com/seaweedfs/seaweedfs/blob/master/test/s3/compatibility/README.md)
has listed failed conditional `PutObject` cases, and a reported
[versioning/object-lock issue](https://github.com/seaweedfs/seaweedfs/issues/8073)
permitted an `If-None-Match` overwrite. The M32 design must not silently
substitute it. The selected MinIO
[release notes](https://github.com/minio/minio/releases/tag/RELEASE.2025-09-07T16-13-09Z)
include conditional-write fixes; that is a reason to test this exact release,
not a claim that it certifies a production topology.
