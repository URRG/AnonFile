# M37: explicit S3 SDK client factory

M37 supplies the deployment-owned constructor for M32's ciphertext-only
transport. It is not wired into an API route, does not fetch or rotate
credentials, and does not claim that an object-store deployment is production
ready.

## Boundary

- `S3ClientFactoryConfig` contains exactly one HTTPS endpoint, bucket, region,
  CA-bundle pathname, explicit access-key pair, namespace and size bound. Its
  `repr` is redacted; the credentials representation is redacted too.
- The factory requires an existing CA-bundle file and passes that exact path to
  boto3 as `verify`. It offers no option for `verify=False` or for silently
  falling back to the platform trust store.
- It creates a fresh `boto3.session.Session` with the explicit access key and
  secret. It does not call the module-level boto3 client/session helpers and
  does not select the shared-profile, environment, ECS, or EC2-instance
  metadata credential-provider chain.
- The client has a fixed endpoint and path-style S3 addressing, SigV4, a
  3-second connect timeout, 10-second read timeout, and at most two total
  attempts using the standard retry mode. Neither endpoint nor bucket comes
  from a request.
- The completed client is passed through `S3CiphertextTransport`, which checks
  that its reported endpoint exactly equals the independently validated M32
  endpoint. SDK exceptions and endpoint/client mismatches become one fixed
  `S3ClientFactoryError` without service detail, URLs, or credentials.

The access key pair must be issued and rotated with a short lifetime by the
deployment's chosen secret-management process. This milestone intentionally
does not implement a secret manager, identity federation, credential rotation,
network isolation, or provider authorization policy. A deployment must also
restrict the credential to the one private bucket/prefix and verify the exact
server and CA configuration end to end.

The implementation follows the documented [`Session.client`](https://docs.aws.amazon.com/boto3/latest/reference/core/session.html)
arguments and botocore [`Config`](https://botocore.amazonaws.com/v1/documentation/api/latest/reference/config.html)
for retries, timeouts, S3 addressing and signature behavior.
