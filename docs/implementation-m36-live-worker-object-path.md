# M36: live worker encrypted-object path gate

M36 exercises M33's `WorkerEncryptedObjects` composition against two separate,
disposable, TLS-enabled services in CI: the pinned OpenBao 2.5.5 image and the
pinned MinIO release already tested by M29 and M34. It does not modify the
worker implementation or make a production deployment claim.

The CI script generates and verifies private CAs/certificates, random masked
credentials, and two five-minute OpenBao tokens with no default policy. The
full token is limited to metadata-read, plaintext-data-key, and decrypt paths
for the one test key. The second token can read metadata but cannot decrypt.
No token, plaintext data key, or marker value is printed by the script.

The integration test writes and reads a synthetic marker through M33 and then
uses privileged test-only S3 access to prove the stored body is an encrypted
envelope rather than the marker. It also verifies cross-tenant use fails,
create-only duplicate storage fails without replacing the original, OpenBao
rejects a wrong associated-data context, the restricted token cannot decrypt,
and a privileged corrupted S3 body is rejected before decryption.

This result is narrowly an interoperability regression test for these exact
CI images and configurations. It does not validate an operational OpenBao or
S3 deployment, IAM design, key rotation, availability, retries, object
lifecycle, incident response, or a release delivery path.
