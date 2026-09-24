# M29 OpenBao Transit interoperability verification

`services/api/tests/test_openbao_transit_integration.py` is an opt-in live
integration test of `app.openbao_transit` and `app.openbao_datakey`. It does not run in normal pytest
invocations. It needs `OPENBAO_TRANSIT_INTEGRATION=1` plus an HTTPS URL, a CA
trusted by Python, a narrowly scoped token, a metadata-only/sign token for the
negative policy check, and the exact public-key/version pins.

GitHub Actions runs `services/api/scripts/run-openbao-transit-integration.sh` in
an isolated job. The harness starts the official `openbao/openbao` 2.5.5
linux/amd64 image pinned to its manifest digest, using `bao server -dev-tls`.
It reads the generated `vault-ca.pem` and supplies it through `SSL_CERT_FILE`;
the application code keeps ordinary HTTPS certificate and hostname validation.
It never sets a skip-verify option or disables certificate verification.

The harness generates an ephemeral root token in memory, masks it, does not
write it to the workspace, and destroys the container after the test. That root
token provisions one non-exportable, no-plaintext-backup `ed25519` Transit key,
then issues two five-minute tokens:

- `m29-transit-integration`: metadata read plus exact-key sign and verify.
- `m29-transit-sign-only`: metadata read plus exact-key sign, deliberately no
  verify permission.

It also provisions a separate non-derived `aes256-gcm96` envelope key and two
five-minute M30 tokens. One has read plus exact plaintext-datakey/decrypt paths;
the other deliberately lacks decrypt. The live test generates a real 32-byte
DEK with canonical AAD, unwraps it, rejects wrong AAD, and observes the expected
fixed failure for the no-decrypt token. This checks the actual OpenBao datakey
ciphertext response shape and version prefix without exposing a plaintext key.

The live assertion signs and verifies with the first token, rejects both a
genuine signature presented for a different message and a fabricated signature
through the pinned local public-key check, and confirms the second token turns a
verify request into the adapter's fixed `verification unavailable` failure. It
therefore tests the real API contract and policy boundary without claiming
production deployment coverage.

For a local, disposable run, install the API test requirements and Docker, then
run:

```bash
bash services/api/scripts/run-openbao-transit-integration.sh
```

This is a development/CI-only harness. OpenBao documents dev mode as insecure
and non-durable; never use it in production. Production operators must instead
provision their own TLS endpoint, CA trust, key, policy, short-lived credentials,
and rotation process as described in the M27 operator contract.
