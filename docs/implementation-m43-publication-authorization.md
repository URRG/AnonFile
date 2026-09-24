# M43a publication-authorization attestation contract

`app.publication_authorization` defines a strict, metadata-only, externally
issued Ed25519 assertion over one M39 plan and M42 payload binding. It commits
to tenant/publication, plan and metadata destination, payload-binding digest,
release-case/privacy-decision evidence, two approval digests, and the rights,
contract, recipient and purpose commitments.

The module has no private-key loader and no access to M18/M21 storage. A
successful signature says only that a pinned external issuer signed this exact
scope for at most five minutes. It does **not** establish that a live rights,
privacy, M18, M21, or approval check occurred. A later admission integration
must independently perform and persist those checks before calling M39.

The verifier accepts only raw 32-byte Ed25519 public-key pins selected by an
exact `(tenant_ref, issuer_key_id)` pair. It rejects any altered plan, target, tenant,
publication, binding, signature, future-issued, expired, or untrusted grant.
It never accepts a wildcard, unknown key, private key, or compatibility wire
shape. Pin removal or revocation takes effect only when a process receives a
new verifier configuration (currently restart/redeploy); production paths
remain closed. A signature still does not prove live M18/M21 checks.
