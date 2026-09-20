# M12 privacy-evidence attestation authority

`app.privacy_evidence_authority` adds a deliberately narrow, worker-side Ed25519
attestation boundary for the M11 privacy-evidence policy.  A tenant-scoped
authority issues a `PrivacyEvidenceReference` only for its configured issuer
and only when the evidence kind matches that issuer's exact policy requirement.
The reference signature covers the tenant, opaque authority identity, evidence
reference and digest, bounded measurement and validity times, every binding
field (candidate, processing, rights, opaque recipient, purpose, method, and
candidate expiry), and the complete policy canonical form (policy ID, method,
age window, all required issuers, and thresholds).

References contain no source bytes, candidate bytes, field names, paths,
subjects, recipient names, release handles, credentials, or the HMAC key.
`to_policy_evidence` emits an Ed25519-signed policy record only after the
reference is re-verified.  Its `policy_verifier` contains the corresponding
public key only and has no issuance/signing API; it can be supplied to
`assess_privacy_evidence` without sharing the issuer's private key.  This
preserves the M11 policy's fixed outcome:
even a complete, valid set is only `INSUFFICIENT_EVIDENCE` and requires an
independent release authorization.

Private and public keys are parsed from canonical, strict base64 raw Ed25519
encodings.  The authority is fail-closed for malformed values, subclasses, altered
bindings or policies, wrong tenant/key, key rotation, inactive authority,
wrong issuer/kind, and expiry-window violations.  It is an in-process HMAC
primitive only: production still requires separated key custody in KMS/HSM,
durable append-only evidence/provenance storage, independently governed
evaluators, authorization and delivery controls, and external privacy/security
review.  This milestone intentionally has no API route, repository, worker
registration, candidate state transition, release, or delivery integration.
