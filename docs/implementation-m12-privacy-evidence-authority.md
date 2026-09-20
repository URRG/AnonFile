# M12 privacy-evidence attestation authority

`app.privacy_evidence_authority` adds a deliberately narrow, worker-side HMAC
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
`assess_policy` keeps reference verification, transient policy attestation,
and policy assessment inside the tenant authority boundary.  It returns only
the existing policy decision: no verifier, key-bearing object, signing
capability, or separately usable policy attestation is exposed.  This
preserves the M11 policy's fixed outcome:
even a complete, valid set is only `INSUFFICIENT_EVIDENCE` and requires an
independent release authorization.

The authority is fail-closed for malformed values, subclasses, altered
bindings or policies, wrong tenant/key, key rotation, inactive authority,
wrong issuer/kind, and expiry-window violations.  It is an in-process HMAC
primitive only: production still requires separated key custody in KMS/HSM,
durable append-only evidence/provenance storage, independently governed
evaluators, authorization and delivery controls, and external privacy/security
review.  This milestone intentionally has no API route, repository, worker
registration, candidate state transition, release, or delivery integration.
