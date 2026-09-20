# M12: operational linkage-risk evidence

M12 turns the bounded M11 `linkage_risk` primitive into an authenticated,
tenant-scoped control-plane endpoint:

- `POST /processing-runs/{run_id}/linkage-risk-evidence` accepts no body and
  requires a processor-owned run plus one idempotency key.
- `GET /processing-runs/{run_id}/linkage-risk-evidence/{evidence_id}` is
  limited to same-tenant processors and reviewers.
- `ANONFLOW_LINKAGE_RISK_AUTHORITIES` is local server configuration.  Each
  tenant entry supplies its key, private linkage field selection, and private
  reference records.  None can be supplied by an HTTP caller.

The worker materializes the already retained private candidate only in-process,
uses the local HMAC authority to construct/verify the reference representation,
and persists an aggregate `LinkageRiskReport` only.  Stored/viewable evidence
contains opaque key/reference commitments, counts, a report digest and an HMAC
attestation.  It excludes raw reference records, reference values, selected
field names, keys, candidate body and source material.

Every report is bound to the exact tenant, run, processing request, candidate,
policy, rights, processing-method configuration, idempotency key and a keyed
opaque revision of both linkage-key selection and reference representation.
Repository admission and rendering independently reconstruct the report and
verify the current authority, the complete attestation and exact active
commitments/counts.  Invalid, expired, missing, tampered, cross-tenant, or
configuration-drifted evidence fails closed.  Dataset invalidation tombstones
the candidate, run and linkage evidence together.

This is observational evidence only.  HMAC-token match counts do not prove
identity correctness, semantic privacy, absence of re-identification, legal
anonymity, release suitability, delivery authorization, or secure production
reference custody.  Production still requires an external/KMS-backed secrets
and reference service, approved attack suites, calibrated thresholds, durable
multi-host controls and independent security validation.
