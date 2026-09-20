# M11 privacy-evidence policy contract

`app.privacy_evidence_policy` is a standalone, source-safe qualification
contract for a future independent release-governance workflow.  It evaluates
only opaque evidence references/digests, bounded scalar measurements,
controlled identifiers, timestamps, and HMAC attestations.  It never accepts
or emits candidate bytes, source values, field names, paths, subjects, actor
identities, recipient names, export URLs, credentials, or delivery handles.

Every decision binds the exact candidate artifact digest, processing-policy
digest, rights digest, opaque recipient reference, purpose code, end-to-end
method-provenance digest, candidate expiry, evidence-policy digest, all five
evidence references, issuer identities, thresholds, and measurement/expiry
times.  The policy requires one evidence family each for independent residual
scanning, disclosure risk, utility, linkage risk, and benchmark performance.
Each reference must be signed by its specifically named authority and match
that complete scope.  Tampered, unknown, duplicate, missing-authority, or
mismatched evidence quarantines; missing, stale, future-dated, or expired
evidence is insufficient.  Threshold violations quarantine.

There is intentionally no successful/ready/approved/exported/delivered state.
Even a complete, current, within-threshold evidence set returns
`INSUFFICIENT_EVIDENCE` with
`INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED`, and every serialized decision
has `NO_RELEASE_AUTHORIZATION`.  This module has no API route, repository,
worker, candidate-state transition, release action, or delivery integration.

The attestation authority is an in-process HMAC boundary only.  Production
requires independently governed evaluators, KMS/HSM custody and rotation,
durable provenance/evidence storage, dataset-specific and adversarial
evaluation suites, statistical confidence handling, linkage-attack design,
authorization workflow, recipient verification, release/delivery controls,
and external security/privacy review.
