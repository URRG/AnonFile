# M15 privacy decision gate

`POST /release-cases/{case_id}/privacy-decisions` accepts no body or evidence
selection. It reads an active M14 case, its tenant-local M15 configuration and
the native evidence controls entirely server-side. Utility, disclosure and
linkage controls are reconstructed and their original worker attestations are
re-verified before a distinct M12 Ed25519 V2 issuer can make a scoped policy
attestation. Ambiguous or altered native controls quarantine; unavailable
families hold. Residual and benchmark do not presently have a suitable
candidate-bound native attestation adapter, so they remain missing rather than
being promoted from an aggregate digest.

The stored envelope is Ed25519-signed and binds case digest, full M12 outcome,
exact source record ID/digest references and the opaque case recipient
commitment-derived binding. Write-time reassessment occurs under the store
lock. Reads re-verify the case, envelope and a fresh server-side assessment;
any drift, expiry, invalidation or source-attestation failure is unavailable.

When the outcome is `QUARANTINED`, the associated release case is invalidated
and the processing run is made sticky-quarantined. The signed decision itself
is retained as a source-safe audit tombstone and can be read without reviving
or revalidating the deleted case; its view remains explicitly non-actionable.

Both possible outcomes are `QUARANTINED` and `INSUFFICIENT_EVIDENCE`, with
`NO_RELEASE_AUTHORIZATION` permanently attached. This increment adds no
approval, artifact bytes, export, delivery, or download route.

The disclosure adapter uses the native report's `unique_record_count` as a
maximum-risk measurement. The policy contract reserves zero as invalid for
that evidence family, so the smallest valid threshold is `1`; deployments
that require no unique records should continue to hold/quarantine through a
separate stricter disclosure policy rather than configuring an invalid value.
