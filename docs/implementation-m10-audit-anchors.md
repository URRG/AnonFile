# M10 audit anchor checkpoints

`app.audit_anchors` defines the hand-off primitive for a future externally
anchored audit trail.  It receives only an opaque tenant reference, opaque
audit-chain-head commitment, opaque checkpoint identifier, bounded sequence,
previous source-safe checkpoint digest, timestamps, and authority identifier.
It never accepts or returns an audit event body, data payload, record/object
identifier, source value, path, actor/subject, URL, external receipt, or raw
audit HMAC.

`AuditAnchorAuthority` HMAC-signs canonical JSON containing every source-safe
checkpoint field.  Verification binds the exact tenant scope, authority,
checkpoint identifier, sequence, chain commitment, parent digest, timestamps,
state, and limitations.  It rejects cross-tenant verification, tampering,
future use, expiry, duplicate checkpoint IDs, duplicate chain heads, sequence
gaps, and parent forks.  `claim()` is deliberately a one-use transition for a
future external-anchor adapter, so a repeated submission is rejected while
ordinary signature verification remains repeatable for auditors.

Issuance and claim use a private lock around their complete validate,
check, sign, and state-update transitions.  This prevents in-process worker
races from creating a fork or accepting the same submission twice.  The lock
and replay ledger are process-local only; they do not coordinate multiple
workers, processes, hosts, or restarts.

The public record state is always `SIGNED_CHECKPOINT_ONLY`, accompanied by
`NO_EXTERNAL_ANCHOR_RECORD`, `NO_RELEASE_AUTHORIZATION`, and
`NON_PRODUCTION_KEY_CUSTODY`.  It does not claim an external anchor occurred:
only a future connector that keeps a separately verifiable external receipt
may make that claim.  This module has no API route, database/repository
integration, scheduler, external transport, delivery authorization, or
release-state transition.

The authority is an in-process HMAC boundary only.  Production use requires
KMS/HSM custody and rotation, durable shared replay state, independently
durable and verifiable external anchor receipts, a trusted clock,
high-availability coordination, retention/legal-hold controls, operational
monitoring, and an independent security review.
