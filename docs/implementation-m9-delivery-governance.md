# M9 delivery-governance evidence

`app.delivery_governance` is a bounded, source-safe control primitive for a
future enterprise dataset handoff workflow. It binds an opaque candidate,
recipient reference, purpose code, contract reference/digest, rights and
policy identity to four required signed assertions: rights validation, privacy
evidence validation, security review, and contract execution.

It accepts only controlled identifiers, timestamps, and SHA-256 references.
It neither accepts nor emits payload bytes, personal data, recipient names,
contract text, export URLs, credentials, or release handles. Every assertion
and resulting record is canonical JSON/digest bound. The resulting readiness
evidence is HMAC-signed and tamper-verifiable only by the private authority.
Non-quarantined evidence cannot be serialized as a control record until that
same authority verifies its signature in-process; a structurally forged HMAC
string is therefore not reusable readiness evidence.

This is deliberately fail-closed. Missing, mismatched, future-dated, expired,
or unverifiable assertions yield `QUARANTINED`. Complete evidence yields only
`INDEPENDENT_APPROVAL_REQUIRED`; there is no ready, approved, exported, or
delivered state, and the module has no routes, storage integration, candidate
state transition, or transport code.

The supplied HMAC authority is an in-process test/integration boundary, not
KMS-backed key custody or an independently governed approval service. Before
production use it needs managed key custody and rotation, durable immutable
audit storage, independent human/system approval, authorization, recipient
identity verification, secure export transport, revocation, retention and
post-delivery controls.
