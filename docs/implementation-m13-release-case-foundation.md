# M13 immutable release-case foundation

`app.release_case` is a standalone, worker-side provenance primitive.  It
constructs an immutable, Ed25519-signed `ReleaseCase` that binds one candidate
artifact digest to its exact processing run ID, processing-run and processing-
request digests, mode, dataset and ingestion provenance digests, processing-
policy digest, rights digest, canonical method-provenance digest, purpose,
contract reference/digest, and expiry.

A trusted `ReleaseCaseAuthority` derives the recipient field using a private
32-byte HMAC salt and a domain-separated commitment over the authority tenant,
canonical recipient, rights digest, purpose, processing mode, run ID and a
versioned recipient-commitment-key ID. The resulting
`recipient-commitment:v1:...` value is opaque and is not a plain SHA-256 hash
of a recipient.  Raw recipient input and the salt are neither retained nor
emitted.  Contract references are also typed opaque references; contract bodies
and counterparty details do not enter the record.

All datetimes must be timezone-aware UTC-normalizable whole seconds.  A case
cannot outlive its candidate, processing run, rights, or contract context, the
issuer authority, or the bounded 31-day case lifetime.  The authority public verifier can verify records without
any ability to create recipient commitments or sign records.  Altered context,
wrong tenant/key, authority expiry, record expiry and malformed fields all fail
closed.

This milestone intentionally has no route, repository, worker registration,
candidate/run state transition, approval, export, or delivery behavior.
`NO_RELEASE_AUTHORIZATION` is a fixed posture, not a decision.  Production use
still needs KMS/HSM-backed key custody, separately governed contract/rights
validation, append-only persistence, independent approval and delivery controls.
When a future store exists, it must invalidate/reject a case on any candidate,
run, rights, contract, provenance, authority-key or recipient-commitment-key
rotation; this primitive cannot observe those external lifecycle events itself.
