# M24: quasi-identifier singling-out observation

`services/api/app/quasi_identifier_risk.py` is an isolated, trusted-worker
primitive for observing within-candidate equivalence-class sizes.  It accepts a
private `CandidateArtifact` containing decoded JSON or JSONL tabular data: a
bounded list of JSON object records.  The caller explicitly selects top-level
quasi-identifier field names and gives the selection a private scope.  A
trusted in-memory authority HMAC-binds both selection and scope.

The report has no source bytes, values, paths, raw hashes, field names, or
scope/tenant strings.  It returns only opaque HMAC commitments, field count,
record count, minimum group size, singleton-record count, and counts of records
in groups at fixed sizes 1, 2, 5, and 10 or smaller.  Missing selected fields,
null or blank selected values, nested values, text, non-tabular inputs, empty
data, and limits abstain with no metrics.  Unsupported or untrusted
configuration fails closed.

This is a limited descriptive observation, not a privacy guarantee.  It does
not assess attack data, background knowledge, indirect identifiers outside the
operator selection, transformation quality, legal compliance, or downstream
controls.  It has no HTTP route, persistence, release-case integration, policy
decision, delivery capability, or authorization effect.
