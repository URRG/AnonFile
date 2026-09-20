# M9: source-safe data-utility evidence

`services/api/app/utility_evidence.py` is a bounded, trusted-worker primitive
for comparing private input data with a private `CandidateArtifact`.  Its
persistable `DataUtilityReport` contains only aggregate byte, unit, node, and
scalar counts; two value-free structural checks; opaque source commitment;
candidate/provenance digests; and a report digest.  It never includes a
record, field name, path, scalar value, snippet, input digest, schema
descriptor, or candidate body.

The caller owns an ephemeral 32--64 byte secret and constructs a
`UtilityEvidenceAuthority`.  It HMAC-binds exact canonical source bytes and
payload kind into the public `utilsrc:v1:` commitment.  A missing, wrong,
tampered, malformed, oversized, or cyclic source cannot be measured: the
primitive returns `SOURCE_COMMITMENT_UNVERIFIED` with no metrics.  A valid
committed text/structured kind mismatch returns `PAYLOAD_KIND_MISMATCH`, also
with no metrics.  This avoids publishing an unkeyed raw-source hash, which
could enable dictionary/membership checks for known or small data.

Object field names are intentionally removed before the internal shape check;
the report exposes only whether value-free shape and top-level unit count were
preserved.  Consequently this is structural evidence, not semantic utility,
ML-task quality, fairness, privacy, linkage/re-identification evidence, or a
release/delivery decision.  M10 adds bounded local control retention and a
server-owned authority path; see `implementation-m10-utility-evidence-api.md`.
Production use still needs managed secret custody, a durable worker boundary,
policy qualification, and independent evaluation before it can influence a
release.
