# M8: bounded disclosure-risk evidence

`services/api/app/disclosure_risk.py` measures equivalence-class sizes for a
private, structured candidate that is a bounded list of object records.  It
returns only aggregate histogram counts, minimum k-anonymity, unique-record
count/percent, and immutable candidate/schema/report bindings.  It is neither
a qualification nor a delivery approval.

Quasi-identifier field selections remain private.  A trusted control plane
creates an in-memory `QuasiIdentifierCommitmentAuthority` from its own
high-entropy 32-64 byte secret and uses it to issue a `qidcfg:v1:` HMAC token
over the canonical sorted field set.  That secret is not persisted or exposed
by this module.  `assess_disclosure_risk` requires the authority to verify the
private fields and token before it can return `ASSESSED`; absent, wrong, or
tampered verification yields the explicit `QUASI_IDENTIFIER_COMMITMENT_UNVERIFIED`
abstention.  This avoids public, unsalted field-name digests, which are
dictionary-reversible.  Public output contains only the verified opaque token,
never a raw selection, path, value, record, or class key.

The primitive abstains for text payloads, empty/non-record structured shapes,
record-limit overflow, and unavailable/non-scalar quasi-identifiers.  Nested
paths and semantic choice of quasi-identifiers remain outside M8; an abstained
or assessed report does not make a candidate sale-ready.
