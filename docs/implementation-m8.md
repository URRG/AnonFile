# M8: bounded disclosure-risk evidence

`services/api/app/disclosure_risk.py` measures equivalence-class sizes for a
private, structured candidate that is a bounded list of object records.  It
returns only aggregate histogram counts, minimum k-anonymity, unique-record
count/percent, and immutable candidate/schema/report bindings.  It is neither
a qualification nor a delivery approval.

Quasi-identifier field selections remain private.  Callers must provide a
high-entropy opaque `qidcfg:v1:` commitment created in their protected control
plane and bind it to the selection there (for example, through a per-run secret
or signed configuration record).  The risk module deliberately does not hash
field names or paths for public records: unsalted field-name digests are
dictionary-reversible.  The public record has only the caller-provided opaque
commitment, never a raw selection, path, value, record, or class key.

The primitive abstains for text payloads, empty/non-record structured shapes,
record-limit overflow, and unavailable/non-scalar quasi-identifiers.  Nested
paths and semantic choice of quasi-identifiers remain outside M8; an abstained
or assessed report does not make a candidate sale-ready.
