# M5: enforced local processing pipeline

M5 is synthetic, local development work. It does not authorize customer data,
approval, export, buyer access, delivery, a privacy score, or a claim of
anonymity.

## Enforced execution

Only the registered `rules-v1` worker may be selected. A processing run retains
its worker identity and language; legacy records without that provenance remain
inspectable but cannot be executed. On execution, the service re-resolves the
sealed policy snapshot and confirms its mode, format and language support.

The worker emits aggregate findings and separately records the operation it
actually applied. The policy bridge maps only known rules labels to taxonomy
families and verifies that each observed finding has exactly matching aggregate
operation evidence. It never infers a transformation merely because a detector
found a value.

`suppress` can be satisfied by a redaction or safe scalar nullification.
`generalize` and `tokenize` require their distinct operations. `block`,
`review`, action mismatch and missing coverage create an encrypted private
artifact only for controlled evidence retention and place the run in
`QUARANTINED`; they do not create a candidate-ready run.

## Coverage boundary

The local rules worker maps only `PII`, `PAYMENT` and `CREDENTIAL`. It does not
assess health-sensitive, business-confidential or quasi-identifier families.
The M5 runtime requires the full policy taxonomy, so a normal rules-only run is
quarantined with an explicit uncovered-category record. This is a deliberately
safe capability boundary, not a release blocker a user may override.

The residual evaluator reports record-unit coverage separately from assessed
taxonomy categories. It never renders an unsupported category as a zero finding
or represents partial taxonomy support as 100% category coverage. A failed
residual report quarantines the run. Qualification retains missing/empty
measurement reasons and quarantines any measured threshold violation.

## Lifecycle and evidence

Private candidate metadata carries an aggregate ledger and policy-execution
metadata; it never exposes candidate bytes. Audit-slot reservations are
consumed safely during invalidation and expiry. A processor can call the local
recovery route after the execution lease expires; recovery terminally fails the
old claim and never requeues its detached source.

The M5 metrics correct count-based F1 handling: a detector that misses all
positive examples reports zero, not an absent score.

The browser workbench and any future delivery feature must preserve these
boundaries. A quarantined run must never be treated as qualified, approved or
available to a buyer.
