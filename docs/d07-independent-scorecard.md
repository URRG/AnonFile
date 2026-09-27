# D07 independent scorecard

## Frozen text-only synthetic holdout slice

`python -m app.d07_text_holdout` runs a fixed, source-controlled synthetic
fixture whose reference annotations were authored separately from the demo
label files and the fixture's automatic predictions. The runner binds the gold
JSONL, automatic-prediction JSONL, and annotation protocol to SHA-256 values
in `services/api/tests/fixtures/d07_text_holdout/fixture-lock.json`; any input
or lock drift fails without a report. The lock file is itself source-pinned,
so changing an input and its lock together cannot silently redefine the
fixture. It emits aggregate exact-span counts by
entity type and `text` format only, without source text or fixture IDs.

This is deliberately a narrow regression slice, not D07 completion or a
generalization claim. It is `NOT_QUALIFIED`: PDF, image, OCR, graph, and
release evaluation are each explicitly `NOT_MEASURED`. The fixture does not
reuse demo labels, but being independently authored *within this synthetic
fixture* does not establish independent external evaluation, representativeness,
or real-world detector performance.

`app.d07_scorecard` is an aggregate-only, synthetic evaluation helper. It reports exact false negatives separately for automatic detector output and reviewer-corrected output, by source format and entity type. It also records bounded abstention counts and exact supplied graph-claim agreement by relation type.

It is not a benchmark, adjudication system, release gate, or identity-resolution proof. Reports omit text and document IDs. Abstained documents are excluded from every span metric and format slice; an all-abstained span set has no metrics. Empty/unsupported slices and final-artifact checks remain explicit abstentions.

## Synthetic demo integration

When a complete, reviewer-supplied synthetic reference-label set is attached
to the bounded demo batch, `/demo/batch/inspect` returns a product-visible aggregate scorecard.
It contains only automatic and reviewer-corrected exact-span count triples,
the fixed `SYNTHETIC_INTERNAL_EVALUATION_ONLY` classification,
`NOT_QUALIFIED`, and an explicit final-artifact-validation abstention. The web
review panel repeats those limits and never displays document IDs, source text,
source values, graph IDs, or a release decision from this aggregate report.

Relationship correction state is not implemented in the stateless demo, so
the integration reports relationship scoring as unavailable rather than
fabricating a reviewer-corrected graph score. No label set means no aggregate
scorecard. This opt-in report is available only through the existing
development-only synthetic demo route; it is not a production or release API.

## Final artifact validation

The current product uses RapidOCR. RapidOCR's own documentation describes alternate inference runtimes, but those remain execution choices within the same toolkit/model family, not an independent OCR method. D07 therefore refuses to call a same-engine recheck independent. It also refuses a caller-supplied different engine name and counts: this increment does not execute a second validator or bind it to exact final-artifact bytes, a versioned checker, source/ground-truth evidence, and reproducible output.

Before any non-synthetic claim, retain separately: frozen corpus and annotation protocol, per-format labels, source-to-final artifact binding, independent OCR/version provenance, visual/pixel coverage, disagreement adjudication, and all exit thresholds. D07 has no such corpus or exit evidence and stays `NOT_QUALIFIED`. Its synthetic-only integration is not a release workflow.
