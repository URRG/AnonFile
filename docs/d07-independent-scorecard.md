# D07 independent scorecard

`app.d07_scorecard` is an aggregate-only, synthetic evaluation helper. It reports exact false negatives separately for automatic detector output and reviewer-corrected output, by source format and entity type. It also records bounded abstention counts and exact supplied graph-claim agreement by relation type.

It is not a benchmark, adjudication system, release gate, or identity-resolution proof. Reports omit text and document IDs. Empty/unsupported slices and final-artifact checks remain explicit abstentions.

## Final artifact validation

The current product uses RapidOCR. RapidOCR's own documentation describes alternate inference runtimes, but those remain execution choices within the same toolkit/model family, not an independent OCR method. D07 therefore refuses to call a same-engine recheck independent. A caller may record only aggregate final text/pixel validation from a distinct named engine; this still cannot prove absence of invisible or unrecognized content.

Before any non-synthetic claim, retain separately: frozen corpus and annotation protocol, per-format labels, source-to-final artifact binding, independent OCR/version provenance, visual/pixel coverage, disagreement adjudication, and all exit thresholds. D07 has no such corpus or exit evidence and stays `NOT_QUALIFIED`.
