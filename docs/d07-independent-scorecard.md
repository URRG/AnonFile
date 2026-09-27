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
Hashes bind canonical LF content: CRLF-only copies left in existing Windows
worktrees are accepted as the same fixture, while lone carriage returns and
all other content drift fail closed. New checkouts preserve fixture bytes via
`.gitattributes`; this compatibility rule does not relax annotation changes.

This is deliberately a narrow regression slice, not D07 completion or a
generalization claim. It is `NOT_QUALIFIED`: PDF, image, OCR, graph, and
release evaluation are each explicitly `NOT_MEASURED`. The fixture does not
reuse demo labels, but being independently authored *within this synthetic
fixture* does not establish independent external evaluation, representativeness,
or real-world detector performance.

## Live current-detector text holdout

`python -m app.d07_text_holdout --live-detector` is a separate regression path:
it runs the current `app.processing.detect_text` against the locked, separately
authored synthetic gold text, maps its label/Unicode half-open offsets into the
exact-span evaluator, and reports aggregate-only corpus and per-type `text`
metrics. It emits the rules method configuration digest alongside a separate
implementation identity: SHA-256 digests of the detector source file and a
canonical callable-code representation. The configuration digest identifies
the declarative rules configuration; it is calculated at call time before
scoring and rechecked afterward, with any drift failing closed. The
implementation identity binds the current callable and changes if its
executable code changes. These are hashes only: no source text, paths, or
source values are emitted. A callable that cannot be bound to both identities
fails closed. The live path
pins the gold text and annotation protocol with a separately source-pinned lock;
gold, protocol, or lock drift fails closed without producing a report.

The report never includes source text, source values, document IDs, or graph
identifiers. It is explicitly `NOT_QUALIFIED`; media, graph, and release are
`NOT_MEASURED` (as are the listed PDF/image/OCR slices). This tiny synthetic
fixture is not externally representative and does not support a generalization,
media-redaction, residual-disclosure, or release-safety claim.

`app.d07_scorecard` is an aggregate-only, synthetic evaluation helper. It reports exact false negatives separately for automatic detector output and reviewer-corrected output, by source format and entity type. It also records bounded abstention counts and exact supplied graph-claim agreement by relation type.

It is not a benchmark, adjudication system, release gate, or identity-resolution proof. Reports omit text and document IDs. Abstained documents are excluded from every span metric and format slice; an all-abstained span set has no metrics. Empty/unsupported slices and final-artifact checks remain explicit abstentions.

### Typed graph, locator, and identity accounting

The optional synthetic graph inputs now add precision/recall count triples for
the aggregate relation corpus and each relation type. They remain separate for
automatic and reviewer-corrected inputs. The scorecard can also accept a
complete fictional set of opaque evidence-locator bindings. A binding is a
relation claim plus an opaque `L1`-style locator token; it emits only aggregate
corpus/per-relation agreement and never returns an endpoint or locator token.
Its gold bindings must cover exactly the separately supplied graph-gold claims,
so locator agreement cannot silently grade a smaller, easier relation subset.
Absent gold labels and assessment state produce the explicit
`NO_COMPLETE_EVIDENCE_LOCATOR_LABELS` abstention.

Identity evaluation is likewise optional and synthetic-only. It accepts a
complete, mutually exclusive `MERGE`/`SPLIT` disposition for every unordered
pair in its fictional person-ID universe. The scorecard rejects an incomplete,
duplicated, or differently covered pair set rather than treating omitted pairs
as correct. It reports separate aggregate precision/recall counts for each
pair disposition and for merge-derived clusters; it returns neither identity
keys nor clusters. Missing identity labels are an explicit
`NO_COMPLETE_IDENTITY_LABELS` abstention.

These are comparisons with supplied complete fictional labels, not identity
resolution, evidence sufficiency, source correctness, self-grading, or any
real-world qualification. They do not change D07's `NOT_QUALIFIED` status or
authorize a release.

### Coverage-aware recall bounds

The v2 synthetic scorecard additionally emits `coverage_aware_recall` for the
automatic and reviewer-corrected inputs, overall and per source format/entity
type. It preserves the existing assessed-only exact-span measurements and
adds eligible, assessed, and abstained document and gold-positive counts.
`conditional_recall` is recall on assessed gold positives only. The
`operational_recall_lower_bound` treats every gold positive in an abstained
document as missed; the upper bound treats each as potentially found. Thus an
all-abstained slice with positive gold has conditional recall `null`, a lower
bound of `0`, and an upper bound of `1`, never a perfect result. A slice with
no eligible gold positives has `null` recall and bounds.

These are deterministic accounting bounds over complete, fictional supplied
labels, not confidence intervals, representative performance, independent
evaluation, or a release threshold. Reviewer-corrected bounds measure the
supplied synthetic workflow result, not automatic detector performance.

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
