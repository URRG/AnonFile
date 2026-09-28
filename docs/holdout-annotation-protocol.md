# Fictional holdout annotation protocol (D05/D07)

This is a handoff for an annotator who has **not** seen AnonFlow predictions or
candidate output. It is not a claim that the holdout has been annotated or that
the product is qualified. Use only fictional/de-identified files in the current
development workflow. Keep the corpus, labels, and resulting predictions out
of Git; commit only aggregate results and source-free methodology after review.

## Freeze before running the system

1. Assign each file an opaque ID and record its SHA-256, format, size, and batch
   membership in a private inventory. Do not rename or edit it after freezing.
   Group files into batches of two or three because that is the demo's current
   limit. Preserve related files in the same batch to test cross-file linking.
2. Reserve the whole set as an untouched holdout. Do not use failures from this
   set to tune detector rules and then report the same set as an independent
   test. A changed model needs a new untouched holdout or a clearly labelled
   development-set result.
3. Have a person other than the implementer annotate the **source** files
   without viewing model findings. A second reviewer adjudicates omissions and
   disagreements. Record annotator/adjudicator roles and protocol version in
   the private inventory; a declaration alone does not prove independence.

## Labels to capture

For every file, explicitly record zero findings when none exist. A missing
annotation list is incomplete, not a negative example.

- **Text (TXT/CSV/JSON/JSONL):** exact `[start, end)` Unicode code-point offsets
  in the decoded source, entity type, and an opaque same-person/same-entity key
  when cross-document consistency matters. `app.evaluation.parse_gold` already
  validates the `id`, `text`, `annotations` JSONL shape used by the span scorer.
  Do not infer a name from a greeting or an email domain without source proof.
- **PDF/image:** page number, exact raster width/height used for annotation,
  half-open pixel box `[x0, y0, x1, y1]`, entity type, and whether the text is
  legible to a human. Also mark visible sensitive regions that OCR fails to
  recognize. Record the rendering tool/version and orientation. Boxes must be
  drawn from the original source, not from AnonFlow's OCR boxes or highlights.
- **Layout utility:** mark protected non-sensitive text, tables, labels, form
  fields, logos, and graphics that must remain legible. Record reading-order
  pairs where column/table order matters. After transformation, independently
  rate readability and overlap, including an explicit **abstain/unusable**
  outcome. An unchanged pixel region is not by itself proof of readability.
- **Relationships:** type (`sent_to`, `works_at`, `client_of`, `assistant_to`,
  `assistant_for`, `works_on`, or `assigned_to`), opaque source/target keys, and
  exact source text offsets or page/box evidence. Record ambiguous identity
  pairs as unresolved; do not force a merge. Complete pairwise merge/split
  labels are required before calculating identity scores.

The intake validator accepts a private directory containing `manifest.json`
and a `files/` subdirectory. Each manifest file name must be a plain basename;
the validator rejects symlinks, source hash drift, incomplete labels and
out-of-bounds metadata. From `services/api`, run
`python -m app.holdout_inventory <absolute-corpus-directory>`. It prints only
aggregate counts, a manifest digest and `NOT_QUALIFIED`; it does not decode
media or score predictions. Keep this directory outside the repository.

Example *accepted intake manifest* (fictional values; replace the digest with
the actual SHA-256 of the exact file bytes):

```json
{
  "schema_version": "fictional-holdout-inventory-v1",
  "cases": [
    {
      "id": "file-001", "batch_id": "batch-001", "filename": "mail.txt",
      "format": "txt", "source_sha256": "sha256:<64 lowercase hex digits>",
      "labels_complete": true,
      "text_spans": [{"start": 12, "end": 22, "entity_type": "PERSON_NAME", "entity_key": "person-01"}],
      "media_regions": [], "protected_regions": []
    },
    {
      "id": "file-002", "batch_id": "batch-001", "filename": "scan.png",
      "format": "png", "source_sha256": "sha256:<64 lowercase hex digits>",
      "labels_complete": true, "text_spans": [],
      "media_regions": [{"page": 1, "page_width": 1000, "page_height": 800,
                         "box": [100, 100, 240, 140], "entity_type": "PERSON_NAME",
                         "entity_key": "person-01"}],
      "protected_regions": [{"page": 1, "page_width": 1000, "page_height": 800,
                             "box": [260, 100, 700, 140], "kind": "text"}]
    }
  ]
}
```

This intake schema is **not** an evaluator input or an API contract. The
validator checks box bounds against the declared page dimensions, but does
not independently verify those dimensions against decoded media. Convert
complete text labels into the existing `parse_gold` JSONL contract. Media,
layout and relationship labels still need a separately validated scoring
adapter before any numerical claim; do not translate pixel boxes into guessed
text offsets. Record relationship/identity annotations in a separate private
adjudication sheet until that adapter is available.

## Evaluation and reporting gate

- Run the frozen inputs through the unchanged build. Store source/candidate
  SHA-256 bindings and detector/version/config identities separately from the
  source files. Preserve original automatic findings before any reviewer fix.
- Report per-format and per-entity-type true positives, false positives, false
  negatives, abstained files/regions, and uncertainty. Automatic and
  reviewer-corrected scores must be separate. Zero labels is **not** 100% recall.
- For media, test exact final returned pixels with a separately provisioned,
  pinned OCR executable and compare against the blind source boxes; inspect
  visible unprocessed regions and layout utility manually. A second OCR engine
  can miss the same text, so its clean output alone is not proof of anonymity.
- Graph scores require fully labelled relationships and evidence locators,
  with identity merge/split decisions independently adjudicated.
- Keep `REVIEW_REQUIRED` and `NOT_QUALIFIED` until the documented thresholds,
  abstentions, corpus provenance, and human review are all satisfied. No
  benchmark result authorizes external release or real-data processing.

Current demo bounds: 2–3 files per batch; 1.5 MB total; text 100 KB/file;
PDF/image 500 KB/file; at most two media pages/file and 3 million total media
pixels/batch. These are development limits, not production capacity.
