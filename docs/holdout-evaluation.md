# Frozen holdout evaluation protocol

AnonFlow has an offline exact-span evaluator. Its new `--holdout-lock` mode
scores only rows marked `split: "holdout"` after pinning the **entire** gold
JSONL file by SHA-256. It requires group IDs on every row, at least one
non-holdout row, no group split across partitions, no identical text across
different partitions, and configured minimum holdout/positive-document counts.
Prediction files must contain exactly the holdout IDs. Reports contain only
aggregate counts and hashes, never document text or IDs. This is a technical
split-integrity check, **not** independent evaluation by itself.

## Required external process

1. Obtain rights to use the evaluation corpus and restrict access to its raw
   files. Do not commit licensed, supplier, or personal source text to this
   repository or use the synthetic demo upload endpoint for it.
2. An annotator who has not tuned the detector labels all target entities,
   including negatives, under a written versioned protocol. Resolve
   disagreements independently and retain adjudication evidence outside the
   application. Include hard cases: scanned PDFs, image text, tables,
   handwriting, low contrast, multilingual names, indirect identifiers,
   business secrets, and overlapping spans.
3. Partition by entity/person or source case before training and tuning, not
   by random document row. Record `group_id` and `split` on each record. Audit
   near duplicates and training-data contamination outside this CLI; it only
   detects exact duplicate text and repeated group IDs across splits.
4. Freeze the corpus and annotation protocol before the candidate detector
   version is evaluated. An independent custodian should protect the lock and
   record its creation time, signer, source license, and detector version.
   This CLI checks bytes against the supplied lock but cannot authenticate
   its curator, timestamp, or independence.
5. Run every detector revision against the untouched holdout and publish
   exact-span precision, recall, false negatives, per-entity metrics and
   source-format slices. Repeat on final transformed artifacts with a
   separate visual/OCR method; span scores cannot establish successful
   redaction or acceptable re-identification risk.

## CLI contract

Gold JSONL rows use the existing evaluator format, plus `group_id` and
`split` (`train`, `validation`, or `holdout`). Each holdout row requires its
own prediction row. An external custodian creates a UTF-8 lock file with
exactly these keys:

```json
{
  "schema_version": "holdout-lock-v1",
  "gold_sha256": "<64 lowercase hex characters>",
  "annotation_protocol_sha256": "<64 lowercase hex characters>",
  "holdout_split": "holdout",
  "minimum_documents": 100,
  "minimum_positive_documents": 50
}
```

Run from `services/api` after installing dependencies:

```powershell
python -m app.evaluate --gold C:\secure\gold.jsonl --predictions C:\secure\predictions.jsonl --holdout-lock C:\secure\holdout-lock.json --output C:\secure\internal-report.json
```

The lock minimums are a corpus acceptance constraint, not a statistical power
calculation or product threshold. They must be set by the evaluation owner
before results are seen. A lock with fewer records can test the CLI but must
not be represented as a credible industry benchmark. The report remains
`NOT_QUALIFIED` and records `NOT_VERIFIED_BY_SOFTWARE` for independence.

## Current status

Only fake, tiny evaluator fixtures are checked into the repository. No
independently annotated, representative, legally usable corpus has been
procured or scored. Media annotations need page-coordinate and visual
disclosure checks beyond this text-span evaluator. Production eligibility,
safe redaction, and release remain unproven.
