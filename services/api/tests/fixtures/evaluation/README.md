# Synthetic evaluator fixtures, not a qualification dataset

These four deliberately tiny, hand-authored fake records test the evaluator.
The predictions are hand-authored errors, not output from a competing detector.
Never represent their scores as real-world accuracy, relative model quality,
residual-output privacy, anonymity, or permission to sell a dataset.

From `services/api`, with its Python environment active:

```powershell
python -m app.evaluate --gold tests/fixtures/evaluation/synthetic-gold.jsonl --predictions tests/fixtures/evaluation/synthetic-predictions.jsonl --output synthetic-supplied-report.json
python -m app.evaluate --gold tests/fixtures/evaluation/synthetic-gold.jsonl --baseline rules-v1 --output synthetic-rules-report.json
```

For the supplied predictions, exact totals are TP=1, FP=2, FN=2, so precision,
recall and F1 are all 1/3. Same-type overlap totals are TP=2, FP=1, FN=1,
so those scores are 2/3. There are 4 documents, 3 with gold annotations.
Two of those 3 documents contain unmatched exact gold spans; one contains an
unmatched overlap gold span. Unicode offsets count the emoji as one code point.

Input format is JSONL, UTF-8, with one object per nonblank line:

- Gold: `id`, `text`, `annotations`; optional `group_id`, `split`.
- Predictions: `id`, `annotations`, with exactly one row for every gold ID.
- Each annotation: integer `start`, exclusive integer `end`, `entity_type`.
- Labels must belong to the fixed `app.evaluation.ENTITY_TYPES` registry.
- IDs and optional group/split values are bounded internal strings, never
  report fields. Every supplied split is evaluated; these labels do not create
  a train/test separation. A group spanning distinct supplied split values is
  rejected, but duplicates or leakage from external training cannot be detected.
- Gold duplicate annotations are rejected. Duplicate predictions count as
  extra false positives; one gold span can never earn multiple true positives.
- Files are bounded to 20 MB, 10,000 documents, 2,000,000 code points per text,
  and 1,000 annotations per document. This CLI is a local bounded evaluator,
  not a scalable or multi-tenant hosted service.

Malformed inputs fail closed without partial reports or sensitive error
content. An existing output is retained if validation fails; callers must use
the exit code, not the existence of an old output, as evidence of success.
Successful writes atomically replace the chosen output. Input paths cannot be
chosen as output paths. Reports are reproducible without timestamps and include
source-content SHA-256 hashes and evaluator/detector source hashes. Treat reports
as internal evidence: even aggregates and fingerprints can be sensitive.

Missing denominators return JSON null, not perfect precision/recall. No
confidence interval, calibrated confidence, qualification or release authority
is produced. The external gold annotations are the reference, not the detector's
own output. Gold quality, source coverage and independent adjudication remain
the user's responsibility. Baseline execution imports processing without the
API, authentication, model downloads, or external network services.
