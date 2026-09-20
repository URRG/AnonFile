# M9: operational detector-evaluation evidence

M9 makes the M8 evaluation-harness aggregate report operationally retainable.
It is intentionally distinct from M3/M8 residual candidate evaluation:

- `POST /processing-runs/{run_id}/detector-evaluation-evidence` accepts a
  verified `ScoredEvaluation` record from a processor worker, with one
  `Idempotency-Key`; processors may submit and processors/reviewers may read.
- The record contains only M8's immutable aggregate category counts, derived
  metrics, detector/evaluator/taxonomy/corpus/prediction digests and fixed
  limitations.  It rejects corpus cases, annotations, protected references,
  predictions, source text, values, paths and offsets.
- The report is bound to the run's request/policy/rights digests and exact
  processor provenance.  Its detector ID, version, configuration digest and
  taxonomy-mapping digest must exactly match the canonical `rules-v1` identity
  persisted when the run was registered.  That configuration includes the
  bounded recognizer patterns/flags, field mappings, limits, output semantics,
  and versioned algorithm/build revisions.  This makes it **method benchmark
  evidence**, not evidence that a particular private candidate was safe or
  utility-preserving.
- It has only the `OBSERVATIONAL_ONLY` posture and must carry
  `NO_RELEASE_AUTHORIZATION`.  Recording/retrieving it cannot alter a run
  state, create a candidate, qualify, approve, export, or deliver anything.

The in-memory/SQLite development store authenticates the control record in its
audit chain and invalidates it when the parent run is invalidated.  The store
is still a development adapter: its HMAC audit key is local, worker identity
is a development processor role rather than an independently attested
evaluator, no corpus is provided here, and the evidence is not a production
benchmark-governance or release gate.
