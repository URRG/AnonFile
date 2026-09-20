# M4 detector, transformation and benchmark evidence contract

M4 adds fail-closed domain contracts for the next processing layer. It remains
synthetic/local development work and does not add approval, export, buyer
delivery, a privacy guarantee or a production model runtime.

## Detector boundary

Detector adapters have a versioned identity and configuration digest. Their
only accepted result is an explicit total/attempted/abstained coverage count
plus aggregate label counts. Each label must map explicitly to the policy
taxonomy; unknown labels, unsupported output shapes and adapter exceptions fail
closed. Snippets, locations, field paths and matched values are outside the
contract and cannot enter evidence records.

## Transformation obligations

A sealed policy snapshot and aggregate taxonomy findings yield deterministic
worker obligations. `suppress`, `generalize` and restricted-mode `tokenize`
become exact aggregate ledger requirements. `review` requires review and
`block` requires quarantine. Tokenization is never permitted in the external
anonymized mode. These dispositions are worker controls, not delivery states.

## Benchmark evidence

Benchmark evidence binds the benchmark/annotation protocol, model and detector
versions/configuration to aggregate category metrics, coverage and mandatory
limitations. The sole posture is `OBSERVATIONAL_ONLY`, including when metrics
are strong. Evidence does not establish residual-risk safety, re-identification
resistance, task utility, legal rights, release approval or buyer access.

## Remaining integration gates

M4 contracts are foundations, not a production detector fleet. Before any
commercial use, implement isolated adapter execution, curated multilingual and
document detectors, benchmark governance and gold labels, adversarial residual
and linkage testing, protected human review, OIDC/KMS/egress controls, and a
separate recipient-bound approval/delivery system.
