# M17 fixed-profile benchmark evidence

`POST /processing-runs/{run_id}/benchmark-evidence` accepts no body. It can
only convert exactly one existing independently evaluator-attested M8 aggregate
report for the run. The tenant-owned `ANONFLOW_BENCHMARK_EVIDENCE_PROFILES`
configuration fixes the evaluator subject/id/version/configuration, corpus
digest, detector id/version/configuration, taxonomy mapping and minimum
annotation-reference count. The required categories must be the complete
platform taxonomy; partial or client-selected categories are rejected.

The persisted M17 control contains only the source control ID, source report
digest, profile digest, evaluator time and the conservative minimum recall
across every required category. It retains no benchmark case, label,
prediction, protected reference, source record or candidate payload. The
server reconstructs and re-verifies the M8 attestation and exact profile at
write and read time. A changed report, authority, profile, scope or source
control fails closed; deletion of the run invalidates both M8 and M17 records.

M15 reads only this M17 control for `BENCHMARK`, recomputes the release case's
method-provenance digest, and uses the evaluator's native `evaluated_at` (not
the later storage timestamp) for evidence freshness. This is still an
observational measurement with `NO_RELEASE_AUTHORIZATION`: it adds no release
approval, export, artifact bytes, download or delivery route.
