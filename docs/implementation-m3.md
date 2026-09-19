# M3 private candidate and qualification contract

M3 is a synthetic/local processing and evidence increment built on M2b. It may
create a **private encrypted candidate** from an admitted run, then inspect that
exact candidate with an independent residual detector. It does not authorize a
sale, reveal candidate bytes, or expose source/candidate previews/downloads.

## Run execution

The local development executor only claims a `REGISTERED` run after its
dataset/rights/policy dependencies are atomically rechecked. It computes from
the original encrypted dataset in process memory, stages the result privately,
then atomically writes `CANDIDATE`, an artifact digest/byte count/media type and
an encrypted candidate body. It never writes source/candidate values to public
audit events, responses, logs or exceptions.

If a dependency is deleted/expired while work occurs, the candidate is
discarded and the run is quarantined/invalidated. Retry and state rules must be
compare-and-set based; a worker may not silently apply a different policy or
source. M3's local executor is not a job queue, worker isolation system or
production scheduler.

## Evidence and qualification

Residual evaluation consumes the exact private candidate in a separately
invoked detector stage with an explicit detector identity. It reports only aggregate sensitivity-family counts,
structural utility checks, coverage/abstentions, bounded limitations and a
canonical report digest. It receives no original source and emits no snippets.
The local M3 adapter deliberately uses the same small rules family as the
processor in a separate pass; it is **not** an independently validated model
or a substitute for a production residual-evaluation suite.

M3 has no success/approval outcome. A candidate with findings is
`QUARANTINED`; a clean rules-only scan is `INSUFFICIENT_EVIDENCE`. Qualification
records bind the candidate, report, policy and rights digests plus recipient and
purpose, and likewise remain only `QUARANTINED` or `INSUFFICIENT_EVIDENCE`.
Neither case creates an export grant.

## Endpoint boundary

The development API provides a processor-only `POST /processing-runs/{id}/execute`
route and reviewer-only residual-evaluation/qualification routes. Candidate
bytes and protected transformation
ledger entries never have a GET/preview/export route. Exact final approval,
buyer-specific grant and delivery remain future milestones after representative
gold-data, residual/linkage tests and task-utility qualification.

## Completion gate

Tests must cover exact-candidate digest binding, no output/source leaks,
candidate retention only in encrypted storage, state/race/dependency failures,
independent residual evidence, structural utility checks, stale/mismatched
qualification records, cross-tenant isolation and absence of any approval or
download capability.
