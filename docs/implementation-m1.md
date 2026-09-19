# M1 implementation contract and ownership

This is the first implementation milestone, not the completed commercial plan.
Synthetic/local development only. No privacy qualification, real customer-data
admission, production authentication, or buyer export is enabled by this milestone.

## Coordination

All work occurs on feat/secure-processing-foundation in the isolated implementation
worktree. Only the orchestrator stages and commits. Agents must not run git mutations,
edit other owners' files, install unapproved model weights or contact external services
with source data. Changes to the shared interface require an orchestrator decision.

| Owner | Exclusive paths |
|---|---|
| Processing agent | app/processing.py; tests/test_processing.py |
| API/security agent | app/main.py; app/security.py; app/repository.py if needed; tests/test_api.py; tests/test_access.py |
| Evaluation agent | app/evaluation.py; app/evaluate.py; tests/test_evaluation.py; tests/fixtures/evaluation/** |
| Orchestrator | app/contracts.py; apps/web/**; docs/**; readme.md; deployment/env/CI and integration tests |

API paths above are relative to services/api. No shared conftest edits by agents.

## Frozen processing interface

`app.processing.detect_text(text: str) -> tuple[Span, ...]` returns resolved,
non-overlapping spans against original text. Values never appear in Findings.

`app.processing.process_payload(*, content: str | None = None,
records: list[dict] | None = None, mode: str = "external_anonymized")
-> ProcessingResult` accepts exactly one bounded payload; supported modes are
external_anonymized and restricted_pseudonymized. Rejections raise PayloadError with
fixed, non-sensitive messages. Any unsupported coverage prevents release approval.

Shared dataclasses live in app/contracts.py. ProcessingResult.output is internal
candidate data. It is never returned by release status/card/review APIs.

## Frozen API/UI interface

Development auth uses an explicit ANONFLOW_DEV_PRINCIPALS JSON environment variable:
an array of objects with token (at least 32 characters), subject, tenant and roles.
Roles are processor, reviewer and buyer. Tokens are server-configured, not user claims.
No default credentials; unconfigured auth fails closed. Browser token is memory-only.
Production mode is refused; static local development credentials are not OIDC.

`POST /datasets` accepts name plus exactly one content/records, owner, jurisdiction,
intended_use, recipient and retention_days. It returns safe metadata plus id.
`GET /datasets` is tenant scoped and processor-only.
`POST /releases` accepts dataset_id, release_mode, policy_version and allow_review.
Allowed policy labels: baseline-v1, external-release-v1, restricted-pseudonymized-v1;
mode/profile combinations are checked server-side. Returns id, dataset_id,
status, eligibility, output=null, card and review=null.
`GET /releases/{id}` and `/card` require same-tenant processor/reviewer authorization.
`POST /reviews/{id}/decision` is reviewer-only with separation of creator/reviewer;
reject may block, approve returns 409 because qualification is missing.
No buyer candidate, preview or download path exists in M1.

Every card includes release_id, dataset_id, policy_version, release_mode,
eligibility, findings (entity_type, severity, count), gates, limitations,
evidence_status="INSUFFICIENT_EVIDENCE", and scores=null. No fabricated privacy,
utility, confidence or signature. Non-critical candidates are REVIEW_REQUIRED;
credentials/critical safety conditions are BLOCKED. API errors never echo input,
tokens, reviewer notes or sensitive field values. UI must not invent a fallback.

## Review gate

Implementation agents test their owned modules; the orchestrator runs the integrated
API/evaluation/UI suite and commits logical changes. Then a separate reviewer batch
cross-reviews modules they did not author against committed code. Blocking findings
are fixed and committed, relevant suites rerun, then reviewers verify fixes. Final
handoff records commit hashes, tests, unresolved limitations and gate outcome.
