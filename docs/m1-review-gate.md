# M1 independent review gate

Reviewed code revision: `7b57b1b837915b43cb9014dc620facf37f9ed0d5`
Date: 19 September 2026
Scope: synthetic/local, rules-only, no-export development foundation.

## Result

PASS for the stated M1 scope after an initial failed gate and remediation. This is an agent code-review gate, not an external security audit, privacy certification, production approval or customer acceptance.

| Author/owner | Independent reviewer | Reviewed scope | Final result |
| --- | --- | --- | --- |
| API agent | Processing agent | Authentication, tenant/role isolation, strict input parsing, review state and withholding | PASS |
| Processing agent | Evaluation agent | Typed transformations, Unicode offsets, overlaps, aliases and input limits | PASS |
| Evaluation agent and orchestrator | API agent | Gold-label metrics, CLI, frontend, deployment configuration and integration test | PASS |

Agents had exclusive file ownership. Only the orchestrator staged and committed. Reviews were read-only; fixes returned to owners; reviewers independently retested the corrected revision. No concurrent Git mutations or merge conflicts occurred.

## Findings closed

1. Duplicate JSON members silently overwrote sensitive values: reject all duplicate keys, including escaped-equivalent and nested keys, before model validation.
2. Sensitive container fields retained arbitrary identifying keys: reject unsupported sensitive containers.
3. Generated aliases collided with source literals: reserve normalized transformation-marker namespaces across source values and keys.
4. Equal-critical credentials could be classified as cards: use consistent severity plus entity priority and hard-redact credentials.
5. Frontend accepted inconsistent card identity/eligibility: bind card and envelope identity, status, required gates and requested policy/mode.
6. Docker contexts could overlay host dependencies and include credentials: add explicit context exclusions.
7. Compose overrode an explicit production environment: preserve the configured environment so startup refuses unsupported modes.
8. Repository checks could not run inside the web-only image: split repository-level checks from web unit tests and run them explicitly in CI.

Additional intake hardening rejects detectable sensitive object keys before retention. Some unsupported processing structures can still be admitted as source but processing fails closed without creating a release.

## Verification

- Python: 175 passed (76 processing, 63 API/access, 36 evaluation); two dependency deprecation warnings.
- Frontend request and validation tests: 17 passed.
- Static deployment regression checks: 2 passed.
- Real localhost HTTP workflow through the actual frontend client: 1 passed.
- TypeScript/Vite build: passed.
- Evaluation CLI: supplied synthetic predictions and rules baseline both generated internal-only reports.
- Whitespace diff check: passed.

Docker images/Compose were not executed because Docker was unavailable. Rendered-browser end-to-end behavior was not tested. GitHub CI is configured but has not run remotely; no push was performed. Dependency version ranges and production supply-chain qualification remain future hardening.

## Remaining product gates

Static development tokens, in-memory single-worker storage, incomplete rules coverage and on-access expiry are deliberate limitations, not industry-grade controls. No candidate output endpoint or buyer export exists. OIDC, durable encrypted tenant storage, parser isolation, approved models, source-specific holdouts, independent output scanning/linkage attacks, utility validation, rights controls and approved-artifact delivery are required before a commercial pilot with real data.

Test counts are regression coverage, not detector accuracy. The four-document synthetic baseline detects two annotated emails and misses the annotated person name; it is explicitly NOT_QUALIFIED and not representative of customer data.

