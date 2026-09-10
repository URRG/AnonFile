# Architecture decisions

This log fixes product defaults so implementation remains consistent. Changes require a new dated decision entry and policy/version migration where applicable.

| ID | Decision | Rationale | Consequence |
| --- | --- | --- | --- |
| ADR-001 | Treat anonymization and pseudonymization as distinct release modes. | Stable identifiers create linkability risk. | External policy cannot export mapping keys; pseudonymized outputs require restricted controls. |
| ADR-002 | Default production deployment is customer VPC/self-hosted. | Enterprise source data often has residency and egress constraints. | Local Compose is development-only; production needs customer identity, KMS, storage, and network integration. |
| ADR-003 | Use policy gates before weighted scores. | A good average must not hide a credential leak or failed re-identification test. | Critical findings block releases regardless of score. |
| ADR-004 | Use layered detection and independent validation. | A single model has correlated blind spots. | Validation must use a separately versioned detector ensemble. |
| ADR-005 | Keep raw payloads out of logs, traces, and metadata DB. | Observability is a common data-exfiltration path. | Store references and redacted findings only; inspect content through privileged review flow. |
| ADR-006 | Scope HMAC pseudonyms to tenant + release + entity type. | Global tokens enable cross-release correlation. | Analytics requiring longitudinal linkage must use a consciously approved dedicated scope. |
| ADR-007 | Hosted LLMs are opt-in only. | Source content may be confidential and model instructions can be malicious. | Default is local model inference; egress policy is mandatory for cloud adjudication. |
| ADR-008 | Start with English, US/India identifiers, text/CSV/JSON. | High-quality coverage requires benchmarked locale and parser support. | Other languages/formats remain unsupported or plugin-gated until tested. |
| ADR-009 | Release Cards are signed, immutable evidence artifacts. | Buyers and auditors need reproducible decision context. | Any policy/model/input change requires a new release run/card. |
