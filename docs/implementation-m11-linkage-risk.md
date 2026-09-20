# M11: bounded linkage and re-identification risk evidence

`services/api/app/linkage_risk.py` is a trusted-worker primitive for measuring
potential record linkage between a private structured `CandidateArtifact` and
an external reference representation. It is deliberately module-only: there
is no route, persistence, qualification, approval, export, or delivery
integration in M11.

## Private inputs and opaque commitments

The caller owns a 32--64 byte `LinkageCommitmentAuthority` secret and creates:

1. a private top-level linkage-key selection with a `linkcfg:v1:` HMAC
   commitment; and
2. an external `LinkageReference` from private reference rows. The reference
   retains only sorted per-row HMAC tokens and a `linkref:v1:` HMAC commitment.

Canonical selected scalar tuples are HMACed with the authority secret. The
module never emits or derives unkeyed hashes of values, field names, paths,
records, or reference content. Neither the private selection nor token list is
present in `LinkageRiskReport` or `to_record()` output. The representation must
verify against the same in-memory authority and linkage-key commitment before
the candidate is materialized; missing, wrong, tampered, or malformed
representations return `REFERENCE_COMMITMENT_UNVERIFIED` with no metrics.

Raw reference construction is bounded to 10,000 list-of-object records and
selected scalar values. Cyclic, oversized, nested-key, missing-key or malformed
raw reference input is rejected by the trusted builder and cannot create a
representation. Candidate text, unsupported shapes, empty sets, excess record
counts, empty references, and inapplicable linkage keys produce explicit
no-metrics abstentions. The candidate artifact's own validation rejects cyclic
and oversized private payloads before this primitive runs.

## Aggregate evidence only

An assessed report binds its candidate artifact/schema digests, opaque key and
reference commitments, methodology digest, and deterministic aggregate counts:

- candidate/reference record counts;
- candidate records with at least one matching reference HMAC token;
- one-to-one matches (a token occurs once in both candidate and reference);
- ambiguous matches (matched records that are not one-to-one); and
- a fixed two-decimal candidate match-coverage percentage.

It contains no candidate or reference identity, match token, field/path,
value, raw source digest, reference fingerprint, row position, or snippet.
`from_record()` rebuilds and checks the report digest while rejecting extra
fields, so a persistence layer cannot add private content or alter counts.

## Non-goals and limits

This is observational attack-surface evidence only. A match is a match of
authority-scoped selected tuples, not proof of a real-world identity; a
non-match is not proof of anonymity. It does not test broader auxiliary data,
semantic similarity, free text, images/documents, attacks across authorities,
privacy law, contractual restrictions, or release safety. The in-process HMAC
authority is not KMS/HSM custody, an external independent attacker simulation,
or a production re-identification testing service. Independent methodology,
managed secrets, protected reference governance and policy qualification remain
necessary before any commercial release decision.
