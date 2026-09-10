# AnonFlow

AnonFlow is a self-hosted, policy-driven system for preparing enterprise data for analytics, evaluation, and controlled external release. It detects sensitive content, applies policy-specific transformations, independently validates output, and creates an auditable Release Card.

**Status:** early development. Policies and scores are engineering evidence, not legal advice or a compliance certification.

## Quick start

Prerequisites are Docker Compose v2 and Make:

```sh
cp .env.example .env
make up
```

Local endpoints: dashboard `http://localhost:3000`, API `http://localhost:8000/docs`, Temporal UI `http://localhost:8233`, and MinIO console `http://localhost:9001`.

The sample environment is for local development only. Replace all secrets, configure OIDC and customer-managed encryption keys, and follow the production guidance before handling customer data.

## Read first

- [Architecture](architecture.md)
- [Architecture decisions](decisions.md)
- [Threat model](threat-model.md)
- [Taxonomy and transformations](taxonomy.md)
- [Scoring and release decisions](scoring-and-release.md)
- [Operations and deployment](operations.md)

## Operating premise

The system distinguishes between an irreversible external anonymized release and restricted pseudonymized processing. Persistent tokens are not called anonymous. Each decision is limited to its named recipient, purpose, policy version, and evidence; a pass is never a universal guarantee against re-identification.
