# M44b server-owned publication-destination contract

`app.publication_destinations` defines a pure immutable registry of
operator-provisioned destination profiles. A profile maps one application
tenant identity to one opaque PostgreSQL `tenantref`, and fixes an opaque
destination reference, recipient label, purpose, contract digest, metadata
kind, key reference and the only currently admitted output profile:
`candidate-canonical-binary-v1`.

Resolution accepts only the application tenant, destination reference and
time. It does not accept a buyer, recipient, target metadata reference,
object reference, work reference, publication reference, transaction ID,
payload, serializer or key from a caller. The recipient label is excluded from
representations to prevent incidental logging, but it is **not confidential**:
the profile digest is an unsalted commitment and a low-entropy label could be
guessed. Treat it as a non-secret configured identifier. A later production
design requiring recipient confidentiality needs a keyed commitment or
encrypted configuration boundary before using this contract.

This module is not a release authorization or delivery capability. It has no
database, signer, API route, mutation endpoint, worker, object store, URL or
credential. Provisioning, activation/revocation, contract legality and admin
approval are explicitly outside this pure contract; they require separate
tenant-admin/legal controls and immutable audit records. A future issuer must
also validate a live M14 case, M15 decision, M18 request/approvals and M21
readiness, use `ReleaseCaseAuthority.matches_recipient_commitment`, allocate
all publication/metadata/object/work references server-side, and lock the
active destination version in PostgreSQL before an M43 signature is persisted.
Those live controls currently do not share a PostgreSQL transaction boundary,
so this module deliberately does not issue an attestation. Production routes
remain closed.
