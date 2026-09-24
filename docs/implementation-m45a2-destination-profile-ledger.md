# M45a2 destination-profile ledger

This PostgreSQL-only slice turns an **already computed M44b profile digest**
into an immutable, tenant-scoped version with an append-only terminal fence.
It stores neither a recipient label nor the other underlying destination
fields. `destination_ref` has one global owner, preventing an opaque
destination identifier from being resolved in two PostgreSQL tenant scopes.

The first fence generation is ACTIVE. A later generation is terminal
DEACTIVATED or REVOKED. Every operation takes the global immutable destination
identity-row lock **first**, then the immutable profile-row lock. `lock_active`
requires READ COMMITTED, reads the newest fence after those locks, and checks
the PostgreSQL clock against `[not_before, expires_at)`. A future mutation must
keep that transaction open and repeat the database-clock check immediately
before commit. Inspection via `fence()` does not retain either lock. The
adapter rejects REPEATABLE READ and SERIALIZABLE because their retained
snapshots do not provide the required post-wait visibility.

Profile rotation is intentionally narrow: versions begin at one and advance
one at a time. A successor may be created only after the immediately preceding
version is terminal DEACTIVATED. REVOKED is permanent for that destination;
there is no successor. Every operation locks the global destination identity
before a profile row. An active read additionally requires its requested
version to be the current highest version, so an old version cannot be used
after a successor commits. Exact terminal-event retries remain readable
history, but cannot alter a newer profile.

This is **not** trusted provisioning or business authorization. It has no
admin route, signer, M43 attestation, M39 admission, candidate access,
delivery capability, or worker. It cannot determine whether a profile digest
represents a legal buyer, a valid contract, a rights grant, a recipient
commitment, or an approved destination. A production issuer needs an
authoritative tenant-admin/legal provisioning boundary and a transactionally
co-located live release-control snapshot before it may use this ledger.
