# M47 trusted signing-key registry

M47 is a PostgreSQL-native registry of immutable tenant-bound Ed25519 **public
key metadata**.  It records opaque tenant, actor and key references; exactly
one of `PRIVACY_REVIEWER`, `RELEASE_AUTHORIZER`, or `SERVICE_ISSUER`; and a
not-before/expiry window.  It has no private keys, signatures, approvals,
issuer, route, or release capability.

Each registration creates generation-zero `ACTIVE`. A revocation appends the
only later state, terminal `REVOKED`; rows and fences cannot be changed or
deleted. Exact registration and revocation retries return their durable result;
cross-tenant, actor, role, key, generation, or public-key drift fails closed.
It is not an approval-independence control: a future issuer must enforce that
approval actors are distinct where the release policy requires it.

`lock_active` is solely a future issuer seam. It rejects idle/autocommit or
unknown driver cursors, requires PostgreSQL READ COMMITTED, locks the stable
tenant/key row, and then reads the newest fence in a fresh statement. A caller
must retain that transaction and recheck the PostgreSQL clock immediately
before its own mutation commits. This avoids a blocked active reader observing
a pre-revocation snapshot. The current code does not issue anything.
