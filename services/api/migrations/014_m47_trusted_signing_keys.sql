-- M47: immutable, tenant-bound trusted Ed25519 public-key registry.
-- This is metadata and revocation state only: it holds no private key,
-- signature, approval, issuer, or HTTP-facing authorization path.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_trusted_signing_keys (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    actor_ref TEXT NOT NULL CHECK (actor_ref ~ '^actorref:v1:[A-Za-z0-9_-]{43}$'),
    key_ref TEXT NOT NULL CHECK (key_ref ~ '^signingkeyref:v1:[A-Za-z0-9_-]{43}$'),
    role TEXT NOT NULL CHECK (role IN ('PRIVACY_REVIEWER','RELEASE_AUTHORIZER','SERVICE_ISSUER')),
    -- The payload is exactly 32 bytes and must be its canonical, unpadded
    -- base64url spelling; aliases cannot name the same Ed25519 public key.
    public_key TEXT NOT NULL UNIQUE CHECK (
        public_key ~ '^ed25519pub:v1:[A-Za-z0-9_-]{43}$' AND
        replace(replace(rtrim(encode(decode(
            replace(replace(substr(public_key, 15), '-', '+'), '_', '/') || '=',
            'base64'), 'base64'), '='), '+', '-'), '/', '_') = substr(public_key, 15)
    ),
    not_before TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (expires_at > not_before),
    PRIMARY KEY (tenant_ref, key_ref),
    UNIQUE (key_ref)
);

CREATE INDEX IF NOT EXISTS anonflow_trusted_signing_keys_tenant_actor_role_idx
    ON anonflow_trusted_signing_keys (tenant_ref, actor_ref, role, key_ref);

CREATE TABLE IF NOT EXISTS anonflow_trusted_signing_key_fences (
    tenant_ref TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','REVOKED')),
    event_ref TEXT UNIQUE CHECK (event_ref IS NULL OR event_ref ~ '^signingkeyfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, key_ref, generation),
    FOREIGN KEY (tenant_ref, key_ref)
        REFERENCES anonflow_trusted_signing_keys(tenant_ref, key_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((generation = 0 AND state = 'ACTIVE' AND event_ref IS NULL) OR
           (generation > 0 AND state = 'REVOKED' AND event_ref IS NOT NULL))
);

-- Fence timestamps are part of the strict application model.  Keep this
-- explicit ALTER rerunnable for databases where the table predated this
-- migration revision or a deployment retried after partial setup.
ALTER TABLE anonflow_trusted_signing_key_fences
    ALTER COLUMN changed_at SET DEFAULT date_trunc('second', clock_timestamp());

CREATE OR REPLACE FUNCTION anonflow_reject_trusted_signing_key_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'trusted signing keys are immutable';
END;
$$;

CREATE OR REPLACE FUNCTION anonflow_reject_trusted_signing_key_fence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'trusted signing key fences are immutable';
END;
$$;

DROP TRIGGER IF EXISTS anonflow_trusted_signing_keys_immutable
    ON anonflow_trusted_signing_keys;
CREATE TRIGGER anonflow_trusted_signing_keys_immutable
    BEFORE UPDATE OR DELETE ON anonflow_trusted_signing_keys
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_trusted_signing_key_mutation();

DROP TRIGGER IF EXISTS anonflow_trusted_signing_key_fences_immutable
    ON anonflow_trusted_signing_key_fences;
CREATE TRIGGER anonflow_trusted_signing_key_fences_immutable
    BEFORE UPDATE OR DELETE ON anonflow_trusted_signing_key_fences
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_trusted_signing_key_fence_mutation();
COMMIT;
