-- M45a2: PostgreSQL destination-profile digest identity and terminal fence.
-- No recipient label or business/admin authorization is present in this ledger.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_destination_identities (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    destination_ref TEXT NOT NULL CHECK (destination_ref ~ '^destinationref:v1:[A-Za-z0-9_-]{43}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, destination_ref), UNIQUE (destination_ref)
);
CREATE TABLE IF NOT EXISTS anonflow_destination_profiles (
    tenant_ref TEXT NOT NULL, destination_ref TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    profile_digest TEXT NOT NULL CHECK (profile_digest ~ '^sha256:[0-9a-f]{64}$'),
    not_before TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, destination_ref, version),
    FOREIGN KEY (tenant_ref, destination_ref) REFERENCES anonflow_destination_identities (tenant_ref, destination_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (expires_at > not_before)
);
CREATE TABLE IF NOT EXISTS anonflow_destination_profile_fences (
    tenant_ref TEXT NOT NULL, destination_ref TEXT NOT NULL, version BIGINT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','DEACTIVATED','REVOKED')),
    event_ref TEXT CHECK (event_ref IS NULL OR event_ref ~ '^destinationfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref,destination_ref,version,generation), UNIQUE (event_ref),
    FOREIGN KEY (tenant_ref,destination_ref,version) REFERENCES anonflow_destination_profiles (tenant_ref,destination_ref,version) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((generation=0 AND state='ACTIVE' AND event_ref IS NULL) OR
           (generation>0 AND state IN ('DEACTIVATED','REVOKED') AND event_ref IS NOT NULL))
);
CREATE OR REPLACE FUNCTION anonflow_reject_destination_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'destination identities are immutable'; END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_destination_profile_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'destination profiles are immutable'; END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_destination_profile_fence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'destination profile fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_destination_identities_immutable ON anonflow_destination_identities;
CREATE TRIGGER anonflow_destination_identities_immutable BEFORE UPDATE OR DELETE ON anonflow_destination_identities FOR EACH ROW EXECUTE FUNCTION anonflow_reject_destination_identity_mutation();
DROP TRIGGER IF EXISTS anonflow_destination_profiles_immutable ON anonflow_destination_profiles;
CREATE TRIGGER anonflow_destination_profiles_immutable BEFORE UPDATE OR DELETE ON anonflow_destination_profiles FOR EACH ROW EXECUTE FUNCTION anonflow_reject_destination_profile_mutation();
DROP TRIGGER IF EXISTS anonflow_destination_profile_fences_immutable ON anonflow_destination_profile_fences;
CREATE TRIGGER anonflow_destination_profile_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_destination_profile_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_destination_profile_fence_mutation();
COMMIT;
