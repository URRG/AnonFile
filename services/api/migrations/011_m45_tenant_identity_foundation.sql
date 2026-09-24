-- M45a3: immutable application-tenant to tenantref mapping and terminal fence.
-- No provisioning/admin route or release authorization is created here.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_tenant_identities (
    application_tenant TEXT PRIMARY KEY CHECK (application_tenant ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
    tenant_ref TEXT NOT NULL UNIQUE CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS anonflow_tenant_identity_fences (
    application_tenant TEXT NOT NULL REFERENCES anonflow_tenant_identities(application_tenant) ON DELETE RESTRICT ON UPDATE RESTRICT,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','DISABLED','QUARANTINED')),
    event_ref TEXT UNIQUE CHECK (event_ref IS NULL OR event_ref ~ '^tenantfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (application_tenant, generation),
    CHECK ((generation = 0 AND state = 'ACTIVE' AND event_ref IS NULL) OR
           (generation > 0 AND state IN ('DISABLED','QUARANTINED') AND event_ref IS NOT NULL))
);
CREATE OR REPLACE FUNCTION anonflow_reject_tenant_identity_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'tenant identities are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_tenant_identities_immutable ON anonflow_tenant_identities;
CREATE TRIGGER anonflow_tenant_identities_immutable BEFORE UPDATE OR DELETE ON anonflow_tenant_identities
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_tenant_identity_mutation();
CREATE OR REPLACE FUNCTION anonflow_reject_tenant_identity_fence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'tenant identity fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_tenant_identity_fences_immutable ON anonflow_tenant_identity_fences;
CREATE TRIGGER anonflow_tenant_identity_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_tenant_identity_fences
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_tenant_identity_fence_mutation();
COMMIT;
