-- M45a1: PostgreSQL-only release-control identity and terminal fence ledger.
-- This does NOT migrate M14--M21, issue an authorization, or enable a route.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_release_control_snapshots (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    snapshot_ref TEXT NOT NULL CHECK (snapshot_ref ~ '^releasectrlref:v1:[A-Za-z0-9_-]{43}$'),
    control_digest TEXT NOT NULL CHECK (control_digest ~ '^sha256:[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, snapshot_ref), UNIQUE (snapshot_ref)
);
CREATE TABLE IF NOT EXISTS anonflow_release_control_fences (
    tenant_ref TEXT NOT NULL, snapshot_ref TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE','REVOKED','QUARANTINED')),
    event_ref TEXT CHECK (event_ref IS NULL OR event_ref ~ '^controlfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, snapshot_ref, generation),
    UNIQUE (event_ref),
    FOREIGN KEY (tenant_ref, snapshot_ref) REFERENCES anonflow_release_control_snapshots (tenant_ref, snapshot_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((generation = 0 AND state = 'ACTIVE' AND event_ref IS NULL) OR
           (generation > 0 AND state IN ('REVOKED','QUARANTINED') AND event_ref IS NOT NULL))
);
CREATE OR REPLACE FUNCTION anonflow_reject_release_control_snapshot_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'release control snapshots are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_release_control_snapshots_immutable ON anonflow_release_control_snapshots;
CREATE TRIGGER anonflow_release_control_snapshots_immutable BEFORE UPDATE OR DELETE ON anonflow_release_control_snapshots FOR EACH ROW EXECUTE FUNCTION anonflow_reject_release_control_snapshot_mutation();
CREATE OR REPLACE FUNCTION anonflow_reject_release_control_fence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'release control fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_release_control_fences_immutable ON anonflow_release_control_fences;
CREATE TRIGGER anonflow_release_control_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_release_control_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_release_control_fence_mutation();
COMMIT;
