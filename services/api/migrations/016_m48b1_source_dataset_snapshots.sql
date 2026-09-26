-- M48b1: immutable source-dataset snapshot metadata; no content or object locator.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_source_dataset_snapshots (
 tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
 source_dataset_ref TEXT NOT NULL UNIQUE CHECK (source_dataset_ref ~ '^supplierdatasetref:v1:[A-Za-z0-9_-]{43}$'),
 source_content_digest TEXT NOT NULL CHECK (source_content_digest ~ '^sha256:[0-9a-f]{64}$'),
 provenance_digest TEXT NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
 input_schema_digest TEXT NOT NULL CHECK (input_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
 source_byte_count BIGINT NOT NULL CHECK (source_byte_count > 0), expires_at TIMESTAMPTZ NOT NULL,
 snapshot_digest TEXT NOT NULL UNIQUE CHECK (snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
 FOREIGN KEY (tenant_ref) REFERENCES anonflow_tenant_identities(tenant_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 PRIMARY KEY (tenant_ref, source_dataset_ref));
CREATE TABLE IF NOT EXISTS anonflow_source_dataset_snapshot_fences (
 tenant_ref TEXT NOT NULL, source_dataset_ref TEXT NOT NULL, generation BIGINT NOT NULL CHECK(generation>=0),
 state TEXT NOT NULL CHECK(state IN ('ACTIVE','QUARANTINED','REVOKED','EXPIRED')),
 event_ref TEXT UNIQUE CHECK(event_ref IS NULL OR event_ref ~ '^sourcesnapshotfence:v1:[A-Za-z0-9_-]{43}$'),
 changed_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second',clock_timestamp()),
 PRIMARY KEY(tenant_ref,source_dataset_ref,generation), FOREIGN KEY(tenant_ref,source_dataset_ref) REFERENCES anonflow_source_dataset_snapshots(tenant_ref,source_dataset_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK((generation=0 AND state='ACTIVE' AND event_ref IS NULL) OR
       (generation=1 AND state IN ('QUARANTINED','REVOKED','EXPIRED') AND event_ref IS NOT NULL)));
ALTER TABLE anonflow_source_dataset_snapshots
    DROP CONSTRAINT IF EXISTS anonflow_source_dataset_snapshots_expires_at_second_check;
ALTER TABLE anonflow_source_dataset_snapshots
    ADD CONSTRAINT anonflow_source_dataset_snapshots_expires_at_second_check
    CHECK (expires_at = date_trunc('second', expires_at));
ALTER TABLE anonflow_source_dataset_snapshot_fences
    DROP CONSTRAINT IF EXISTS anonflow_source_dataset_snapshot_fences_changed_at_second_check;
ALTER TABLE anonflow_source_dataset_snapshot_fences
    ADD CONSTRAINT anonflow_source_dataset_snapshot_fences_changed_at_second_check
    CHECK (changed_at = date_trunc('second', changed_at));
CREATE OR REPLACE FUNCTION anonflow_require_source_snapshot_active_fence()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM anonflow_source_dataset_snapshot_fences
        WHERE tenant_ref=NEW.tenant_ref AND source_dataset_ref=NEW.source_dataset_ref
          AND generation=0 AND state='ACTIVE' AND event_ref IS NULL
    ) THEN
        RAISE EXCEPTION 'source dataset snapshot requires an active generation-zero fence';
    END IF;
    RETURN NULL;
END;
$$;
CREATE OR REPLACE FUNCTION anonflow_validate_source_snapshot_fence_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE latest_generation BIGINT;
DECLARE latest_state TEXT;
DECLARE snapshot_expires_at TIMESTAMPTZ;
BEGIN
    SELECT expires_at INTO snapshot_expires_at FROM anonflow_source_dataset_snapshots
    WHERE tenant_ref=NEW.tenant_ref AND source_dataset_ref=NEW.source_dataset_ref
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source dataset snapshot parent unavailable';
    END IF;
    SELECT generation,state INTO latest_generation,latest_state
    FROM anonflow_source_dataset_snapshot_fences
    WHERE tenant_ref=NEW.tenant_ref AND source_dataset_ref=NEW.source_dataset_ref
    ORDER BY generation DESC LIMIT 1;
    IF latest_generation IS NULL THEN
        IF NEW.generation<>0 OR NEW.state<>'ACTIVE' OR NEW.event_ref IS NOT NULL THEN
            RAISE EXCEPTION 'source dataset snapshot fence must start active at generation zero';
        END IF;
    ELSIF latest_generation=0 AND latest_state='ACTIVE' THEN
        IF NEW.generation<>1 OR NEW.state NOT IN ('QUARANTINED','REVOKED','EXPIRED')
           OR NEW.event_ref IS NULL THEN
            RAISE EXCEPTION 'source dataset snapshot fence must append one terminal generation';
        END IF;
        IF NEW.state='EXPIRED' AND date_trunc('second', clock_timestamp()) < snapshot_expires_at THEN
            RAISE EXCEPTION 'source dataset snapshot is not expired';
        END IF;
    ELSE
        RAISE EXCEPTION 'source dataset snapshot already has a terminal fence';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshots_require_active_fence
    ON anonflow_source_dataset_snapshots;
CREATE CONSTRAINT TRIGGER anonflow_source_dataset_snapshots_require_active_fence
    AFTER INSERT ON anonflow_source_dataset_snapshots DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION anonflow_require_source_snapshot_active_fence();
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshot_fences_validate_insert
    ON anonflow_source_dataset_snapshot_fences;
CREATE TRIGGER anonflow_source_dataset_snapshot_fences_validate_insert
    BEFORE INSERT ON anonflow_source_dataset_snapshot_fences
    FOR EACH ROW EXECUTE FUNCTION anonflow_validate_source_snapshot_fence_insert();
CREATE OR REPLACE FUNCTION anonflow_reject_source_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'source dataset snapshots are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshots_immutable ON anonflow_source_dataset_snapshots;
CREATE TRIGGER anonflow_source_dataset_snapshots_immutable BEFORE UPDATE OR DELETE ON anonflow_source_dataset_snapshots FOR EACH ROW EXECUTE FUNCTION anonflow_reject_source_snapshot_mutation();
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshot_fences_immutable ON anonflow_source_dataset_snapshot_fences;
CREATE TRIGGER anonflow_source_dataset_snapshot_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_source_dataset_snapshot_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_source_snapshot_mutation();
COMMIT;
