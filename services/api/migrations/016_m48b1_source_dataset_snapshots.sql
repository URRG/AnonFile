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
 CHECK((generation=0 AND state='ACTIVE' AND event_ref IS NULL) OR (generation>0 AND state IN ('QUARANTINED','REVOKED','EXPIRED') AND event_ref IS NOT NULL)));
CREATE OR REPLACE FUNCTION anonflow_reject_source_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'source dataset snapshots are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshots_immutable ON anonflow_source_dataset_snapshots;
CREATE TRIGGER anonflow_source_dataset_snapshots_immutable BEFORE UPDATE OR DELETE ON anonflow_source_dataset_snapshots FOR EACH ROW EXECUTE FUNCTION anonflow_reject_source_snapshot_mutation();
DROP TRIGGER IF EXISTS anonflow_source_dataset_snapshot_fences_immutable ON anonflow_source_dataset_snapshot_fences;
CREATE TRIGGER anonflow_source_dataset_snapshot_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_source_dataset_snapshot_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_source_snapshot_mutation();
COMMIT;
