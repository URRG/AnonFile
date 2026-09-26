-- M48b3: inert, immutable processing-run lineage binding.
-- This records no bytes, object locator, worker action, API, or release decision.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_processing_run_lineages (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    processing_run_ref TEXT NOT NULL UNIQUE
        CHECK (processing_run_ref ~ '^processingrunref:v1:[A-Za-z0-9_-]{43}$'),
    source_snapshot_digest TEXT NOT NULL CHECK (source_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    source_dataset_ref TEXT NOT NULL
        CHECK (source_dataset_ref ~ '^supplierdatasetref:v1:[A-Za-z0-9_-]{43}$'),
    source_content_digest TEXT NOT NULL CHECK (source_content_digest ~ '^sha256:[0-9a-f]{64}$'),
    provenance_digest TEXT NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_method_snapshot_digest TEXT NOT NULL CHECK (policy_method_snapshot_digest ~ '^sha256:[0-9a-f]{64}$'),
    policy_method_ref TEXT NOT NULL
        CHECK (policy_method_ref ~ '^policymethodref:v1:[A-Za-z0-9_-]{43}$'),
    policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    output_schema_digest TEXT NOT NULL CHECK (output_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    lineage_digest TEXT NOT NULL UNIQUE CHECK (lineage_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_ref, processing_run_ref),
    FOREIGN KEY (tenant_ref) REFERENCES anonflow_tenant_identities(tenant_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (tenant_ref, source_dataset_ref)
        REFERENCES anonflow_source_dataset_snapshots(tenant_ref, source_dataset_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (tenant_ref, policy_method_ref)
        REFERENCES anonflow_policy_method_snapshots(tenant_ref, policy_method_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (expires_at = date_trunc('second', expires_at))
);

CREATE TABLE IF NOT EXISTS anonflow_processing_run_lineage_fences (
    tenant_ref TEXT NOT NULL,
    processing_run_ref TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'QUARANTINED', 'REVOKED', 'EXPIRED')),
    event_ref TEXT UNIQUE CHECK (event_ref IS NULL OR event_ref ~ '^processingrunfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', clock_timestamp()),
    PRIMARY KEY (tenant_ref, processing_run_ref, generation),
    FOREIGN KEY (tenant_ref, processing_run_ref)
        REFERENCES anonflow_processing_run_lineages(tenant_ref, processing_run_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((generation = 0 AND state = 'ACTIVE' AND event_ref IS NULL)
        OR (generation = 1 AND state IN ('QUARANTINED', 'REVOKED', 'EXPIRED') AND event_ref IS NOT NULL)),
    CHECK (changed_at = date_trunc('second', changed_at))
);

CREATE OR REPLACE FUNCTION anonflow_validate_processing_run_lineage_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    source_row RECORD;
    policy_row RECORD;
    source_generation BIGINT;
    source_state TEXT;
    policy_generation BIGINT;
    policy_state TEXT;
BEGIN
    SELECT snapshot_digest, source_content_digest, provenance_digest, expires_at
      INTO source_row
      FROM anonflow_source_dataset_snapshots
     WHERE tenant_ref = NEW.tenant_ref AND source_dataset_ref = NEW.source_dataset_ref
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'processing run source snapshot unavailable';
    END IF;
    SELECT generation, state INTO source_generation, source_state
      FROM anonflow_source_dataset_snapshot_fences
     WHERE tenant_ref = NEW.tenant_ref AND source_dataset_ref = NEW.source_dataset_ref
     ORDER BY generation DESC LIMIT 1;
    IF source_generation IS DISTINCT FROM 0 OR source_state IS DISTINCT FROM 'ACTIVE'
       OR date_trunc('second', clock_timestamp()) >= source_row.expires_at THEN
        RAISE EXCEPTION 'processing run source snapshot is not live';
    END IF;

    SELECT policy_digest, output_schema_digest, expires_at
      INTO policy_row
      FROM anonflow_policy_method_snapshots
     WHERE tenant_ref = NEW.tenant_ref AND policy_method_ref = NEW.policy_method_ref
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'processing run policy method snapshot unavailable';
    END IF;
    SELECT generation, state INTO policy_generation, policy_state
      FROM anonflow_policy_method_snapshot_fences
     WHERE tenant_ref = NEW.tenant_ref AND policy_method_ref = NEW.policy_method_ref
     ORDER BY generation DESC LIMIT 1;
    IF policy_generation IS DISTINCT FROM 0 OR policy_state IS DISTINCT FROM 'ACTIVE'
       OR date_trunc('second', clock_timestamp()) >= policy_row.expires_at THEN
        RAISE EXCEPTION 'processing run policy method snapshot is not live';
    END IF;

    IF NEW.source_snapshot_digest <> source_row.snapshot_digest
       OR NEW.source_content_digest <> source_row.source_content_digest
       OR NEW.provenance_digest <> source_row.provenance_digest
       OR NEW.policy_digest <> policy_row.policy_digest
       OR NEW.output_schema_digest <> policy_row.output_schema_digest
       OR NEW.expires_at <= date_trunc('second', clock_timestamp())
       OR NEW.expires_at > source_row.expires_at
       OR NEW.expires_at > policy_row.expires_at THEN
        RAISE EXCEPTION 'processing run lineage does not exactly bind live parents';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION anonflow_validate_processing_run_lineage_fence_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    latest_generation BIGINT;
    latest_state TEXT;
    run_expires_at TIMESTAMPTZ;
BEGIN
    SELECT expires_at INTO run_expires_at
      FROM anonflow_processing_run_lineages
     WHERE tenant_ref = NEW.tenant_ref AND processing_run_ref = NEW.processing_run_ref
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'processing run lineage parent unavailable';
    END IF;
    SELECT generation, state INTO latest_generation, latest_state
      FROM anonflow_processing_run_lineage_fences
     WHERE tenant_ref = NEW.tenant_ref AND processing_run_ref = NEW.processing_run_ref
     ORDER BY generation DESC LIMIT 1;
    IF latest_generation IS NULL THEN
        IF NEW.generation <> 0 OR NEW.state <> 'ACTIVE' OR NEW.event_ref IS NOT NULL THEN
            RAISE EXCEPTION 'processing run lineage fence must start active at generation zero';
        END IF;
    ELSIF latest_generation = 0 AND latest_state = 'ACTIVE' THEN
        IF NEW.generation <> 1 OR NEW.state NOT IN ('QUARANTINED', 'REVOKED', 'EXPIRED')
           OR NEW.event_ref IS NULL THEN
            RAISE EXCEPTION 'processing run lineage fence must append one terminal generation';
        END IF;
        IF NEW.state = 'EXPIRED' AND date_trunc('second', clock_timestamp()) < run_expires_at THEN
            RAISE EXCEPTION 'processing run lineage is not expired';
        END IF;
    ELSE
        RAISE EXCEPTION 'processing run lineage already has a terminal fence';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION anonflow_require_processing_run_lineage_baseline()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM anonflow_processing_run_lineage_fences
         WHERE tenant_ref = NEW.tenant_ref AND processing_run_ref = NEW.processing_run_ref
           AND generation = 0 AND state = 'ACTIVE' AND event_ref IS NULL
    ) THEN
        RAISE EXCEPTION 'processing run lineage requires an active generation-zero fence';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION anonflow_reject_processing_run_lineage_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'processing run lineages are immutable';
END;
$$;

DROP TRIGGER IF EXISTS anonflow_processing_run_lineages_validate_insert ON anonflow_processing_run_lineages;
CREATE TRIGGER anonflow_processing_run_lineages_validate_insert
BEFORE INSERT ON anonflow_processing_run_lineages
FOR EACH ROW EXECUTE FUNCTION anonflow_validate_processing_run_lineage_insert();
DROP TRIGGER IF EXISTS anonflow_processing_run_lineages_require_baseline ON anonflow_processing_run_lineages;
CREATE CONSTRAINT TRIGGER anonflow_processing_run_lineages_require_baseline
AFTER INSERT ON anonflow_processing_run_lineages DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION anonflow_require_processing_run_lineage_baseline();
DROP TRIGGER IF EXISTS anonflow_processing_run_lineages_immutable ON anonflow_processing_run_lineages;
CREATE TRIGGER anonflow_processing_run_lineages_immutable
BEFORE UPDATE OR DELETE ON anonflow_processing_run_lineages
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_processing_run_lineage_mutation();
DROP TRIGGER IF EXISTS anonflow_processing_run_lineage_fences_validate_insert ON anonflow_processing_run_lineage_fences;
CREATE TRIGGER anonflow_processing_run_lineage_fences_validate_insert
BEFORE INSERT ON anonflow_processing_run_lineage_fences
FOR EACH ROW EXECUTE FUNCTION anonflow_validate_processing_run_lineage_fence_insert();
DROP TRIGGER IF EXISTS anonflow_processing_run_lineage_fences_immutable ON anonflow_processing_run_lineage_fences;
CREATE TRIGGER anonflow_processing_run_lineage_fences_immutable
BEFORE UPDATE OR DELETE ON anonflow_processing_run_lineage_fences
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_processing_run_lineage_mutation();
COMMIT;
