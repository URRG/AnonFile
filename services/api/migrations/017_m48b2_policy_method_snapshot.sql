-- M48b2: immutable policy/method metadata snapshots. Deploy after 016; no dependency on it.
-- This creates neither policy execution nor any bytes, object, worker, or release authority.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_policy_method_snapshots (
 tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
 policy_method_ref TEXT NOT NULL CHECK (policy_method_ref ~ '^policymethodref:v1:[A-Za-z0-9_-]{43}$'),
 policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
 method_id TEXT NOT NULL CHECK (method_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
 method_version TEXT NOT NULL CHECK (method_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
 method_config_digest TEXT NOT NULL CHECK (method_config_digest ~ '^sha256:[0-9a-f]{64}$'),
 taxonomy_mapping_digest TEXT NOT NULL CHECK (taxonomy_mapping_digest ~ '^sha256:[0-9a-f]{64}$'),
 output_schema_digest TEXT NOT NULL CHECK (output_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_ref, policy_method_ref), UNIQUE (policy_method_ref),
 FOREIGN KEY (tenant_ref) REFERENCES anonflow_tenant_identities(tenant_ref) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE IF NOT EXISTS anonflow_policy_method_snapshot_fences (
 tenant_ref TEXT NOT NULL, policy_method_ref TEXT NOT NULL, generation BIGINT NOT NULL CHECK (generation >= 0),
 state TEXT NOT NULL CHECK (state IN ('ACTIVE','QUARANTINED','REVOKED','EXPIRED')),
 event_ref TEXT CHECK (event_ref IS NULL OR event_ref ~ '^policymethodfence:v1:[A-Za-z0-9_-]{43}$'),
 changed_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', clock_timestamp()),
 PRIMARY KEY (tenant_ref, policy_method_ref, generation), UNIQUE(event_ref),
 FOREIGN KEY (tenant_ref,policy_method_ref) REFERENCES anonflow_policy_method_snapshots(tenant_ref,policy_method_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK ((generation=0 AND state='ACTIVE' AND event_ref IS NULL) OR (generation>0 AND state IN ('QUARANTINED','REVOKED','EXPIRED') AND event_ref IS NOT NULL))
);
-- Named checks are added separately so rerunning 017 upgrades a table created
-- by an interrupted/older deployment rather than silently retaining looser SQL.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'anonflow_policy_method_snapshots_expires_at_second'
                     AND conrelid = 'anonflow_policy_method_snapshots'::regclass) THEN
        ALTER TABLE anonflow_policy_method_snapshots
        ADD CONSTRAINT anonflow_policy_method_snapshots_expires_at_second
        CHECK (expires_at = date_trunc('second', expires_at));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'anonflow_policy_method_snapshot_fences_changed_at_second'
                     AND conrelid = 'anonflow_policy_method_snapshot_fences'::regclass) THEN
        ALTER TABLE anonflow_policy_method_snapshot_fences
        ADD CONSTRAINT anonflow_policy_method_snapshot_fences_changed_at_second
        CHECK (changed_at = date_trunc('second', changed_at));
    END IF;
END $$;
-- Enforce the append-only state machine even for SQL clients that bypass the
-- Python adapter.  Locking the parent first matches the adapter's lock order
-- (tenant identity, then snapshot) and serializes concurrent fence writers.
CREATE OR REPLACE FUNCTION anonflow_validate_policy_method_snapshot_fence_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE latest_generation BIGINT;
DECLARE latest_state TEXT;
DECLARE parent_expires_at TIMESTAMPTZ;
BEGIN
    SELECT expires_at INTO parent_expires_at FROM anonflow_policy_method_snapshots
    WHERE tenant_ref = NEW.tenant_ref AND policy_method_ref = NEW.policy_method_ref
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'policy method snapshot does not exist';
    END IF;
    SELECT generation, state INTO latest_generation, latest_state
    FROM anonflow_policy_method_snapshot_fences
    WHERE tenant_ref = NEW.tenant_ref AND policy_method_ref = NEW.policy_method_ref
    ORDER BY generation DESC LIMIT 1;
    IF latest_generation IS NULL THEN
        IF NEW.generation = 0 AND NEW.state = 'ACTIVE' AND NEW.event_ref IS NULL THEN
            RETURN NEW;
        END IF;
    ELSIF latest_generation = 0 AND latest_state = 'ACTIVE' THEN
        IF NEW.generation = 1 AND NEW.state IN ('QUARANTINED','REVOKED','EXPIRED')
           AND NEW.event_ref IS NOT NULL THEN
            IF NEW.state = 'EXPIRED'
               AND date_trunc('second', clock_timestamp()) < parent_expires_at THEN
                RAISE EXCEPTION 'policy method snapshot has not expired';
            END IF;
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'invalid policy method snapshot fence transition';
END;
$$;
-- A snapshot and its generation-zero baseline are one atomic commitment.  The
-- adapter inserts both in one transaction; this deferred trigger rejects a raw
-- snapshot INSERT that attempts to commit without that baseline.
CREATE OR REPLACE FUNCTION anonflow_require_policy_method_snapshot_baseline()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM anonflow_policy_method_snapshot_fences
    WHERE tenant_ref = NEW.tenant_ref
      AND policy_method_ref = NEW.policy_method_ref
      AND generation = 0
      AND state = 'ACTIVE'
      AND event_ref IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'policy method snapshot requires an active baseline fence';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION anonflow_reject_policy_method_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'policy method snapshots are immutable'; END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_policy_method_snapshot_fence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'policy method snapshot fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_policy_method_snapshots_immutable ON anonflow_policy_method_snapshots;
CREATE TRIGGER anonflow_policy_method_snapshots_immutable BEFORE UPDATE OR DELETE ON anonflow_policy_method_snapshots FOR EACH ROW EXECUTE FUNCTION anonflow_reject_policy_method_snapshot_mutation();
DROP TRIGGER IF EXISTS anonflow_policy_method_snapshot_fences_immutable ON anonflow_policy_method_snapshot_fences;
CREATE TRIGGER anonflow_policy_method_snapshot_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_policy_method_snapshot_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_policy_method_snapshot_fence_mutation();
DROP TRIGGER IF EXISTS anonflow_policy_method_snapshot_fences_state_machine ON anonflow_policy_method_snapshot_fences;
CREATE TRIGGER anonflow_policy_method_snapshot_fences_state_machine BEFORE INSERT ON anonflow_policy_method_snapshot_fences FOR EACH ROW EXECUTE FUNCTION anonflow_validate_policy_method_snapshot_fence_insert();
DROP TRIGGER IF EXISTS anonflow_policy_method_snapshots_require_baseline ON anonflow_policy_method_snapshots;
CREATE CONSTRAINT TRIGGER anonflow_policy_method_snapshots_require_baseline
AFTER INSERT ON anonflow_policy_method_snapshots DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION anonflow_require_policy_method_snapshot_baseline();
COMMIT;
