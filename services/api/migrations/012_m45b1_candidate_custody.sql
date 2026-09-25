-- M45b1: inert candidate-custody metadata intent. No bytes, object, key, or release capability.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_candidate_custody_intents (
 tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
 custody_ref TEXT NOT NULL CHECK (custody_ref ~ '^custodyref:v1:[A-Za-z0-9_-]{43}$'),
 artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'), run_digest TEXT NOT NULL CHECK (run_digest ~ '^sha256:[0-9a-f]{64}$'), policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'), schema_digest TEXT NOT NULL CHECK (schema_digest ~ '^sha256:[0-9a-f]{64}$'), provenance_digest TEXT NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
 byte_count BIGINT NOT NULL CHECK (byte_count > 0), expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (tenant_ref,custody_ref), UNIQUE (custody_ref)
);
CREATE TABLE IF NOT EXISTS anonflow_candidate_custody_fences (
 tenant_ref TEXT NOT NULL, custody_ref TEXT NOT NULL, generation BIGINT NOT NULL CHECK (generation >= 0),
 state TEXT NOT NULL CHECK (state IN ('PENDING_UPLOAD','QUARANTINED','REVOKED','EXPIRED')),
 event_ref TEXT CHECK (event_ref IS NULL OR event_ref ~ '^custodyfence:v1:[A-Za-z0-9_-]{43}$'), changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_ref,custody_ref,generation), UNIQUE(event_ref),
 FOREIGN KEY (tenant_ref,custody_ref) REFERENCES anonflow_candidate_custody_intents(tenant_ref,custody_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK ((generation=0 AND state='PENDING_UPLOAD' AND event_ref IS NULL) OR (generation>0 AND state IN ('QUARANTINED','REVOKED','EXPIRED') AND event_ref IS NOT NULL))
);
CREATE OR REPLACE FUNCTION anonflow_reject_candidate_custody_intent_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'candidate custody intents are immutable'; END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_candidate_custody_fence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'candidate custody fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_candidate_custody_intents_immutable ON anonflow_candidate_custody_intents;
CREATE TRIGGER anonflow_candidate_custody_intents_immutable BEFORE UPDATE OR DELETE ON anonflow_candidate_custody_intents FOR EACH ROW EXECUTE FUNCTION anonflow_reject_candidate_custody_intent_mutation();
DROP TRIGGER IF EXISTS anonflow_candidate_custody_fences_immutable ON anonflow_candidate_custody_fences;
CREATE TRIGGER anonflow_candidate_custody_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_candidate_custody_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_candidate_custody_fence_mutation();
COMMIT;
