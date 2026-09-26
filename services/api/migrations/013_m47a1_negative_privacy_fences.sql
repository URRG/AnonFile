-- M47a1: denial-only, tenant-scoped subject privacy fences.
-- This migration creates no consent, lawful-basis, processing, or release authority.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_privacy_subjects (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    subject_ref TEXT NOT NULL CHECK (subject_ref ~ '^privacysubjectref:v1:[A-Za-z0-9_-]{43}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, subject_ref)
);
CREATE TABLE IF NOT EXISTS anonflow_negative_privacy_fences (
    tenant_ref TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation >= 0),
    state TEXT NOT NULL CHECK (state IN ('NONE','OPT_OUT','WITHDRAWN','QUARANTINED')),
    event_ref TEXT UNIQUE CHECK (event_ref IS NULL OR event_ref ~ '^privacyfence:v1:[A-Za-z0-9_-]{43}$'),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, subject_ref, generation),
    FOREIGN KEY (tenant_ref, subject_ref) REFERENCES anonflow_privacy_subjects (tenant_ref, subject_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((generation = 0 AND state = 'NONE' AND event_ref IS NULL) OR
           (generation > 0 AND state IN ('OPT_OUT','WITHDRAWN','QUARANTINED') AND event_ref IS NOT NULL))
);
CREATE OR REPLACE FUNCTION anonflow_reject_privacy_subject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'privacy subjects are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_privacy_subjects_immutable ON anonflow_privacy_subjects;
CREATE TRIGGER anonflow_privacy_subjects_immutable BEFORE UPDATE OR DELETE ON anonflow_privacy_subjects
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_privacy_subject_mutation();
CREATE OR REPLACE FUNCTION anonflow_reject_negative_privacy_fence_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'negative privacy fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_negative_privacy_fences_immutable ON anonflow_negative_privacy_fences;
CREATE TRIGGER anonflow_negative_privacy_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_negative_privacy_fences
FOR EACH ROW EXECUTE FUNCTION anonflow_reject_negative_privacy_fence_mutation();
COMMIT;
