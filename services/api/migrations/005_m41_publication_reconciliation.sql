-- M41a bounded, metadata-only observation ledger.  It never performs object
-- I/O, changes finalization state, or acknowledges worker jobs.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_publication_observations (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    publication_ref TEXT NOT NULL CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    observation_epoch BIGINT NOT NULL CHECK (observation_epoch >= 1),
    observation_token TEXT NOT NULL
        CHECK (observation_token ~ '^observation:v1:[A-Za-z0-9_-]{43}$'),
    state TEXT NOT NULL CHECK (state IN ('OBSERVED', 'QUARANTINED')),
    reason TEXT CHECK (reason IS NULL OR reason IN ('OPERATOR_CONFIRMED_UNRECOVERABLE')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    quarantined_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_ref, publication_ref),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_intents (tenant_ref, publication_ref),
    CHECK ((state = 'OBSERVED' AND reason IS NULL AND quarantined_at IS NULL)
       OR (state = 'QUARANTINED' AND reason IS NOT NULL AND quarantined_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS anonflow_publication_observation_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    publication_ref TEXT NOT NULL,
    observation_epoch BIGINT NOT NULL CHECK (observation_epoch >= 1),
    event_type TEXT NOT NULL CHECK (event_type IN ('OBSERVED', 'QUARANTINED')),
    reason TEXT CHECK (reason IS NULL OR reason IN ('OPERATOR_CONFIRMED_UNRECOVERABLE')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_observations (tenant_ref, publication_ref),
    CHECK ((event_type = 'OBSERVED' AND reason IS NULL)
       OR (event_type = 'QUARANTINED' AND reason = 'OPERATOR_CONFIRMED_UNRECOVERABLE'))
);

-- Event rows are append-only even for the application migration role. A
-- database owner can of course alter schema; that administrative boundary is
-- outside this metadata adapter and must be independently audited.
CREATE OR REPLACE FUNCTION anonflow_reject_publication_observation_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'publication observation events are append-only';
END;
$$;
DROP TRIGGER IF EXISTS anonflow_publication_observation_events_immutable
    ON anonflow_publication_observation_events;
CREATE TRIGGER anonflow_publication_observation_events_immutable
    BEFORE UPDATE OR DELETE ON anonflow_publication_observation_events
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_publication_observation_event_mutation();

CREATE INDEX IF NOT EXISTS anonflow_publication_observations_tenant_state_expiry_idx
    ON anonflow_publication_observations (tenant_ref, state, lease_expires_at, publication_ref);
CREATE INDEX IF NOT EXISTS anonflow_publication_observation_events_tenant_publication_idx
    ON anonflow_publication_observation_events (tenant_ref, publication_ref, event_id);
CREATE INDEX IF NOT EXISTS anonflow_publication_intents_reconcile_idx
    ON anonflow_publication_intents (tenant_ref, created_at, publication_ref);

COMMIT;
