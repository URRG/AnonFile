-- M41c: immutable, non-authorizing verification outcomes for M41 observations.
-- It stores no source bytes, ciphertext bytes, object key, URL, wrapped key, or token.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_publication_observation_verifications (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    publication_ref TEXT NOT NULL CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    observation_epoch BIGINT NOT NULL CHECK (observation_epoch >= 1),
    outcome TEXT NOT NULL CHECK (outcome IN ('VERIFIED', 'NOT_VERIFIED')),
    binding_digest TEXT NOT NULL CHECK (binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    authorization_digest TEXT NOT NULL CHECK (authorization_digest ~ '^sha256:[0-9a-f]{64}$'),
    ciphertext_digest TEXT CHECK (ciphertext_digest IS NULL OR ciphertext_digest ~ '^sha256:[0-9a-f]{64}$'),
    ciphertext_size_bytes BIGINT CHECK (ciphertext_size_bytes IS NULL OR ciphertext_size_bytes >= 0),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, publication_ref, observation_epoch),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_observations (tenant_ref, publication_ref),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_authorizations (tenant_ref, publication_ref),
    CHECK ((outcome = 'VERIFIED' AND ciphertext_digest IS NOT NULL AND ciphertext_size_bytes IS NOT NULL)
        OR (outcome = 'NOT_VERIFIED' AND ciphertext_digest IS NULL AND ciphertext_size_bytes IS NULL))
);

CREATE OR REPLACE FUNCTION anonflow_reject_publication_observation_verification_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'publication observation verifications are immutable';
END;
$$;
DROP TRIGGER IF EXISTS anonflow_publication_observation_verifications_immutable
    ON anonflow_publication_observation_verifications;
CREATE TRIGGER anonflow_publication_observation_verifications_immutable
    BEFORE UPDATE OR DELETE ON anonflow_publication_observation_verifications
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_publication_observation_verification_mutation();

COMMIT;
