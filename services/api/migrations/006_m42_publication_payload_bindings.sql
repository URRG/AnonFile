-- M42a immutable release-payload commitments.  Apply after migrations 003--005.
-- This stores opaque identifiers and commitments only: never release bytes,
-- URLs, envelopes, ciphertext, or key material.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_publication_payload_bindings (
    tenant_ref TEXT NOT NULL
        CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    publication_ref TEXT NOT NULL
        CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    object_ref TEXT NOT NULL
        CHECK (object_ref ~ '^objectref:v1:[A-Za-z0-9_-]{43}$'),
    key_ref TEXT NOT NULL
        CHECK (key_ref ~ '^keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}$'),
    plan_digest TEXT NOT NULL
        CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
    payload_digest TEXT NOT NULL
        CHECK (payload_digest ~ '^sha256:[0-9a-f]{64}$'),
    payload_size_bytes BIGINT NOT NULL
        CHECK (payload_size_bytes BETWEEN 0 AND 33554432),
    serialization_id TEXT NOT NULL
        CHECK (serialization_id IN ('binary-v1', 'jsonl-utf8-v1')),
    binding_digest TEXT NOT NULL
        CHECK (binding_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, publication_ref),
    UNIQUE (publication_ref),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_intents (tenant_ref, publication_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- A binding is a release commitment, not mutable metadata.  A database owner
-- can alter the schema; that administrative boundary must be audited outside
-- this adapter.
CREATE OR REPLACE FUNCTION anonflow_reject_publication_payload_binding_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'publication payload bindings are immutable';
END;
$$;
DROP TRIGGER IF EXISTS anonflow_publication_payload_bindings_immutable
    ON anonflow_publication_payload_bindings;
CREATE TRIGGER anonflow_publication_payload_bindings_immutable
    BEFORE UPDATE OR DELETE ON anonflow_publication_payload_bindings
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_publication_payload_binding_mutation();

COMMIT;
