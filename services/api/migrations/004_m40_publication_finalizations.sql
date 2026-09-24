-- M40 claim-fenced completion receipt.  It has no route or delivery effect.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_publication_finalizations (
    tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    publication_ref TEXT NOT NULL CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    completion_digest CHAR(64) NOT NULL CHECK (completion_digest ~ '^[0-9a-f]{64}$'),
    result_document JSONB NOT NULL CHECK (octet_length(result_document::text) <= 16384),
    finalized_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, publication_ref),
    FOREIGN KEY (tenant_ref, publication_ref) REFERENCES anonflow_publication_intents (tenant_ref, publication_ref)
);
COMMIT;
