-- M26 metadata-only PostgreSQL substrate. Apply explicitly with a privileged
-- migration role before using PostgresControlPlaneMetadata; the adapter never
-- creates or migrates schema at application startup.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_metadata_records (
    tenant_ref TEXT NOT NULL,
    record_id TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    document JSONB NOT NULL CHECK (octet_length(document::text) <= 65536),
    PRIMARY KEY (tenant_ref, record_id)
);

CREATE TABLE IF NOT EXISTS anonflow_metadata_transactions (
    tenant_ref TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    request_digest CHAR(64) NOT NULL,
    -- NULL exists only during the enclosing uncommitted transaction.
    result_document JSONB CHECK (result_document IS NULL OR octet_length(result_document::text) <= 8389632),
    PRIMARY KEY (tenant_ref, transaction_id)
);

COMMIT;
