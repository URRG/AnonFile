-- M39a immutable publication-intent ledger.  Apply explicitly with a
-- privileged migration role; this creates no publication worker or delivery.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_publication_intents (
    publication_ref TEXT NOT NULL
        CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    tenant_ref TEXT NOT NULL
        CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    transaction_id TEXT NOT NULL
        CHECK (transaction_id ~ '^metatx:v1:[A-Za-z0-9_-]{43}$'),
    object_ref TEXT NOT NULL
        CHECK (object_ref ~ '^objectref:v1:[A-Za-z0-9_-]{43}$'),
    plan_digest TEXT NOT NULL
        CHECK (plan_digest ~ '^sha256:[0-9a-f]{64}$'),
    document JSONB NOT NULL CHECK (octet_length(document::text) <= 16384),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, publication_ref),
    -- The external M38 object marker is one publication ref per create-only
    -- object key, so never allow a reference to cross a tenant boundary.
    UNIQUE (publication_ref),
    UNIQUE (tenant_ref, object_ref),
    UNIQUE (tenant_ref, transaction_id),
    CHECK (jsonb_typeof(document) = 'object'),
    CHECK (document ?& ARRAY['attributes', 'expected_version', 'key_ref', 'metadata_kind', 'object_ref',
                             'policy_digest', 'publication_ref', 'request_digest', 'state', 'target_ref',
                             'tenant_ref', 'transaction_id', 'work_ref']),
    CHECK (document - ARRAY['attributes', 'expected_version', 'key_ref', 'metadata_kind', 'object_ref',
                             'policy_digest', 'publication_ref', 'request_digest', 'state', 'target_ref',
                             'tenant_ref', 'transaction_id', 'work_ref'] = '{}'::jsonb),
    CHECK (document->>'tenant_ref' = tenant_ref),
    CHECK (document->>'publication_ref' = publication_ref),
    CHECK (document->>'transaction_id' = transaction_id),
    CHECK (document->>'object_ref' = object_ref),
    CHECK (document->>'state' = 'PENDING'),
    CHECK (document->>'object_ref' ~ '^objectref:v1:[A-Za-z0-9_-]{43}$'),
    CHECK (document->>'key_ref' ~ '^keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}$'),
    CHECK (document->>'work_ref' ~ '^workref:v1:[A-Za-z0-9_-]{43}$'),
    CHECK (document->>'target_ref' ~ '^metarecord:v1:[A-Za-z0-9_-]{43}$'),
    CHECK (document->>'metadata_kind' ~ '^[a-z][a-z0-9_]{0,63}$'),
    CHECK (document->>'request_digest' ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (document->>'policy_digest' ~ '^sha256:[0-9a-f]{64}$'),
    CHECK ((document->>'expected_version') ~ '^(0|[1-9][0-9]*)$'),
    CHECK (jsonb_typeof(document->'attributes') = 'object'),
    CHECK (document->'attributes' - ARRAY['authorization_ref', 'release_case_ref', 'sequence'] = '{}'::jsonb),
    CHECK (NOT (document->'attributes' ? 'authorization_ref')
           OR document->'attributes'->>'authorization_ref' ~ '^metarecord:v1:[A-Za-z0-9_-]{43}$'),
    CHECK (NOT (document->'attributes' ? 'release_case_ref')
           OR document->'attributes'->>'release_case_ref' ~ '^metarecord:v1:[A-Za-z0-9_-]{43}$'),
    CHECK (NOT (document->'attributes' ? 'sequence')
           OR document->'attributes'->>'sequence' ~ '^[1-9][0-9]*$')
);

CREATE INDEX IF NOT EXISTS anonflow_publication_intents_tenant_publication_idx
    ON anonflow_publication_intents (tenant_ref, publication_ref);

COMMIT;
