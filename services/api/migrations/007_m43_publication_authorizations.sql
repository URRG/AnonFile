-- M43b immutable externally-issued authorization envelopes. Apply after 006.
-- This table contains signed opaque commitments only, never release bytes,
-- recipient labels, private keys, credentials, or policy/contract bodies.
BEGIN;

CREATE TABLE IF NOT EXISTS anonflow_publication_authorizations (
    tenant_ref TEXT NOT NULL
        CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
    publication_ref TEXT NOT NULL
        CHECK (publication_ref ~ '^publicationref:v1:[A-Za-z0-9_-]{43}$'),
    attestation_digest TEXT NOT NULL
        CHECK (attestation_digest ~ '^sha256:[0-9a-f]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    document JSONB NOT NULL CHECK (octet_length(document::text) <= 16384),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, publication_ref),
    UNIQUE (publication_ref),
    FOREIGN KEY (tenant_ref, publication_ref)
        REFERENCES anonflow_publication_payload_bindings (tenant_ref, publication_ref)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (jsonb_typeof(document) = 'object'),
    CHECK (document ?& ARRAY['approval_digests', 'binding_digest', 'contract_digest', 'digest',
                             'expires_at', 'issued_at', 'issuer_key_id', 'metadata_kind', 'plan_digest',
                             'privacy_decision_digest', 'privacy_decision_id', 'publication_ref',
                             'purpose_code', 'recipient_commitment', 'release_case_digest', 'release_case_id',
                             'rights_digest', 'signature', 'target_ref', 'tenant_ref']),
    CHECK (document - ARRAY['approval_digests', 'binding_digest', 'contract_digest', 'digest',
                             'expires_at', 'issued_at', 'issuer_key_id', 'metadata_kind', 'plan_digest',
                             'privacy_decision_digest', 'privacy_decision_id', 'publication_ref',
                             'purpose_code', 'recipient_commitment', 'release_case_digest', 'release_case_id',
                             'rights_digest', 'signature', 'target_ref', 'tenant_ref'] = '{}'::jsonb),
    CHECK (document->>'tenant_ref' = tenant_ref),
    CHECK (document->>'publication_ref' = publication_ref),
    CHECK (document->>'digest' = attestation_digest),
    CHECK (document->>'expires_at' = to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE OR REPLACE FUNCTION anonflow_reject_publication_authorization_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'publication authorizations are immutable';
END;
$$;
DROP TRIGGER IF EXISTS anonflow_publication_authorizations_immutable
    ON anonflow_publication_authorizations;
CREATE TRIGGER anonflow_publication_authorizations_immutable
    BEFORE UPDATE OR DELETE ON anonflow_publication_authorizations
    FOR EACH ROW EXECUTE FUNCTION anonflow_reject_publication_authorization_mutation();

COMMIT;
