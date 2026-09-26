-- M48a: designate a key role for exact-scope supplier-rights assertions.
-- The registry does not prove supplier ownership or agency.
-- This changes only the closed trusted-key role set. It stores neither an
-- assertion nor private key material and grants no release capability.
BEGIN;

-- Migration 014 created this named check. Replacing it in one transaction
-- retains a closed allow-list and takes the table lock needed to prevent an
-- observable interval with a broader role policy. The DROP/ADD sequence also
-- makes a retry after a completed migration safe.
ALTER TABLE anonflow_trusted_signing_keys
    DROP CONSTRAINT IF EXISTS anonflow_trusted_signing_keys_role_check;
ALTER TABLE anonflow_trusted_signing_keys
    DROP CONSTRAINT IF EXISTS anonflow_trusted_signing_keys_role_m48a_check;
ALTER TABLE anonflow_trusted_signing_keys
    ADD CONSTRAINT anonflow_trusted_signing_keys_role_m48a_check
    CHECK (role IN (
        'PRIVACY_REVIEWER',
        'RELEASE_AUTHORIZER',
        'SERVICE_ISSUER',
        'SUPPLIER_RIGHTS_ATTESTER'
    ));

COMMIT;
