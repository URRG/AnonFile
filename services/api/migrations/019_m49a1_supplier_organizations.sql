-- M49a1: inert supplier-organization identity metadata.  No onboarding,
-- signing, processing, release, legal-validity, or HTTP authority is created.
BEGIN;
CREATE TABLE IF NOT EXISTS anonflow_supplier_organizations (
 tenant_ref TEXT NOT NULL CHECK (tenant_ref ~ '^tenantref:v1:[A-Za-z0-9_-]{43}$'),
 supplier_org_ref TEXT NOT NULL UNIQUE CHECK (supplier_org_ref ~ '^supplierorgref:v1:[A-Za-z0-9_-]{43}$'),
 provisioning_case_ref TEXT NOT NULL CHECK (provisioning_case_ref ~ '^supplierorgcase:v1:[A-Za-z0-9_-]{43}$'),
 evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (tenant_ref,supplier_org_ref),
 FOREIGN KEY (tenant_ref) REFERENCES anonflow_tenant_identities(tenant_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK (expires_at = date_trunc('second', expires_at))
);
CREATE TABLE IF NOT EXISTS anonflow_supplier_organization_fences (
 tenant_ref TEXT NOT NULL, supplier_org_ref TEXT NOT NULL, generation BIGINT NOT NULL CHECK (generation >= 0),
 state TEXT NOT NULL CHECK (state IN ('ACTIVE','QUARANTINED','REVOKED','EXPIRED')),
 event_ref TEXT UNIQUE CHECK (event_ref IS NULL OR event_ref ~ '^supplierorgfence:v1:[A-Za-z0-9_-]{43}$'),
 changed_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', clock_timestamp()),
 PRIMARY KEY (tenant_ref,supplier_org_ref,generation),
 FOREIGN KEY (tenant_ref,supplier_org_ref) REFERENCES anonflow_supplier_organizations(tenant_ref,supplier_org_ref) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK ((generation=0 AND state='ACTIVE' AND event_ref IS NULL) OR (generation=1 AND state IN ('QUARANTINED','REVOKED','EXPIRED') AND event_ref IS NOT NULL)),
 CHECK (changed_at = date_trunc('second', changed_at))
);
-- Raw SQL cannot create an already-expired ACTIVE identity and then supply its
-- baseline fence.  ``clock_timestamp`` is deliberately used rather than a
-- transaction-start timestamp so a long-running transaction cannot bypass it.
CREATE OR REPLACE FUNCTION anonflow_validate_supplier_organization_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.expires_at <= date_trunc('second',clock_timestamp()) THEN
   RAISE EXCEPTION 'supplier organization is already expired';
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION anonflow_validate_supplier_organization_fence_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prior_generation BIGINT; prior_state TEXT; parent_expiry TIMESTAMPTZ;
BEGIN
 SELECT expires_at INTO parent_expiry FROM anonflow_supplier_organizations WHERE tenant_ref=NEW.tenant_ref AND supplier_org_ref=NEW.supplier_org_ref FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'supplier organization does not exist'; END IF;
 SELECT generation,state INTO prior_generation,prior_state FROM anonflow_supplier_organization_fences WHERE tenant_ref=NEW.tenant_ref AND supplier_org_ref=NEW.supplier_org_ref ORDER BY generation DESC LIMIT 1;
 IF prior_generation IS NULL AND NEW.generation=0 AND NEW.state='ACTIVE' AND NEW.event_ref IS NULL THEN RETURN NEW; END IF;
 IF prior_generation=0 AND prior_state='ACTIVE' AND NEW.generation=1 AND NEW.state IN ('QUARANTINED','REVOKED','EXPIRED') AND NEW.event_ref IS NOT NULL THEN
   IF NEW.state='EXPIRED' AND date_trunc('second',clock_timestamp()) < parent_expiry THEN RAISE EXCEPTION 'supplier organization has not expired'; END IF;
   RETURN NEW;
 END IF;
 RAISE EXCEPTION 'invalid supplier organization fence transition';
END; $$;
CREATE OR REPLACE FUNCTION anonflow_require_supplier_organization_baseline() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM anonflow_supplier_organization_fences WHERE tenant_ref=NEW.tenant_ref AND supplier_org_ref=NEW.supplier_org_ref AND generation=0 AND state='ACTIVE' AND event_ref IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'supplier organization requires an active baseline fence'; END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_supplier_organization_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'supplier organizations are immutable'; END; $$;
CREATE OR REPLACE FUNCTION anonflow_reject_supplier_organization_fence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'supplier organization fences are immutable'; END; $$;
DROP TRIGGER IF EXISTS anonflow_supplier_organizations_immutable ON anonflow_supplier_organizations;
CREATE TRIGGER anonflow_supplier_organizations_immutable BEFORE UPDATE OR DELETE ON anonflow_supplier_organizations FOR EACH ROW EXECUTE FUNCTION anonflow_reject_supplier_organization_mutation();
DROP TRIGGER IF EXISTS anonflow_supplier_organizations_expiry_gate ON anonflow_supplier_organizations;
CREATE TRIGGER anonflow_supplier_organizations_expiry_gate BEFORE INSERT ON anonflow_supplier_organizations FOR EACH ROW EXECUTE FUNCTION anonflow_validate_supplier_organization_insert();
DROP TRIGGER IF EXISTS anonflow_supplier_organization_fences_immutable ON anonflow_supplier_organization_fences;
CREATE TRIGGER anonflow_supplier_organization_fences_immutable BEFORE UPDATE OR DELETE ON anonflow_supplier_organization_fences FOR EACH ROW EXECUTE FUNCTION anonflow_reject_supplier_organization_fence_mutation();
DROP TRIGGER IF EXISTS anonflow_supplier_organization_fences_state_machine ON anonflow_supplier_organization_fences;
CREATE TRIGGER anonflow_supplier_organization_fences_state_machine BEFORE INSERT ON anonflow_supplier_organization_fences FOR EACH ROW EXECUTE FUNCTION anonflow_validate_supplier_organization_fence_insert();
DROP TRIGGER IF EXISTS anonflow_supplier_organizations_require_baseline ON anonflow_supplier_organizations;
CREATE CONSTRAINT TRIGGER anonflow_supplier_organizations_require_baseline AFTER INSERT ON anonflow_supplier_organizations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION anonflow_require_supplier_organization_baseline();
COMMIT;
