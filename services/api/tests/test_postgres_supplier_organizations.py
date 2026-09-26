"""M49a1 supplier-organization ledger regressions."""
from __future__ import annotations
import copy, os, secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import pytest
from app.postgres_supplier_organizations import (SupplierOrganization, PostgresSupplierOrganizationAuthority, PostgresSupplierOrganizationError)
from app.postgres_tenant_identities import PostgresTenantIdentityAuthority, TenantIdentity

NOW=datetime(2026,9,26,12,tzinfo=UTC)
def opaque(prefix): return prefix+secrets.token_urlsafe(32)
def digest(): return "sha256:"+secrets.token_hex(32)

class DB:
    def __init__(self): self.identities={}; self.tenant_fences={}; self.orgs={}; self.fences={}; self.now=NOW
class Conn:
    def __init__(self,db):
        self.db=db; self.identities=copy.deepcopy(db.identities); self.tenant_fences=copy.deepcopy(db.tenant_fences); self.orgs=copy.deepcopy(db.orgs); self.fences=copy.deepcopy(db.fences); self.autocommit=True; self.info=SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))
    def cursor(self): return Cursor(self)
    def commit(self): self.db.identities,self.db.tenant_fences,self.db.orgs,self.db.fences=self.identities,self.tenant_fences,self.orgs,self.fences; self.info.transaction_status=SimpleNamespace(name="IDLE")
    def rollback(self): self.info.transaction_status=SimpleNamespace(name="IDLE")
    def close(self): pass
class Cursor:
    def __init__(self,c): self.connection=c; self._row=None; self.rowcount=-1
    def fetchone(self): return self._row
    def execute(self,sql,params=()):
        q=" ".join(sql.split()); self._row=None; self.rowcount=-1; c=self.connection
        if q in {"BEGIN","COMMIT","ROLLBACK"}: c.info.transaction_status=SimpleNamespace(name="INTRANS" if q=="BEGIN" else "IDLE"); return
        if q=="SHOW transaction_isolation": self._row=("read committed",); return
        if q=="SELECT date_trunc('second', clock_timestamp())": self._row=(c.db.now,); return
        if q.startswith("INSERT INTO anonflow_tenant_identities"):
            app,ref=params
            if app not in c.identities and ref not in c.identities.values(): c.identities[app]=ref; self._row=(app,); self.rowcount=1
            return
        if q.startswith("SELECT application_tenant, tenant_ref FROM anonflow_tenant_identities"):
            app=params[0]; self._row=(app,c.identities[app]) if app in c.identities else None; return
        if q.startswith("SELECT generation, state, event_ref, changed_at FROM anonflow_tenant_identity_fences"):
            values=[v for (app,_),v in c.tenant_fences.items() if app==params[0]]; self._row=max(values,key=lambda v:v[0]) if values else None; return
        if q.startswith("INSERT INTO anonflow_tenant_identity_fences"):
            app,changed=params; c.tenant_fences[(app,0)]=(0,"ACTIVE",None,changed); self.rowcount=1; return
        if q.startswith("INSERT INTO anonflow_supplier_organizations"):
            key=params[:2]
            if params[1] not in {k[1] for k in c.orgs}: c.orgs[key]=tuple(params); self._row=(params[1],); self.rowcount=1
            return
        if q.startswith("SELECT tenant_ref,supplier_org_ref,provisioning_case_ref"):
            self._row=c.orgs.get(tuple(params)); return
        if q.startswith("SELECT generation,state,event_ref,changed_at FROM anonflow_supplier_organization_fences"):
            values=[v for (tenant,ref,_),v in c.fences.items() if (tenant,ref)==tuple(params)]; self._row=max(values,key=lambda v:v[0]) if values else None; return
        if q.startswith("INSERT INTO anonflow_supplier_organization_fences"):
            if len(params)==3: tenant,ref,changed=params; v=(0,"ACTIVE",None,changed)
            else: tenant,ref,generation,state,event,changed=params; v=(generation,state,event,changed)
            c.fences[(tenant,ref,v[0])]=v; self.rowcount=1; return
        raise AssertionError(q)

def setup():
    db=DB(); factory=lambda:Conn(db); tenant=PostgresTenantIdentityAuthority(factory); return db,tenant,PostgresSupplierOrganizationAuthority(factory,tenant)
def org(ref=None,**changes):
    values=dict(tenant_ref=opaque("tenantref:v1:"),supplier_org_ref=ref or opaque("supplierorgref:v1:"),provisioning_case_ref=opaque("supplierorgcase:v1:"),evidence_digest=digest(),expires_at=NOW+timedelta(minutes=2)); values.update(changes); return SupplierOrganization(**values)
def provision(tenant,ref,app="server-tenant"): tenant.create(TenantIdentity(app,ref))

def test_domain_separated_identity_exact_replay_and_no_self_provisioning():
    db,tenant,service=setup(); item=org(); provision(tenant,item.tenant_ref)
    first=service.create(item,application_tenant="server-tenant",expected_tenant_generation=0)
    assert first.state=="ACTIVE" and service.create(item,application_tenant="server-tenant",expected_tenant_generation=0)==first
    assert item.identity_digest != item.evidence_digest
    with pytest.raises(PostgresSupplierOrganizationError): service.create(org(ref=item.supplier_org_ref,tenant_ref=item.tenant_ref),application_tenant="server-tenant",expected_tenant_generation=0)
    with pytest.raises(PostgresSupplierOrganizationError): service.create(org(),application_tenant="unprovisioned",expected_tenant_generation=0)

def test_active_lock_is_transactional_and_expiry_and_terminal_are_fail_closed():
    db,tenant,service=setup(); item=org(); provision(tenant,item.tenant_ref); service.create(item,application_tenant="server-tenant",expected_tenant_generation=0)
    kwargs=dict(application_tenant="server-tenant",tenant_ref=item.tenant_ref,supplier_org_ref=item.supplier_org_ref,expected_tenant_generation=0,expected_identity_digest=item.identity_digest,expected_generation=0)
    with pytest.raises(PostgresSupplierOrganizationError): service.lock_active(Conn(db).cursor(),**kwargs)
    db.now=item.expires_at
    with pytest.raises(PostgresSupplierOrganizationError): service.fence(**kwargs)
    assert service.terminal(application_tenant="server-tenant",tenant_ref=item.tenant_ref,supplier_org_ref=item.supplier_org_ref,expected_tenant_generation=0,expected_generation=0,state="EXPIRED",event_ref=opaque("supplierorgfence:v1:")).state=="EXPIRED"

@pytest.fixture
def live():
    dsn=os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg=pytest.importorskip("psycopg"); root=Path(__file__).parents[1]
    with psycopg.connect(dsn,autocommit=True) as c:
        c.execute((root/"migrations"/"011_m45_tenant_identity_foundation.sql").read_text()); c.execute((root/"migrations"/"019_m49a1_supplier_organizations.sql").read_text()); c.execute((root/"migrations"/"019_m49a1_supplier_organizations.sql").read_text())
    factory=lambda:psycopg.connect(dsn,autocommit=True); tenant=PostgresTenantIdentityAuthority(factory); return dsn,psycopg,tenant,PostgresSupplierOrganizationAuthority(factory,tenant)

def test_live_postgres_raw_sql_state_machine_immutability_and_reapply(live):
    dsn,psycopg,tenant,service=live
    app="supplier-live-"+secrets.token_hex(8)
    item=org(expires_at=datetime.now(UTC).replace(microsecond=0)+timedelta(minutes=2))
    provision(tenant,item.tenant_ref,app); service.create(item,application_tenant=app,expected_tenant_generation=0)
    with psycopg.connect(dsn,autocommit=True) as c:
        with pytest.raises(psycopg.errors.RaiseException): c.execute("UPDATE anonflow_supplier_organizations SET evidence_digest=%s WHERE supplier_org_ref=%s",(digest(),item.supplier_org_ref))
        with pytest.raises(psycopg.errors.RaiseException): c.execute("INSERT INTO anonflow_supplier_organization_fences (tenant_ref,supplier_org_ref,generation,state,event_ref) VALUES (%s,%s,2,'REVOKED',%s)",(item.tenant_ref,item.supplier_org_ref,opaque("supplierorgfence:v1:")))
    terminal=service.terminal(application_tenant=app,tenant_ref=item.tenant_ref,supplier_org_ref=item.supplier_org_ref,expected_tenant_generation=0,expected_generation=0,state="REVOKED",event_ref=opaque("supplierorgfence:v1:")); assert terminal.state=="REVOKED"
    with psycopg.connect(dsn,autocommit=True) as c:
        with pytest.raises(psycopg.errors.RaiseException): c.execute("DELETE FROM anonflow_supplier_organization_fences WHERE supplier_org_ref=%s",(item.supplier_org_ref,))
