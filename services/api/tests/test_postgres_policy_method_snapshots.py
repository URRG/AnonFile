"""M48b2 policy/method snapshot regressions."""
from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
import time
from types import SimpleNamespace

import pytest

from app.postgres_policy_method_snapshots import (PolicyMethodSnapshot,
    PolicyMethodSnapshotFence, PostgresPolicyMethodSnapshotAuthority,
    PostgresPolicyMethodSnapshotError)
from app.postgres_tenant_identities import PostgresTenantIdentityAuthority, TenantIdentity

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
def opaque(prefix): return prefix + secrets.token_urlsafe(32)
def digest(): return "sha256:" + secrets.token_hex(32)
TENANT, OTHER = opaque("tenantref:v1:"), opaque("tenantref:v1:")

class Database:
    def __init__(self): self.identities, self.tenant_fences, self.snapshots, self.fences, self.now = {}, {}, {}, {}, NOW
class Connection:
    def __init__(self, db):
        self.db=db; self.identities=copy.deepcopy(db.identities); self.tenant_fences=copy.deepcopy(db.tenant_fences); self.snapshots=copy.deepcopy(db.snapshots); self.fences=copy.deepcopy(db.fences)
        self.autocommit=True; self.closed=False; self.info=SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))
    def cursor(self): return Cursor(self)
    def commit(self):
        self.db.identities,self.db.tenant_fences,self.db.snapshots,self.db.fences=self.identities,self.tenant_fences,self.snapshots,self.fences; self.info.transaction_status=SimpleNamespace(name="IDLE")
    def rollback(self): self.info.transaction_status=SimpleNamespace(name="IDLE")
    def close(self): self.closed=True
class Cursor:
    def __init__(self, c): self.connection=c; self._row=None; self.rowcount=-1
    def fetchone(self): return self._row
    def execute(self, sql, params=()):
        q=" ".join(sql.split()); self._row=None; self.rowcount=-1
        if q in {"BEGIN", "COMMIT", "ROLLBACK"}: self.connection.info.transaction_status=SimpleNamespace(name="INTRANS" if q=="BEGIN" else "IDLE"); return
        if q=="SHOW transaction_isolation": self._row=("read committed",); return
        if q=="SELECT date_trunc('second', clock_timestamp())": self._row=(self.connection.db.now,); return
        if q.startswith("INSERT INTO anonflow_tenant_identities"):
            app, tenant=params
            if app not in self.connection.identities and tenant not in self.connection.identities.values(): self.connection.identities[app]=tenant; self._row=(app,); self.rowcount=1
            return
        if q.startswith("SELECT application_tenant, tenant_ref FROM anonflow_tenant_identities"):
            app=params[0]; value=self.connection.identities.get(app); self._row=None if value is None else (app,value); return
        if q.startswith("SELECT generation, state, event_ref, changed_at FROM anonflow_tenant_identity_fences"):
            rows=[v for (app,_),v in self.connection.tenant_fences.items() if app==params[0]]; self._row=max(rows,key=lambda x:x[0]) if rows else None; return
        if q.startswith("INSERT INTO anonflow_tenant_identity_fences"):
            if len(params)==2: app,changed=params; value=(0,"ACTIVE",None,changed)
            else: app,generation,state,event,changed=params; value=(generation,state,event,changed)
            self.connection.tenant_fences[(app,value[0])]=value; self.rowcount=1; return
        if q.startswith("INSERT INTO anonflow_policy_method_snapshots"):
            key=params[0],params[1]
            if params[1] not in {x[1] for x in self.connection.snapshots.values()}: self.connection.snapshots[key]=tuple(params); self._row=(params[1],); self.rowcount=1
            return
        if q.startswith("SELECT tenant_ref,policy_method_ref,policy_digest"):
            self._row=self.connection.snapshots.get(tuple(params)); return
        if q.startswith("SELECT generation,state,event_ref,changed_at FROM anonflow_policy_method_snapshot_fences"):
            values=[v for (tenant,ref,_),v in self.connection.fences.items() if (tenant,ref)==tuple(params)]; self._row=max(values,key=lambda x:x[0]) if values else None; return
        if q.startswith("INSERT INTO anonflow_policy_method_snapshot_fences"):
            if len(params)==3: tenant,ref,changed=params; value=(0,"ACTIVE",None,changed)
            else: tenant,ref,generation,state,event,changed=params; value=(generation,state,event,changed)
            self.connection.fences[(tenant,ref,value[0])]=value; self.rowcount=1; return
        raise AssertionError(q)

def services(db):
    factory=lambda: Connection(db)
    tenant=PostgresTenantIdentityAuthority(factory)
    return tenant, PostgresPolicyMethodSnapshotAuthority(factory, tenant)
def snapshot(**changes):
    values=dict(tenant_ref=TENANT, policy_method_ref=opaque("policymethodref:v1:"), policy_digest=digest(), method_id="deidentify", method_version="2026.09", method_config_digest=digest(), taxonomy_mapping_digest=digest(), output_schema_digest=digest(), expires_at=NOW+timedelta(minutes=5)); values.update(changes); return PolicyMethodSnapshot(**values)
def provision(tenant, app="server-tenant"):
    tenant.create(TenantIdentity(app,TENANT)); return app

def test_snapshot_is_domain_separated_exact_replay_and_globally_collision_safe():
    db=Database(); tenant, service=services(db); app=provision(tenant); item=snapshot()
    first=service.create(item, application_tenant=app, expected_tenant_generation=0)
    assert first.state=="ACTIVE" and service.create(item, application_tenant=app, expected_tenant_generation=0)==first
    assert item.snapshot_digest != item.policy_digest
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.create(snapshot(policy_method_ref=item.policy_method_ref), application_tenant=app, expected_tenant_generation=0)
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.create(snapshot(tenant_ref=OTHER, policy_method_ref=item.policy_method_ref), application_tenant=app, expected_tenant_generation=0)
    # The authority rejects an unprovisioned/orphan tenant before the snapshot
    # insert; migration 017 also has a tenant_ref FK against M45a3 for SQL paths.
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.create(snapshot(tenant_ref=OTHER), application_tenant="missing-tenant", expected_tenant_generation=0)

def test_active_lock_requires_active_transaction_tenant_and_unexpired_db_clock():
    db=Database(); tenant, service=services(db); app=provision(tenant); item=snapshot(); service.create(item,application_tenant=app,expected_tenant_generation=0)
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.lock_active(Connection(db).cursor(),application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_snapshot_digest=item.snapshot_digest,expected_generation=0)
    db.now=item.expires_at
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.fence(application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_snapshot_digest=item.snapshot_digest,expected_generation=0)
    assert service.terminal(application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_generation=0,state="EXPIRED",event_ref=opaque("policymethodfence:v1:")).state=="EXPIRED"

def test_terminal_is_append_only_and_idempotent():
    db=Database(); tenant, service=services(db); app=provision(tenant); item=snapshot(); service.create(item,application_tenant=app,expected_tenant_generation=0); event=opaque("policymethodfence:v1:")
    value=service.terminal(application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_generation=0,state="REVOKED",event_ref=event)
    assert service.terminal(application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_generation=0,state="REVOKED",event_ref=event)==value
    with pytest.raises(PostgresPolicyMethodSnapshotError): service.terminal(application_tenant=app,tenant_ref=TENANT,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_generation=0,state="QUARANTINED",event_ref=opaque("policymethodfence:v1:"))
    with pytest.raises(PostgresPolicyMethodSnapshotError):
        PolicyMethodSnapshotFence(item, 2, "REVOKED",
                                  opaque("policymethodfence:v1:"), NOW)

@pytest.fixture
def live():
    dsn=os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg=pytest.importorskip("psycopg")
    root=Path(__file__).parents[1]
    with psycopg.connect(dsn,autocommit=True) as c:
        c.execute((root/"migrations"/"011_m45_tenant_identity_foundation.sql").read_text())
        # Deployment runners may retry an interrupted migration.
        c.execute((root/"migrations"/"017_m48b2_policy_method_snapshot.sql").read_text())
        c.execute((root/"migrations"/"017_m48b2_policy_method_snapshot.sql").read_text())
    factory=lambda: psycopg.connect(dsn,autocommit=True)
    tenant=PostgresTenantIdentityAuthority(factory)
    return dsn, psycopg, tenant, PostgresPolicyMethodSnapshotAuthority(factory,tenant)

def test_live_postgres_constraints_replay_terminal_and_immutability(live):
    dsn, psycopg, tenant, service = live
    app="policy-live-"+secrets.token_hex(8)
    tenant_ref=opaque("tenantref:v1:")
    tenant.create(TenantIdentity(app,tenant_ref))
    item=snapshot(tenant_ref=tenant_ref,expires_at=datetime.now(UTC).replace(microsecond=0)+timedelta(minutes=2))
    assert service.create(item,application_tenant=app,expected_tenant_generation=0)==service.create(item,application_tenant=app,expected_tenant_generation=0)
    raw_ref = opaque("policymethodref:v1:")
    with psycopg.connect(dsn, autocommit=False) as connection:
        connection.execute("INSERT INTO anonflow_policy_method_snapshots (tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) VALUES (%s,%s,%s,'x','v',%s,%s,%s,date_trunc('second',clock_timestamp())+interval '1 minute')",(tenant_ref,raw_ref,digest(),digest(),digest(),digest()))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.commit()
    with pytest.raises(PostgresPolicyMethodSnapshotError):
        service.create(snapshot(tenant_ref=tenant_ref,policy_method_ref=item.policy_method_ref),application_tenant=app,expected_tenant_generation=0)
    with pytest.raises(PostgresPolicyMethodSnapshotError):
        service.fence(application_tenant=app,tenant_ref=OTHER,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_snapshot_digest=item.snapshot_digest,expected_generation=0)
    with psycopg.connect(dsn,autocommit=True) as connection:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute("INSERT INTO anonflow_policy_method_snapshots (tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) VALUES (%s,%s,%s,'x','v',%s,%s,%s,date_trunc('second',clock_timestamp())+interval '1 minute')",(OTHER,opaque("policymethodref:v1:"),digest(),digest(),digest(),digest()))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_policy_method_snapshots SET method_id='changed' WHERE tenant_ref=%s AND policy_method_ref=%s",(tenant_ref,item.policy_method_ref))
    terminal=service.terminal(application_tenant=app,tenant_ref=tenant_ref,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_generation=0,state="REVOKED",event_ref=opaque("policymethodfence:v1:"))
    assert terminal.state=="REVOKED"
    with pytest.raises(PostgresPolicyMethodSnapshotError):
        service.fence(application_tenant=app,tenant_ref=tenant_ref,policy_method_ref=item.policy_method_ref,expected_tenant_generation=0,expected_snapshot_digest=item.snapshot_digest,expected_generation=0)
    with psycopg.connect(dsn,autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_policy_method_snapshot_fences SET state='ACTIVE' WHERE tenant_ref=%s AND policy_method_ref=%s",(tenant_ref,item.policy_method_ref))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("DELETE FROM anonflow_policy_method_snapshot_fences WHERE tenant_ref=%s AND policy_method_ref=%s",(tenant_ref,item.policy_method_ref))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_policy_method_snapshot_fences (tenant_ref,policy_method_ref,generation,state,event_ref) VALUES (%s,%s,2,'REVOKED',%s)",(tenant_ref,item.policy_method_ref,opaque("policymethodfence:v1:")))
    raw_state_ref = opaque("policymethodref:v1:")
    with psycopg.connect(dsn, autocommit=False) as connection:
        connection.execute("INSERT INTO anonflow_policy_method_snapshots (tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) VALUES (%s,%s,%s,'x','v',%s,%s,%s,date_trunc('second',clock_timestamp())+interval '1 minute')",(tenant_ref,raw_state_ref,digest(),digest(),digest(),digest()))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_policy_method_snapshot_fences (tenant_ref,policy_method_ref,generation,state,event_ref) VALUES (%s,%s,1,'REVOKED',%s)",(tenant_ref,raw_state_ref,opaque("policymethodfence:v1:")))
    raw_expiry_ref = opaque("policymethodref:v1:")
    with psycopg.connect(dsn, autocommit=False) as connection:
        connection.execute("INSERT INTO anonflow_policy_method_snapshots (tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) VALUES (%s,%s,%s,'x','v',%s,%s,%s,date_trunc('second',clock_timestamp())+interval '1 minute')",(tenant_ref,raw_expiry_ref,digest(),digest(),digest(),digest()))
        connection.execute("INSERT INTO anonflow_policy_method_snapshot_fences (tenant_ref,policy_method_ref,generation,state,event_ref) VALUES (%s,%s,0,'ACTIVE',NULL)",(tenant_ref,raw_expiry_ref))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_policy_method_snapshot_fences (tenant_ref,policy_method_ref,generation,state,event_ref) VALUES (%s,%s,1,'EXPIRED',%s)",(tenant_ref,raw_expiry_ref,opaque("policymethodfence:v1:")))
    raw_timestamp_ref = opaque("policymethodref:v1:")
    with psycopg.connect(dsn, autocommit=False) as connection:
        connection.execute("INSERT INTO anonflow_policy_method_snapshots (tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) VALUES (%s,%s,%s,'x','v',%s,%s,%s,date_trunc('second',clock_timestamp())+interval '1 minute')",(tenant_ref,raw_timestamp_ref,digest(),digest(),digest(),digest()))
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute("INSERT INTO anonflow_policy_method_snapshot_fences (tenant_ref,policy_method_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,0,'ACTIVE',NULL,date_trunc('second',clock_timestamp())+interval '1 microsecond')",(tenant_ref,raw_timestamp_ref))


def test_live_postgres_expiry_boundary_is_fail_closed(live):
    dsn, psycopg, tenant, service = live
    app = "policy-expiry-" + secrets.token_hex(8)
    tenant_ref = opaque("tenantref:v1:")
    tenant.create(TenantIdentity(app, tenant_ref))
    item = snapshot(tenant_ref=tenant_ref,
                    expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=5))
    service.create(item, application_tenant=app, expected_tenant_generation=0)
    deadline = time.monotonic() + 12
    while True:
        with psycopg.connect(dsn, autocommit=True) as connection:
            database_now = connection.execute(
                "SELECT date_trunc('second', clock_timestamp())").fetchone()[0]
        if database_now >= item.expires_at:
            break
        if time.monotonic() >= deadline:
            pytest.fail("PostgreSQL clock did not cross policy snapshot expiry")
        time.sleep(0.05)
    with pytest.raises(PostgresPolicyMethodSnapshotError):
        service.fence(application_tenant=app, tenant_ref=tenant_ref,
                      policy_method_ref=item.policy_method_ref,
                      expected_tenant_generation=0,
                      expected_snapshot_digest=item.snapshot_digest,
                      expected_generation=0)
    assert service.terminal(application_tenant=app, tenant_ref=tenant_ref,
                            policy_method_ref=item.policy_method_ref,
                            expected_tenant_generation=0, expected_generation=0,
                            state="EXPIRED",
                            event_ref=opaque("policymethodfence:v1:")).state == "EXPIRED"
