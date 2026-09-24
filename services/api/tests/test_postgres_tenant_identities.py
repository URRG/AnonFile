"""M45a3 tenant-identity fence regressions."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import time
import pytest

from app.postgres_tenant_identities import (PostgresTenantIdentityAuthority,
                                            PostgresTenantIdentityError, TenantIdentity)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def opaque(prefix):
    return prefix + secrets.token_urlsafe(32)


TENANT, OTHER = opaque("tenantref:v1:"), opaque("tenantref:v1:")

class Database:
    def __init__(self):
        self.identities = {}
        self.fences = {}
        self.now = NOW
class Connection:
    def __init__(self, database):
        self.database = database
        self.identities = copy.deepcopy(database.identities)
        self.fences = copy.deepcopy(database.fences)
        self.autocommit = True
        self.closed = False

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.database.identities, self.database.fences = self.identities, self.fences

    def rollback(self):
        pass

    def close(self):
        self.closed = True
class Cursor:
    def __init__(self, connection): self.connection=connection; self._row=None; self.rowcount=-1; self.isolation="read committed"
    def fetchone(self): return self._row
    def execute(self, sql, params=()):
        q=" ".join(sql.split()); self._row=None; self.rowcount=-1
        if q in {"BEGIN","COMMIT","ROLLBACK"}: return
        if q=="SHOW transaction_isolation": self._row=(self.isolation,); return
        if q=="SELECT date_trunc('second', clock_timestamp())": self._row=(self.connection.database.now,); return
        if q.startswith("INSERT INTO anonflow_tenant_identities"):
            app,tenant=params
            if app not in self.connection.identities and tenant not in self.connection.identities.values(): self.connection.identities[app]=tenant; self._row=(app,); self.rowcount=1
            else: self.rowcount=0
            return
        if q.startswith("SELECT application_tenant, tenant_ref FROM anonflow_tenant_identities"):
            app=params[0]; tenant=self.connection.identities.get(app); self._row=None if tenant is None else (app,tenant); return
        if q.startswith("SELECT generation, state, event_ref, changed_at"):
            app=params[0]; rows=[v for (name,_),v in self.connection.fences.items() if name==app]; self._row=max(rows,key=lambda x:x[0]) if rows else None; return
        if q.startswith("INSERT INTO anonflow_tenant_identity_fences"):
            if len(params)==2: app,changed=params; generation,state,event=0,"ACTIVE",None
            else: app,generation,state,event,changed=params
            key=(app,generation)
            if key not in self.connection.fences: self.connection.fences[key]=(generation,state,event,changed); self.rowcount=1
            return
        raise AssertionError(q)
def adapter(db):
    opened=[]
    def connect(): value=Connection(db); opened.append(value); return value
    return PostgresTenantIdentityAuthority(connect),opened
def identity(app="tenant-a", tenant=TENANT): return TenantIdentity(app,tenant)

def test_exact_replay_mapping_is_one_to_one_and_tenant_scoped():
    db=Database(); authority,opened=adapter(db); item=identity()
    assert authority.create(item).generation==0
    assert authority.create(item).state=="ACTIVE"
    assert authority.fence(application_tenant="tenant-a",tenant_ref=TENANT,expected_generation=0).identity==item
    with pytest.raises(PostgresTenantIdentityError): authority.create(identity(tenant=OTHER))
    with pytest.raises(PostgresTenantIdentityError): authority.create(identity("tenant-b"))
    with pytest.raises(PostgresTenantIdentityError): authority.fence(application_tenant="tenant-b",tenant_ref=TENANT,expected_generation=0)
    assert all(x.closed for x in opened)

def test_terminal_fence_is_monotonic_and_read_committed_only():
    db=Database(); authority,_=adapter(db); item=identity(); authority.create(item); event=opaque("tenantfence:v1:")
    assert authority.terminal(application_tenant="tenant-a",tenant_ref=TENANT,expected_generation=0,state="DISABLED",event_ref=event).generation==1
    assert authority.terminal(application_tenant="tenant-a",tenant_ref=TENANT,expected_generation=0,state="DISABLED",event_ref=event).state=="DISABLED"
    with pytest.raises(PostgresTenantIdentityError): authority.fence(application_tenant="tenant-a",tenant_ref=TENANT,expected_generation=0)
    cursor=Connection(db).cursor(); cursor.isolation="repeatable read"
    with pytest.raises(PostgresTenantIdentityError): authority.lock_active(cursor,application_tenant="tenant-a",tenant_ref=TENANT,expected_generation=0)

@pytest.fixture
def postgres_authority():
    dsn=os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg=pytest.importorskip("psycopg")
    migration=Path(__file__).parents[1]/"migrations"/"011_m45_tenant_identity_foundation.sql"
    with psycopg.connect(dsn,autocommit=True) as connection: connection.execute(migration.read_text(encoding="utf-8"))
    return psycopg,dsn

def test_postgres_cross_tenant_and_terminal_fence(postgres_authority):
    psycopg, dsn = postgres_authority
    authority = PostgresTenantIdentityAuthority(lambda: psycopg.connect(dsn, autocommit=True))
    item = identity(app="tenant-live-" + secrets.token_hex(8), tenant=opaque("tenantref:v1:"))
    authority.create(item)
    with pytest.raises(PostgresTenantIdentityError): authority.create(identity("tenant-b"))
    with pytest.raises(PostgresTenantIdentityError): authority.fence(application_tenant="tenant-a",tenant_ref=OTHER,expected_generation=0)
    authority.terminal(application_tenant=item.application_tenant, tenant_ref=item.tenant_ref,
                       expected_generation=0, state="QUARANTINED", event_ref=opaque("tenantfence:v1:"))
    with pytest.raises(PostgresTenantIdentityError):
        authority.fence(application_tenant=item.application_tenant, tenant_ref=item.tenant_ref,
                        expected_generation=0)


def test_postgres_terminal_fence_blocks_competing_reader_then_rejects_stale_active(postgres_authority):
    psycopg, dsn = postgres_authority
    authority = PostgresTenantIdentityAuthority(lambda: psycopg.connect(dsn, autocommit=True))
    item = identity(app="tenant-race-" + secrets.token_hex(8), tenant=opaque("tenantref:v1:"))
    authority.create(item)
    event = opaque("tenantfence:v1:")
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor()
        cursor.execute("BEGIN")
        cursor.execute("SELECT application_tenant FROM anonflow_tenant_identities "
                       "WHERE application_tenant=%s FOR UPDATE", (item.application_tenant,))
        cursor.execute("INSERT INTO anonflow_tenant_identity_fences "
                       "(application_tenant,generation,state,event_ref) VALUES (%s,1,'QUARANTINED',%s)",
                       (item.application_tenant, event))
        pids: Queue[int] = Queue()

        def connect():
            connection = psycopg.connect(dsn, autocommit=True)
            with connection.cursor() as worker:
                worker.execute("SELECT pg_backend_pid()")
                pids.put(worker.fetchone()[0])
            return connection

        racing = PostgresTenantIdentityAuthority(connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(racing.fence, application_tenant=item.application_tenant,
                                     tenant_ref=item.tenant_ref, expected_generation=0)
            try:
                pid = pids.get(timeout=3)
            except Empty:
                cursor.execute("ROLLBACK")
                pytest.fail("tenant fence reader did not connect")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (pid,))
                if cursor.fetchone() == ("Lock",):
                    break
                time.sleep(0.02)
            else:
                cursor.execute("ROLLBACK")
                pytest.fail("tenant fence reader did not block on the identity row")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresTenantIdentityError):
                future.result(timeout=5)
