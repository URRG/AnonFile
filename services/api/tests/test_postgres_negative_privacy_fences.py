"""M47a1 regressions for the PostgreSQL denial-only privacy fence ledger."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import time
from types import SimpleNamespace

import pytest

from app.postgres_negative_privacy_fences import (
    NegativePrivacyFence,
    PostgresNegativePrivacyFenceAuthority,
    PostgresNegativePrivacyFenceError,
    PrivacySubject,
)

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


TENANT = opaque("tenantref:v1:")
OTHER = opaque("tenantref:v1:")


class Database:
    def __init__(self) -> None:
        self.subjects = set()
        self.fences = {}


class Connection:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.subjects = copy.deepcopy(database.subjects)
        self.fences = copy.deepcopy(database.fences)
        self.autocommit = True
        self.closed = self.rolled_back = False
        self.info = SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))

    def cursor(self) -> "Cursor":
        return Cursor(self)

    def commit(self) -> None:
        self.database.subjects, self.database.fences = self.subjects, self.fences
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def rollback(self) -> None:
        self.rolled_back = True
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def close(self) -> None:
        self.closed = True


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection, self._row, self.rowcount = connection, None, -1
        self.isolation = "read committed"

    def fetchone(self):
        return self._row

    def execute(self, sql: str, params=()) -> None:
        query = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if query in {"BEGIN", "COMMIT", "ROLLBACK"}:
            self.connection.info.transaction_status = SimpleNamespace(
                name="INTRANS" if query == "BEGIN" else "IDLE")
            return
        if query == "SHOW transaction_isolation":
            self._row = (self.isolation,)
            return
        if query.startswith("INSERT INTO anonflow_privacy_subjects"):
            key = tuple(params)
            if key not in self.connection.subjects:
                self.connection.subjects.add(key)
                self._row, self.rowcount = (key[1],), 1
            return
        if query.startswith("SELECT tenant_ref,subject_ref FROM anonflow_privacy_subjects"):
            self._row = tuple(params) if tuple(params) in self.connection.subjects else None
            return
        if query.startswith("SELECT generation,state,event_ref,changed_at"):
            tenant, subject = params
            options = [value for (item_tenant, item_subject, _), value in self.connection.fences.items()
                       if (item_tenant, item_subject) == (tenant, subject)]
            self._row = max(options, key=lambda item: item[0]) if options else None
            return
        if query.startswith("INSERT INTO anonflow_negative_privacy_fences"):
            if len(params) == 2:
                tenant, subject = params
                generation, state, event = 0, "NONE", None
            else:
                tenant, subject, generation, state, event = params
            key = tenant, subject, generation
            if key not in self.connection.fences:
                self.connection.fences[key] = (generation, state, event, NOW)
                self._row, self.rowcount = (NOW,), 1
            return
        raise AssertionError(query)


def adapter(database: Database):
    opened = []

    def connect():
        result = Connection(database)
        opened.append(result)
        return result

    return PostgresNegativePrivacyFenceAuthority(connect), opened


def subject(*, tenant=TENANT, subject_ref=None) -> PrivacySubject:
    return PrivacySubject(tenant, subject_ref or opaque("privacysubjectref:v1:"))


def test_baseline_is_denial_ledger_history_not_positive_permission():
    database = Database()
    authority, opened = adapter(database)
    item = subject()
    baseline = authority.create(item)
    assert baseline == authority.create(item)
    assert baseline == NegativePrivacyFence(item, 0, "NONE", None, NOW)
    assert authority.fence_none(tenant_ref=TENANT, subject_ref=item.subject_ref,
                                expected_generation=0) == baseline
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.fence_none(tenant_ref=OTHER, subject_ref=item.subject_ref,
                             expected_generation=0)
    assert all(connection.closed for connection in opened)


def test_terminal_state_is_monotonic_and_exactly_idempotent():
    database = Database()
    authority, _ = adapter(database)
    item = subject()
    authority.create(item)
    event = opaque("privacyfence:v1:")
    result = authority.terminal(tenant_ref=TENANT, subject_ref=item.subject_ref,
                                expected_generation=0, state="WITHDRAWN", event_ref=event)
    assert result.generation == 1
    assert authority.terminal(tenant_ref=TENANT, subject_ref=item.subject_ref,
                              expected_generation=0, state="WITHDRAWN", event_ref=event) == result
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.fence_none(tenant_ref=TENANT, subject_ref=item.subject_ref,
                             expected_generation=0)
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.terminal(tenant_ref=TENANT, subject_ref=item.subject_ref,
                           expected_generation=0, state="OPT_OUT",
                           event_ref=opaque("privacyfence:v1:"))


def test_lock_none_requires_active_read_committed_caller_transaction():
    database = Database()
    authority, _ = adapter(database)
    item = subject()
    authority.create(item)
    connection = Connection(database)
    cursor = connection.cursor()
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.lock_none(cursor, tenant_ref=TENANT, subject_ref=item.subject_ref,
                            expected_generation=0)
    cursor.execute("BEGIN")
    assert authority.lock_none(cursor, tenant_ref=TENANT, subject_ref=item.subject_ref,
                               expected_generation=0).state == "NONE"
    cursor.isolation = "repeatable read"
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.lock_none(cursor, tenant_ref=TENANT, subject_ref=item.subject_ref,
                            expected_generation=0)


@pytest.mark.parametrize(
    "kwargs",
    ({"tenant": "tenantref:v1:short"}, {"subject_ref": "plain-subject"}),
)
def test_opaque_subject_identity_validation_is_strict(kwargs):
    with pytest.raises(PostgresNegativePrivacyFenceError):
        subject(**kwargs)


def test_terminal_input_validation_precedes_database_access():
    authority, _ = adapter(Database())
    item = subject()
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.terminal(tenant_ref=TENANT, subject_ref=item.subject_ref,
                           expected_generation=True, state="OPT_OUT",
                           event_ref=opaque("privacyfence:v1:"))
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.terminal(tenant_ref=TENANT, subject_ref=item.subject_ref,
                           expected_generation=0, state="NONE",
                           event_ref=opaque("privacyfence:v1:"))


@pytest.fixture
def postgres_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "013_m47a1_negative_privacy_fences.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))
        connection.execute(migration.read_text(encoding="utf-8"))
    return dsn, psycopg, PostgresNegativePrivacyFenceAuthority(
        lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_wrong_tenant_replay_and_terminal_race_fail_closed(postgres_authority):
    dsn, psycopg, authority = postgres_authority
    item = subject()
    baseline = authority.create(item)
    assert baseline.generation == 0
    assert baseline.changed_at.microsecond == 0
    assert authority.create(item).generation == 0
    with pytest.raises(PostgresNegativePrivacyFenceError):
        authority.fence_none(tenant_ref=OTHER, subject_ref=item.subject_ref,
                             expected_generation=0)
    # The opaque reference is explicitly tenant-scoped: the same token can be
    # an unrelated subject in a different tenant and never grants cross-tenant
    # visibility into this subject's fence history.
    assert authority.create(subject(tenant=OTHER, subject_ref=item.subject_ref)).generation == 0

    # Writer A holds the stable subject lock while appending a negative state.
    # Reader B must block, then see that committed terminal state on its fresh
    # READ COMMITTED post-lock statement and reject rather than return NONE.
    event = opaque("privacyfence:v1:")
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor()
        cursor.execute("BEGIN")
        cursor.execute("SELECT subject_ref FROM anonflow_privacy_subjects "
                       "WHERE tenant_ref=%s AND subject_ref=%s FOR UPDATE",
                       (item.tenant_ref, item.subject_ref))
        cursor.execute("INSERT INTO anonflow_negative_privacy_fences "
                       "(tenant_ref,subject_ref,generation,state,event_ref) VALUES (%s,%s,1,'OPT_OUT',%s)",
                       (item.tenant_ref, item.subject_ref, event))
        pids: Queue[int] = Queue()

        def connect():
            connection = psycopg.connect(dsn, autocommit=True)
            with connection.cursor() as worker:
                worker.execute("SELECT pg_backend_pid()")
                pids.put(worker.fetchone()[0])
            return connection

        racing = PostgresNegativePrivacyFenceAuthority(connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(racing.fence_none, tenant_ref=item.tenant_ref,
                                     subject_ref=item.subject_ref, expected_generation=0)
            try:
                pid = pids.get(timeout=3)
            except Empty:
                cursor.execute("ROLLBACK")
                pytest.fail("privacy fence reader did not connect")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (pid,))
                if cursor.fetchone() == ("Lock",):
                    break
                time.sleep(0.02)
            else:
                cursor.execute("ROLLBACK")
                pytest.fail("privacy fence reader did not block on the subject row")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresNegativePrivacyFenceError):
                future.result(timeout=5)

    terminal_subject = subject()
    terminal_baseline = authority.create(terminal_subject)
    terminal = authority.terminal(
        tenant_ref=terminal_subject.tenant_ref,
        subject_ref=terminal_subject.subject_ref,
        expected_generation=terminal_baseline.generation,
        state="QUARANTINED",
        event_ref=opaque("privacyfence:v1:"),
    )
    assert terminal.changed_at.microsecond == 0
