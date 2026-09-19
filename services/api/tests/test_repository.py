"""Local synthetic repository contracts, tampering and cross-instance transactions."""
import copy
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException

from app.durable_repository import DurableStore
from app.repository import DevelopmentStore

KEY = bytes(range(32))
TIME = "2026-09-20T00:00:00+00:00"


def source(identifier="d1", tenant="tenant-a"):
    return {"id": identifier, "tenant": tenant, "owner": "synthetic-actor", "name": "synthetic-name",
            "content": "SYNTHETIC-SECRET-FOR-CIPHERTEXT-CHECK", "records": None, "size_bytes": 100,
            "created_at": TIME, "intended_use": "synthetic", "original_source": "synthetic-original-value"}


def candidate(identifier="r1", dataset_id="d1", tenant="tenant-a"):
    card = {"release_id": identifier, "dataset_id": dataset_id, "eligibility": "REVIEW_REQUIRED",
            "revision": 1, "gates": ["EXPORT_DISABLED"], "generated_at": TIME}
    return {"id": identifier, "dataset_id": dataset_id, "tenant": tenant, "creator": "processor",
            "card": card, "review": None, "events": [{"revision": 1, "card": copy.deepcopy(card)}]}


def control(kind="rights_profile", identifier="control-1", tenant="tenant-a", *, key="safe-key-0001", digest="sha256:" + "a" * 64):
    return {"id": identifier, "kind": kind, "tenant": tenant, "created_at": TIME,
            "expires_at": time.time() + 1000, "size_bytes": 0,
            "payload": {"idempotency_key": key, "request_digest": digest,
                        "private_business_label": "buyer-sensitive-synthetic"}}


def run_dependencies(store, *, rights_expiry=None):
    store.add_dataset(source())
    rights = control("rights_profile", "rights-1")
    if rights_expiry is not None:
        rights["expires_at"] = rights_expiry
    rights["payload"] = {"digest": "r" * 64}
    policy = control("policy_snapshot", "policy-1")
    policy["payload"] = {"digest": "sha256:" + "p" * 64}
    store.add_control(rights, "operator")
    store.add_control(policy, "operator")
    run = control("processing_run", "run-1")
    run["payload"].update({"dataset_id": "d1", "rights_profile_id": "rights-1", "policy_snapshot_id": "policy-1",
                           "rights_digest": "r" * 64, "policy_digest": "sha256:" + "p" * 64})
    return run, rights, policy


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    result = DevelopmentStore() if request.param == "memory" else DurableStore(str(tmp_path / "source.db"), KEY)
    yield result
    result.close()


def fails(code, function, *args):
    with pytest.raises(HTTPException) as error:
        function(*args)
    assert error.value.status_code == code
    return error.value


def test_repository_detached_roundtrip_and_tenant_isolation(store):
    original = source()
    store.add_dataset(original)
    original["content"] = "changed"
    result = store.get_dataset("d1", "tenant-a")
    assert result["content"] == source()["content"]
    result["content"] = "changed-again"
    listed = store.list_datasets("tenant-a")
    assert len(listed) == 1 and listed[0]["content"] == source()["content"]
    listed[0]["content"] = "mutated-list"
    assert store.get_dataset("d1", "tenant-a")["content"] == source()["content"]
    assert store.list_datasets("tenant-b") == []
    fails(404, store.get_dataset, "d1", "tenant-b")
    store.add_release(candidate())
    output = store.get_release("r1", "tenant-a")
    output["card"]["eligibility"] = "APPROVED"
    assert store.get_release("r1", "tenant-a")["card"]["eligibility"] == "REVIEW_REQUIRED"
    fails(404, store.get_release, "r1", "tenant-b")
    fails(404, store.add_release, candidate("foreign", tenant="tenant-b"))


def test_atomic_review_preserves_previous_event(store):
    store.add_dataset(source())
    store.add_release(candidate())
    old = store.get_release("r1", "tenant-a")
    fails(403, store.reject_release, "r1", "tenant-a", "processor", TIME)
    fails(404, store.reject_release, "r1", "tenant-b", "reviewer", TIME)
    result = store.reject_release("r1", "tenant-a", "reviewer", TIME)
    assert result["card"]["eligibility"] == "BLOCKED"
    assert result["card"]["revision"] == 2
    assert result["events"][0]["card"] == old["card"]
    assert len(result["events"]) == 2
    fails(409, store.reject_release, "r1", "tenant-a", "another-reviewer", TIME)
    assert [e["action"] for e in store.audit_events("tenant-a")] == ["dataset.created", "release.created", "review.rejected"]


def test_delete_cascade_and_metadata_only_audit(store):
    store.add_dataset(source())
    store.add_release(candidate())
    fails(404, store.delete_dataset, "d1", "tenant-b", "foreign")
    store.delete_dataset("d1", "tenant-a", "deleter")
    fails(404, store.get_dataset, "d1", "tenant-a")
    fails(404, store.get_release, "r1", "tenant-a")
    events = store.audit_events("tenant-a", 2)
    assert [e["seq"] for e in events] == [2, 3]
    assert all(set(e) == {"seq", "time", "actor", "action", "object_id"} for e in events)
    assert events[-1]["actor"] == "deleter"
    assert "SECRET" not in str(events)
    assert store.audit_events("tenant-b") == []
    assert store.verify_audit("tenant-a")
    fails(429, store.audit_events, "tenant-a", 1001)


def test_expiry_cascade_is_committed_and_audited(store, monkeypatch):
    store.add_dataset(source())
    store.add_release(candidate())
    expiry = store.get_dataset("d1", "tenant-a")["expires_at"]
    monkeypatch.setattr("app.repository.time.time", lambda: expiry + 1)
    fails(404, store.get_release, "r1", "tenant-a")
    assert store.list_datasets("tenant-a") == []
    assert store.purge() == 0
    assert store.audit_events("tenant-a")[-1]["action"] == "dataset.expired"


def test_quota_and_conflict_no_partial_audit(store):
    store.MAX_DATASETS_PER_TENANT = 1
    store.add_dataset(source())
    fails(409, store.add_dataset, source())
    fails(429, store.add_dataset, source("d2"))
    assert len(store.audit_events("tenant-a")) == 1
    store.MAX_RELEASES_PER_TENANT = 1
    store.add_release(candidate())
    fails(429, store.add_release, candidate("r2"))
    assert len(store.audit_events("tenant-a")) == 2
    fails(404, store.add_release, candidate("r3", "missing"))


def test_byte_quota_does_not_trust_underreported_counts(store):
    store.MAX_TENANT_SOURCE_BYTES = 500
    data = source()
    data.update(content="x" * 1000, size_bytes=0)
    fails(429, store.add_dataset, data)
    assert store.list_datasets("tenant-a") == []
    assert store.audit_events("tenant-a") == []


def test_audit_reserve_keeps_deletion_available(store):
    store.MAX_AUDIT_EVENTS = 5
    store.MAX_AUDIT_EVENTS_PER_TENANT = 5
    store.add_dataset(source())
    store.add_release(candidate())
    store.add_release(candidate("r2"))
    store.add_release(candidate("r3"))
    fails(429, store.add_dataset, source("d2"))
    store.delete_dataset("d1", "tenant-a", "deleter")
    assert len(store.audit_events("tenant-a")) == 5
    assert store.list_datasets("tenant-a") == []


def test_exhausted_audit_does_not_authorize_expired_data(store, monkeypatch):
    store.add_dataset(source())
    store.add_release(candidate())
    expiry = store.get_dataset("d1", "tenant-a")["expires_at"]
    store.MAX_AUDIT_EVENTS = 2
    store.MAX_AUDIT_EVENTS_PER_TENANT = 2
    monkeypatch.setattr("app.repository.time.time", lambda: expiry + 1)
    fails(429, store.purge)
    fails(404, store.get_dataset, "d1", "tenant-a")
    fails(404, store.get_release, "r1", "tenant-a")


def test_failed_audit_append_rolls_back_data(store, monkeypatch):
    original = store._append_event
    def fail_after_append(*args, **kwargs):
        original(*args, **kwargs)
        raise HTTPException(503, "Simulated write failure")
    monkeypatch.setattr(store, "_append_event", fail_after_append)
    fails(503, store.add_dataset, source())
    assert store.list_datasets("tenant-a") == []
    assert store.audit_events("tenant-a") == []


def test_durable_restart_and_no_plaintext_source_or_audit(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.add_release(candidate())
    store.reject_release("r1", "tenant-a", "synthetic-private-reviewer", TIME)
    store.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    for marker in (source()["content"], source()["original_source"], "synthetic-private-reviewer", "synthetic-actor", "REVIEW_REQUIRED"):
        assert marker.encode() not in raw
    reopened = DurableStore(str(path), KEY)
    try:
        assert reopened.get_dataset("d1", "tenant-a")["content"] == source()["content"]
        assert reopened.get_release("r1", "tenant-a")["card"]["revision"] == 2
        assert len(reopened.audit_events("tenant-a")) == 3
    finally:
        reopened.close()


def test_wrong_key_never_reinitializes_existing_database(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.close()
    before = path.read_bytes()
    error = fails(503, DurableStore, str(path), b"z" * 32)
    assert str(path) not in error.detail
    assert path.read_bytes() == before
    good = DurableStore(str(path), KEY)
    assert good.get_dataset("d1", "tenant-a")["content"] == source()["content"]
    good.close()


@pytest.mark.parametrize("mutation", ["ciphertext", "tenant", "identifier", "type", "expiry", "size", "schema", "audit"])
def test_tamper_fails_closed_without_repair(tmp_path, mutation):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.add_release(candidate())
    with sqlite3.connect(path) as connection:
        if mutation == "ciphertext":
            connection.execute("UPDATE records SET blob=? WHERE kind='dataset'", (b"corrupt" * 10,))
        elif mutation == "tenant":
            connection.execute("UPDATE records SET tenant='tenant-other' WHERE kind='dataset'")
        elif mutation == "identifier":
            connection.execute("UPDATE records SET id='other' WHERE kind='dataset'")
        elif mutation == "type":
            connection.execute("UPDATE records SET kind='release' WHERE kind='dataset'")
        elif mutation == "expiry":
            connection.execute("UPDATE records SET expires_at=expires_at+100 WHERE kind='dataset'")
        elif mutation == "size":
            connection.execute("UPDATE records SET size_bytes=0 WHERE kind='dataset'")
        elif mutation == "schema":
            connection.execute("UPDATE meta SET value=? WHERE name='schema'", (b"bad",))
        else:
            connection.execute("UPDATE audit SET blob=? WHERE seq=1", (b"corrupt" * 10,))
    before = path.read_bytes()
    fails(503, store.get_dataset, "d1", "tenant-a")
    assert path.read_bytes() == before
    store.close()
    fails(503, DurableStore, str(path), KEY)
    assert path.read_bytes() == before


def test_ciphertexts_cannot_be_swapped_between_records(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source("d1"))
    store.add_dataset(source("d2"))
    with sqlite3.connect(path) as connection:
        first = connection.execute("SELECT blob FROM records WHERE id='d1'").fetchone()[0]
        connection.execute("UPDATE records SET blob=? WHERE id='d2'", (first,))
    fails(503, store.verify_audit, "tenant-a")
    store.close()


def test_oversized_sqlite_blobs_are_rejected_before_materialization(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE records SET blob=zeroblob(?) WHERE kind='dataset'", (DurableStore.MAX_RECORD_BLOB + 1,))
    fails(503, DurableStore, str(path), KEY)


def test_cross_instance_quota_and_review_races(tmp_path):
    path = tmp_path / "source.db"
    first, second = DurableStore(str(path), KEY), DurableStore(str(path), KEY)
    first.MAX_DATASETS_PER_TENANT = second.MAX_DATASETS_PER_TENANT = 1
    def attempt(store, data):
        try:
            store.add_dataset(data)
            return 201
        except HTTPException as error:
            return error.status_code
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: attempt(*args), [(first, source("d1")), (second, source("d2"))]))
        assert sorted(results) == [201, 429]
        parent = first.list_datasets("tenant-a")[0]["id"]
        first.add_release(candidate(dataset_id=parent))
        def review(store):
            try:
                store.reject_release("r1", "tenant-a", "reviewer", TIME)
                return 200
            except HTTPException as error:
                return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(review, [first, second])) == [200, 409]
        assert len(second.get_release("r1", "tenant-a")["events"]) == 2
        assert len(first.audit_events("tenant-a")) == 3
    finally:
        first.close()
        second.close()


def test_audit_interior_and_unpaired_terminal_deletion_detected(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.add_release(candidate())
    store.reject_release("r1", "tenant-a", "reviewer", TIME)
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM audit WHERE seq=3")
    # The latest row commitment detects truncation while new record state remains.
    fails(503, store.verify_audit, "tenant-a")
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM audit WHERE seq=1")
    fails(503, store.verify_audit, "tenant-a")
    store.close()


def test_record_replay_rejected_and_consistent_database_rollback_needs_anchor(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.add_release(candidate())
    with sqlite3.connect(path) as connection:
        prior = connection.execute("SELECT size_bytes,blob FROM records WHERE kind='release'").fetchone()
    snapshot = path.read_bytes()
    store.reject_release("r1", "tenant-a", "reviewer", TIME)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE records SET size_bytes=?,blob=? WHERE kind='release'", prior)
    fails(503, store.get_release, "r1", "tenant-a")
    store.close()
    # Explicit documented limitation: replacing the complete DB with a valid old
    # snapshot cannot be detected without a separately held external head anchor.
    path.write_bytes(snapshot)
    reopened = DurableStore(str(path), KEY)
    assert reopened.verify_audit("tenant-a")
    assert reopened.get_release("r1", "tenant-a")["card"]["eligibility"] == "REVIEW_REQUIRED"
    reopened.close()


def test_existing_empty_or_wrong_schema_database_is_not_initialized(tmp_path):
    path = tmp_path / "preexisting.db"
    path.touch()
    fails(503, DurableStore, str(path), KEY)
    assert path.read_bytes() == b""
    for invalid_key in (b"x", "not-bytes", None):
        fails(503, DurableStore, str(tmp_path / "never-created.db"), invalid_key)
    assert not (tmp_path / "never-created.db").exists()


def test_closed_durable_store_fails_safely(tmp_path):
    store = DurableStore(str(tmp_path / "source.db"), KEY)
    store.close()
    store.close()
    fails(503, store.list_datasets, "tenant-a")


def test_deleted_ids_cannot_be_reused_against_old_history(store):
    store.add_dataset(source())
    store.add_release(candidate())
    store.delete_dataset("d1", "tenant-a", "deleter")
    fails(409, store.add_dataset, source())
    store.add_dataset(source("d2"))
    fails(409, store.add_release, candidate(dataset_id="d2"))


def test_sql_commit_path_failure_rolls_back_records_and_audit(tmp_path, monkeypatch):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    original = store._save
    def fail_after_sql(before):
        original(before)
        raise sqlite3.OperationalError("synthetic-sensitive-path-do-not-echo")
    monkeypatch.setattr(store, "_save", fail_after_sql)
    error = fails(503, store.add_dataset, source())
    assert "sensitive" not in error.detail
    monkeypatch.setattr(store, "_save", original)
    assert store.list_datasets("tenant-a") == []
    assert store.audit_events("tenant-a") == []
    store.close()


def test_dataset_delete_wins_over_detached_stale_release_creation(tmp_path):
    path = tmp_path / "source.db"
    first, second = DurableStore(str(path), KEY), DurableStore(str(path), KEY)
    first.add_dataset(source())
    old = first.get_dataset("d1", "tenant-a")
    second.delete_dataset("d1", "tenant-a", "deleter")
    fails(404, first.add_release, candidate(dataset_id=old["id"]))
    assert len(first.audit_events("tenant-a")) == 2
    first.close()
    second.close()


@pytest.mark.parametrize("kind", ["dataset", "release"])
def test_silent_row_deletion_disagrees_with_authenticated_history(tmp_path, kind):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    store.add_release(candidate())
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM records WHERE kind=?", (kind,))
    fails(503, store.verify_audit, "tenant-a")
    store.close()


def test_audit_hmac_is_verified_after_successful_aead_decryption(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_dataset(source())
    with sqlite3.connect(path) as connection:
        blob = connection.execute("SELECT blob FROM audit WHERE seq=1").fetchone()[0]
        entry = store._open(blob, ["tenant-a", "audit", 1], store.MAX_AUDIT_BLOB)
        entry["event"]["actor"] = "forged-actor"
        connection.execute("UPDATE audit SET blob=? WHERE seq=1", (store._seal(entry, ["tenant-a", "audit", 1]),))
    fails(503, store.verify_audit, "tenant-a")
    store.close()


def test_subkey_separation_and_fresh_encryption_nonces(tmp_path):
    store = DurableStore(str(tmp_path / "source.db"), KEY)
    assert store._audit_key != store._encryption_key
    record, aad = {"synthetic": "value"}, ["tenant", "type", "id"]
    first, second = store._seal(record, aad), store._seal(record, aad)
    assert first[:12] != second[:12]
    assert store._open(first, aad, 4096) == store._open(second, aad, 4096) == record
    store.close()


def test_control_records_are_detached_tenant_scoped_and_idempotent(store):
    original = control()
    stored = store.add_control(original, "operator")
    original["payload"]["private_business_label"] = "changed"
    assert store.get_control("rights_profile", "control-1", "tenant-a")["payload"]["private_business_label"] == "buyer-sensitive-synthetic"
    stored["payload"]["private_business_label"] = "changed-again"
    assert store.list_controls("rights_profile", "tenant-a")[0]["payload"]["private_business_label"] == "buyer-sensitive-synthetic"
    fails(404, store.get_control, "rights_profile", "control-1", "tenant-b")
    fails(409, store.add_control, control(), "operator")
    run, _, _ = run_dependencies(store)
    first, reused = store.register_run_control(run, "operator")
    assert not reused and first["id"] == "run-1"
    replay = copy.deepcopy(run)
    replay["id"] = "run-other"
    second, reused = store.register_run_control(replay, "operator")
    assert reused and second["id"] == "run-1"
    conflict = copy.deepcopy(run)
    conflict["id"] = "run-conflict"
    conflict["payload"]["request_digest"] = "sha256:" + "b" * 64
    fails(409, store.register_run_control, conflict, "operator")


def test_durable_controls_restart_encrypt_and_detect_silent_deletion(tmp_path):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    store.add_control(control(), "operator")
    run, _, _ = run_dependencies(store)
    store.register_run_control(run, "operator")
    store.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir() if p.is_file())
    assert b"buyer-sensitive-synthetic" not in raw and b"safe-key-0001" not in raw
    reopened = DurableStore(str(path), KEY)
    assert reopened.get_control("rights_profile", "control-1", "tenant-a")["id"] == "control-1"
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM records WHERE kind='processing_run'")
    fails(503, reopened.verify_audit, "tenant-a")
    reopened.close()


def test_cross_instance_run_idempotency_is_atomic(tmp_path):
    path = tmp_path / "source.db"
    first, second = DurableStore(str(path), KEY), DurableStore(str(path), KEY)
    try:
        first_run, _, _ = run_dependencies(first)
        second_run = copy.deepcopy(first_run)
        second_run["id"] = "run-2"
        def register(store, record):
            try:
                return store.register_run_control(record, "operator")[1]
            except HTTPException as error:
                return error.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(lambda args: register(*args), [(first, first_run), (second, second_run)]))
        assert sorted(result) == [False, True]
        assert first.list_controls("processing_run", "tenant-a")[0]["id"] in {"run-1", "run-2"}
    finally:
        first.close()
        second.close()


def test_expired_durable_control_has_authenticated_tombstone_and_restarts(tmp_path, monkeypatch):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    expiring = control()
    expiring["expires_at"] = time.time() + 1
    store.add_control(expiring, "operator")
    monkeypatch.setattr("app.repository.time.time", lambda: expiring["expires_at"] + 1)
    assert store.purge() == 1
    assert store.audit_events("tenant-a")[-1]["action"] == "rights_profile.expired"
    store.close()
    reopened = DurableStore(str(path), KEY)
    try:
        assert reopened.verify_audit("tenant-a")
        fails(404, reopened.get_control, "rights_profile", "control-1", "tenant-a")
    finally:
        reopened.close()


def test_run_registration_rechecks_live_dependencies_and_deletion_invalidates(store):
    run, rights, _ = run_dependencies(store)
    created, reused = store.register_run_control(run, "operator")
    assert not reused and created["id"] == "run-1"
    store.delete_dataset("d1", "tenant-a", "deleter")
    fails(404, store.get_control, "processing_run", "run-1", "tenant-a")
    assert store.audit_events("tenant-a")[-1]["action"] == "processing_run.invalidated"
    fails(404, store.register_run_control, run, "operator")
    assert store.get_control("rights_profile", "rights-1", "tenant-a")["id"] == rights["id"]


def test_rights_expiry_invalidates_dependent_run_before_restart(tmp_path, monkeypatch):
    path = tmp_path / "source.db"
    store = DurableStore(str(path), KEY)
    run, rights, _ = run_dependencies(store, rights_expiry=time.time() + 1)
    store.register_run_control(run, "operator")
    monkeypatch.setattr("app.repository.time.time", lambda: rights["expires_at"] + 1)
    assert store.purge() == 1
    fails(404, store.get_control, "processing_run", "run-1", "tenant-a")
    store.close()
    reopened = DurableStore(str(path), KEY)
    try:
        assert reopened.verify_audit("tenant-a")
    finally:
        reopened.close()
