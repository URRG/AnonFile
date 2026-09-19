from datetime import UTC, datetime, timedelta

import pytest

from app.runs import (MAX_ATTEMPTS, IdempotencyConflict, ProcessingPlan,
                      RunError, RunRegistry, RunState, artifact_metadata,
                      canonical_json)


SOURCE = "sha256:" + "a" * 64


def plan(**changes):
    values = {"dataset_id": "dataset-1", "source_digest": SOURCE,
              "policy_id": "baseline", "policy_version": "v1",
              "method_id": "rules-v1", "mode": "external_anonymized",
              "options": {"threshold": 2, "labels": ["EMAIL"]}}
    values.update(changes)
    return ProcessingPlan.create(**values)


def registry():
    return RunRegistry(clock=lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))


def register(store, *, key="safe-key-0001", request=None):
    return store.register(run_id="run-1", tenant="tenant-1", idempotency_key=key,
                          plan=request or plan())


def test_request_digest_is_stable_across_object_order_and_plan_is_immutable():
    first = plan(options={"z": [3, 2], "a": {"enabled": True}})
    second = plan(options={"a": {"enabled": True}, "z": [3, 2]})
    assert first.request_digest == second.request_digest
    with pytest.raises(AttributeError):
        first.mode = "different"
    assert first.options == canonical_json({"a": {"enabled": True}, "z": [3, 2]})


@pytest.mark.parametrize("options", [b"null", b"[]"])
def test_direct_plan_construction_keeps_mapping_options_contract(options):
    with pytest.raises(RunError):
        ProcessingPlan(dataset_id="dataset-1", source_digest=SOURCE, policy_id="baseline", policy_version="v1",
                       method_id="rules-v1", mode="external_anonymized", options=options)


def test_register_is_idempotent_for_identical_request_and_conflicts_for_different_request():
    store = registry()
    created, reused = register(store)
    existing, reused_again = store.register(run_id="other-run", tenant="tenant-1",
                                            idempotency_key="safe-key-0001", plan=plan())
    assert not reused and reused_again
    assert existing is created
    with pytest.raises(IdempotencyConflict) as error:
        store.register(run_id="third-run", tenant="tenant-1", idempotency_key="safe-key-0001",
                       plan=plan(policy_version="v2"))
    assert str(error.value) == "Idempotency key conflicts with a different request."


def test_run_transitions_only_follow_legal_state_graph_and_never_store_output():
    store = registry()
    created, _ = register(store)
    with pytest.raises(RunError, match="Illegal processing run transition"):
        store.candidate(tenant="tenant-1", run_id=created.id,
                        artifact=artifact_metadata("private output", media_type="text/plain"))
    started = store.start(tenant="tenant-1", run_id=created.id)
    candidate = store.candidate(tenant="tenant-1", run_id=created.id,
                                artifact=artifact_metadata("private output", media_type="text/plain"))
    assert (started.state, candidate.state) == (RunState.RUNNING, RunState.CANDIDATE)
    assert candidate.artifact is not None
    assert "private output" not in repr(candidate)
    quarantined = store.quarantine(tenant="tenant-1", run_id=created.id, code="RESIDUAL_RISK")
    assert quarantined.state is RunState.QUARANTINED
    with pytest.raises(RunError, match="Illegal processing run transition"):
        store.start(tenant="tenant-1", run_id=created.id)


def test_failed_runs_can_retry_only_within_bounded_attempts():
    store = registry()
    created, _ = register(store)
    for attempt in range(MAX_ATTEMPTS):
        running = store.start(tenant="tenant-1", run_id=created.id)
        assert running.attempts == attempt + 1
        failed = store.fail(tenant="tenant-1", run_id=created.id, code="WORKER_FAILURE")
        assert failed.events[-1].error_code == "WORKER_FAILURE"
    with pytest.raises(RunError, match="attempt capacity"):
        store.start(tenant="tenant-1", run_id=created.id)


@pytest.mark.parametrize("bad", ["short", "space is invalid", "x" * 129, "bad/key!", 7])
def test_invalid_idempotency_or_unsafe_errors_do_not_echo_input(bad):
    store = registry()
    with pytest.raises(RunError) as error:
        register(store, key=bad)
    assert str(bad) not in str(error.value)
    created, _ = register(store)
    with pytest.raises(RunError) as error:
        store.fail(tenant="tenant-1", run_id=created.id, code="private exception text")
    assert str(error.value) == "Invalid processing run request."


@pytest.mark.parametrize("value", [float("nan"), {"x": "\ud800"}, {"x": [None] * 1001}, {"x": {"y": {"z": {"q": {"r": {"s": {"t": {"u": {"v": {"w": {"a": {"b": {"c": 1}}}}}}}}}}}}}])
def test_canonical_json_rejects_oversized_or_invalid_graphs_safely(value):
    with pytest.raises(RunError) as error:
        canonical_json(value)
    assert str(error.value) == "Invalid processing run request."


def test_artifact_metadata_is_deterministic_and_metadata_only():
    output = {"b": 2, "a": ["secret-value"]}
    first = artifact_metadata(output, media_type="application/json")
    second = artifact_metadata({"a": ["secret-value"], "b": 2}, media_type="application/json")
    assert first == second
    assert first.digest.startswith("sha256:")
    assert "secret-value" not in repr(first)
    with pytest.raises(RunError):
        artifact_metadata("not json", media_type="text/csv")


def test_event_timestamps_are_utc_and_monotonic_callers_are_not_required():
    store = registry()
    created, _ = register(store)
    # A valid earlier timestamp cannot cause event mutation; ordering is the
    # immutable sequence, while adapters may impose stronger monotonic clocks.
    started = store.start(tenant="tenant-1", run_id=created.id,
                          occurred_at=datetime(2020, 1, 1, tzinfo=UTC) + timedelta(seconds=1))
    assert started.events[-1].occurred_at.tzinfo is UTC
