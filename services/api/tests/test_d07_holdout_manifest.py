import hashlib
import json

import pytest

from app.d07_holdout_manifest import (D07HoldoutManifestError, FinalArtifact,
                                      bind_final_artifacts)


def _manifest() -> bytes:
    return json.dumps({
        "schema_version": "d07-frozen-holdout-manifest-v1",
        "artifacts": [
            {"artifact_id": "opaque-01", "format": "pdf", "final_sha256": hashlib.sha256(b"final pdf").hexdigest(),
             "entity_types": ["EMAIL", "PHONE"]},
            {"artifact_id": "opaque-02", "format": "jsonl", "final_sha256": hashlib.sha256(b"final jsonl").hexdigest(),
             "entity_types": ["EMAIL"]},
        ],
    }, sort_keys=True, separators=(",", ":")).encode()


def _artifacts() -> tuple[FinalArtifact, ...]:
    return (FinalArtifact("opaque-01", b"final pdf"), FinalArtifact("opaque-02", b"final jsonl"))


def test_binds_every_final_artifact_and_reports_only_aggregate_format_type_shape() -> None:
    raw = _manifest()
    report = bind_final_artifacts(manifest_bytes=raw, expected_manifest_sha256=hashlib.sha256(raw).hexdigest(), artifacts=_artifacts())
    assert report["status"] == "FINAL_ARTIFACTS_BOUND"
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["aggregate"] == {"artifacts": 2, "by_format": {"jsonl": 1, "pdf": 1},
                                    "artifacts_by_entity_type": {"EMAIL": 2, "PHONE": 1}}
    encoded = json.dumps(report, sort_keys=True)
    assert "opaque-01" not in encoded and "final pdf" not in encoded


@pytest.mark.parametrize("mutate", ["pin", "byte", "missing", "duplicate", "unknown_type"])
def test_bad_pins_bytes_or_manifest_shape_fail_closed(mutate: str) -> None:
    raw = _manifest()
    digest = hashlib.sha256(raw).hexdigest()
    artifacts = _artifacts()
    if mutate == "pin":
        digest = "0" * 64
    elif mutate == "byte":
        artifacts = (FinalArtifact("opaque-01", b"changed"), artifacts[1])
    elif mutate == "missing":
        artifacts = artifacts[:1]
    elif mutate == "duplicate":
        artifacts = (artifacts[0], FinalArtifact("opaque-01", b"final jsonl"))
    else:
        parsed = json.loads(raw)
        parsed["artifacts"][0]["entity_types"] = ["NOT_A_TYPE"]
        raw = json.dumps(parsed).encode()
        digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(D07HoldoutManifestError, match="^D07 frozen holdout manifest verification failed; no report was produced\\.$"):
        bind_final_artifacts(manifest_bytes=raw, expected_manifest_sha256=digest, artifacts=artifacts)


def test_tuple_and_bytes_subclasses_cannot_bypass_input_caps(monkeypatch) -> None:
    raw = _manifest()
    digest = hashlib.sha256(raw).hexdigest()

    class LyingTuple(tuple):
        def __len__(self):
            return 1

    class ForgedLengthBytes(bytes):
        def __len__(self):
            return 1

    with pytest.raises(D07HoldoutManifestError):
        bind_final_artifacts(manifest_bytes=raw, expected_manifest_sha256=digest,
                             artifacts=LyingTuple(_artifacts()))
    monkeypatch.setattr("app.d07_holdout_manifest._MAX_ARTIFACT_BYTES", 10)
    forged = FinalArtifact("opaque-01", ForgedLengthBytes(b"x" * 11))
    with pytest.raises(D07HoldoutManifestError):
        bind_final_artifacts(manifest_bytes=raw, expected_manifest_sha256=digest,
                             artifacts=(forged, _artifacts()[1]))


def test_cumulative_artifact_byte_cap_is_checked_before_hashing(monkeypatch) -> None:
    raw = _manifest()
    monkeypatch.setattr("app.d07_holdout_manifest._MAX_TOTAL_ARTIFACT_BYTES", 10)
    artifacts = (FinalArtifact("opaque-01", b"123456"), FinalArtifact("opaque-02", b"abcdef"))
    # The manifest hashes intentionally differ: the aggregate cap must reject
    # before final-byte digests are consulted.
    with pytest.raises(D07HoldoutManifestError):
        bind_final_artifacts(manifest_bytes=raw, expected_manifest_sha256=hashlib.sha256(raw).hexdigest(),
                             artifacts=artifacts)
