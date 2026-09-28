import hashlib
import json

import pytest

from app.holdout_inventory import HoldoutInventoryError, inspect_fictional_holdout
from app.holdout_scaffold import scaffold_fictional_holdout


def corpus(tmp_path, count=3):
    root = tmp_path / "private-fictional-holdout"
    files = root / "files"
    files.mkdir(parents=True)
    for index in range(count):
        (files / f"source-{index}.txt").write_text(f"Fictional person {index} 🚀\n", encoding="utf-8")
    return root


@pytest.mark.parametrize("count,expected_batches", [(2, 1), (3, 1), (4, 2), (7, 3)])
def test_scaffold_freezes_sources_without_claiming_labels(tmp_path, count, expected_batches):
    root = corpus(tmp_path, count)
    report = scaffold_fictional_holdout(root)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert report["status"] == "AWAITING_BLIND_ANNOTATION"
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["files"] == count and report["batches"] == expected_batches
    assert "Fictional" not in json.dumps(report)
    assert all(case["labels_complete"] is False and case["text_spans"] == []
               for case in manifest["cases"])
    assert all(case["source_sha256"] == "sha256:" + hashlib.sha256(
        (root / "files" / case["filename"]).read_bytes()).hexdigest()
        for case in manifest["cases"])
    assert all(2 <= sum(case["batch_id"] == batch for case in manifest["cases"]) <= 3
               for batch in {case["batch_id"] for case in manifest["cases"]})
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)


def test_scaffold_never_overwrites_existing_manifest(tmp_path):
    root = corpus(tmp_path)
    manifest = root / "manifest.json"
    manifest.write_text("human-authored", encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        scaffold_fictional_holdout(root)
    assert manifest.read_text(encoding="utf-8") == "human-authored"


@pytest.mark.parametrize("extra", ["nested", "bad.exe", "too-large.txt"])
def test_scaffold_rejects_unexpected_or_oversized_inputs(tmp_path, extra):
    root = corpus(tmp_path, 2)
    target = root / "files" / extra
    if extra == "nested":
        target.mkdir()
    elif extra == "too-large.txt":
        target.write_bytes(b"a" * 100_001)
    else:
        target.write_text("content", encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        scaffold_fictional_holdout(root)
    assert not (root / "manifest.json").exists()


def test_scaffold_rejects_symlinked_source(tmp_path):
    root = corpus(tmp_path, 2)
    source = root / "files" / "source-0.txt"
    source.rename(root / "backup.txt")
    try:
        source.symlink_to(root / "backup.txt")
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(HoldoutInventoryError):
        scaffold_fictional_holdout(root)
    assert not (root / "manifest.json").exists()
