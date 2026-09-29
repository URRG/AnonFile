import copy
import hashlib
import json

import pytest

from app.holdout_inventory import HoldoutInventoryError, inspect_fictional_holdout


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def corpus(tmp_path):
    root = tmp_path / "private-fictional-holdout"
    files = root / "files"
    files.mkdir(parents=True)
    text = "Riya 🚀 sent mail.\n".encode("utf-8")
    # The inventory is deliberately not a media parser; a scorer must still
    # decode and validate the exact frozen source separately.
    image = b"fictional-image-fixture"
    (files / "mail.txt").write_bytes(text)
    (files / "scan.png").write_bytes(image)
    manifest = {"schema_version": "fictional-holdout-inventory-v1", "cases": [
        {"id": "mail-01", "batch_id": "batch-01", "filename": "mail.txt", "format": "txt",
         "source_sha256": digest(text), "labels_complete": True,
         "text_spans": [{"start": 0, "end": 4, "entity_type": "PERSON_NAME", "entity_key": "person-01"}],
         "media_regions": [], "protected_regions": []},
        {"id": "scan-01", "batch_id": "batch-01", "filename": "scan.png", "format": "png",
         "source_sha256": digest(image), "labels_complete": True, "text_spans": [],
         "media_regions": [{"page": 1, "page_width": 100, "page_height": 80,
                            "box": [5, 5, 35, 20], "entity_type": "PERSON_NAME", "entity_key": "person-01"}],
         "protected_regions": [{"page": 1, "page_width": 100, "page_height": 80,
                                "box": [40, 5, 90, 20], "kind": "text"}]},
    ]}
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root, manifest


def save(root, manifest):
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_valid_inventory_reports_counts_only_and_does_not_claim_independence(tmp_path):
    root, _ = corpus(tmp_path)
    report = inspect_fictional_holdout(root)
    assert report["status"] == "STRUCTURALLY_VALID_ONLY"
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["batches"] == 1 and report["files"] == 2
    assert report["text_spans"] == report["media_regions"] == report["protected_regions"] == 1
    encoded = json.dumps(report)
    assert "Riya" not in encoded and "mail.txt" not in encoded and "scan-01" not in encoded


@pytest.mark.parametrize("change", [
    lambda m: m["cases"][0].update(labels_complete=False),
    lambda m: m["cases"][0].update(source_sha256="sha256:" + "0" * 64),
    lambda m: m["cases"][0].update(filename="../mail.txt"),
    lambda m: m["cases"][1]["media_regions"][0].update(box=[0, 0, 101, 20]),
    lambda m: m["cases"][1]["protected_regions"][0].update(page_width=101),
    lambda m: m["cases"][1]["media_regions"][0].update(page=2),
    lambda m: m["cases"][0]["text_spans"][0].update(end=999),
    lambda m: m["cases"][0]["text_spans"][0].update(start=True),
    lambda m: m["cases"][1].update(batch_id="orphan"),
])
def test_incomplete_or_inconsistent_inventory_fails_closed(tmp_path, change):
    root, original = corpus(tmp_path)
    invalid = copy.deepcopy(original)
    change(invalid)
    save(root, invalid)
    with pytest.raises(HoldoutInventoryError, match="no report was produced"):
        inspect_fictional_holdout(root)


def test_duplicate_manifest_key_and_changed_source_fail_closed(tmp_path):
    root, manifest = corpus(tmp_path)
    (root / "manifest.json").write_text('{"schema_version":"fictional-holdout-inventory-v1","cases":[],"cases":[]}', encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)
    save(root, manifest)
    (root / "files" / "mail.txt").write_text("changed source", encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)


def test_duplicate_source_bytes_under_different_names_fail_closed(tmp_path):
    root, manifest = corpus(tmp_path)
    data = (root / "files" / "mail.txt").read_bytes()
    (root / "files" / "scan.png").write_bytes(data)
    manifest["cases"][1]["source_sha256"] = digest(data)
    save(root, manifest)
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)


def test_unlisted_source_file_fails_closed(tmp_path):
    root, _ = corpus(tmp_path)
    (root / "files" / "unlisted.txt").write_text("fictional extra", encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)


def test_symlinked_source_is_rejected_when_platform_supports_it(tmp_path):
    root, manifest = corpus(tmp_path)
    source = root / "files" / "mail.txt"
    source.rename(root / "mail-backup.txt")
    try:
        source.symlink_to(root / "mail-backup.txt")
    except OSError:
        pytest.skip("symlink creation unavailable")
    save(root, manifest)
    with pytest.raises(HoldoutInventoryError):
        inspect_fictional_holdout(root)
