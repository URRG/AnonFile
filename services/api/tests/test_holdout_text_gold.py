import hashlib
import json

import pytest

from app.evaluation import parse_gold, read_jsonl
from app.holdout_inventory import HoldoutInventoryError
from app.holdout_text_gold import export_fictional_text_gold


def _corpus(tmp_path):
    root = tmp_path / "private-fictional-holdout"
    files = root / "files"
    files.mkdir(parents=True)
    sources = {"mail.txt": "Riya 🚀 sent mail.\n", "empty.txt": "No personal values.\n",
               "scan.png": None}
    cases = []
    for index, (name, value) in enumerate(sources.items(), 1):
        data = value.encode("utf-8") if value is not None else b"fictional-image-fixture"
        (files / name).write_bytes(data)
        cases.append({"id": f"file-{index:03d}", "batch_id": "batch-001", "filename": name,
                      "format": name.split(".")[-1],
                      "source_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                      "labels_complete": True,
                      "text_spans": ([{"start": 0, "end": 4, "entity_type": "PERSON_NAME", "entity_key": "person-01"}]
                                     if index == 1 else []),
                      "media_regions": [], "protected_regions": []})
    (root / "manifest.json").write_text(json.dumps({"schema_version": "fictional-holdout-inventory-v1",
                                                     "cases": cases}), encoding="utf-8")
    return root, cases


def test_export_text_gold_keeps_source_private_and_preserves_zero_labels(tmp_path):
    root, _ = _corpus(tmp_path)
    report = export_fictional_text_gold(root)
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["text_files"] == 2 and report["media_files_not_converted"] == 1
    assert "Riya" not in json.dumps(report) and "mail.txt" not in json.dumps(report)
    rows, _ = read_jsonl(root / "text-gold.jsonl")
    assert len(parse_gold(rows)) == 2
    assert rows[0]["text"] == "Riya 🚀 sent mail.\n"
    assert rows[0]["annotations"] == [{"start": 0, "end": 4, "entity_type": "PERSON_NAME"}]
    assert rows[1]["annotations"] == []
    assert rows[0]["group_id"] == rows[1]["group_id"]
    assert "entity_key" not in json.dumps(rows)


def test_export_never_overwrites_private_gold_or_uses_incomplete_labels(tmp_path):
    root, cases = _corpus(tmp_path)
    output = root / "text-gold.jsonl"
    output.write_text("existing human-authored work", encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        export_fictional_text_gold(root)
    assert output.read_text(encoding="utf-8") == "existing human-authored work"
    output.unlink()
    cases[0]["labels_complete"] = False
    (root / "manifest.json").write_text(json.dumps({"schema_version": "fictional-holdout-inventory-v1",
                                                    "cases": cases}), encoding="utf-8")
    with pytest.raises(HoldoutInventoryError):
        export_fictional_text_gold(root)
    assert not output.exists()


def test_source_drift_after_inventory_is_rejected(tmp_path, monkeypatch):
    root, _ = _corpus(tmp_path)
    from app import holdout_text_gold
    original = holdout_text_gold.inspect_fictional_holdout

    def tampered(path):
        result = original(path)
        (root / "files" / "mail.txt").write_text("changed", encoding="utf-8")
        return result

    monkeypatch.setattr(holdout_text_gold, "inspect_fictional_holdout", tampered)
    with pytest.raises(HoldoutInventoryError):
        export_fictional_text_gold(root)
    assert not (root / "text-gold.jsonl").exists()
