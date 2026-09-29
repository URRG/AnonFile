"""Privately convert validated fictional text labels to evaluator gold JSONL.

This does not run a detector, create annotations, or establish an independent
benchmark. The output contains the original source text and must stay outside
Git. Media cases are deliberately not converted into guessed text offsets.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from app.evaluation import EvaluationError, parse_gold
from app.holdout_inventory import (_MAX_MANIFEST, _TEXT, HoldoutInventoryError,
                                   inspect_fictional_holdout)


def export_fictional_text_gold(root: Path) -> dict[str, object]:
    """Create root/text-gold.jsonl exclusively; return only source-free counts."""
    try:
        if root.is_symlink():
            raise HoldoutInventoryError()
        root = root.resolve(strict=True)
        inventory = inspect_fictional_holdout(root)
        manifest_path = root / "manifest.json"
        if manifest_path.is_symlink():
            raise HoldoutInventoryError()
        with manifest_path.open("rb") as stream:
            raw = stream.read(_MAX_MANIFEST + 1)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != inventory["manifest_sha256"]:
            raise HoldoutInventoryError()
        manifest = json.loads(raw.decode("utf-8"))
        rows: list[dict[str, object]] = []
        for case in manifest["cases"]:
            if case["format"] not in _TEXT:
                continue
            path = root / "files" / case["filename"]
            if path.is_symlink() or not path.is_file() or path.resolve(strict=True).parent != (root / "files").resolve(strict=True):
                raise HoldoutInventoryError()
            with path.open("rb") as stream:
                source = stream.read(100_001)
            if (not 1 <= len(source) <= 100_000 or
                    "sha256:" + hashlib.sha256(source).hexdigest() != case["source_sha256"]):
                raise HoldoutInventoryError()
            rows.append({"id": case["id"], "group_id": case["batch_id"],
                         "text": source.decode("utf-8"),
                         "annotations": [{key: label[key] for key in ("start", "end", "entity_type")}
                                         for label in case["text_spans"]]})
        if not rows:
            raise HoldoutInventoryError()
        parse_gold(rows)
        payload = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
                          for row in rows)
        output = root / "text-gold.jsonl"
        # An existing private gold file could contain human corrections. Never replace it.
        created = False
        try:
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                created = True
                stream.write(payload)
        except BaseException:
            if created:
                output.unlink(missing_ok=True)
            raise
        return {"status": "PRIVATE_TEXT_GOLD_CREATED", "qualification": "NOT_QUALIFIED",
                "text_files": len(rows), "media_files_not_converted": inventory["files"] - len(rows),
                "gold_sha256": "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                "limitations": ["The source-text gold file is private and must not be committed.",
                                "The inventory does not prove annotation independence or completeness.",
                                "Media, OCR, graph, final-artifact safety, and release are not measured."]}
    except (OSError, ValueError, TypeError, UnicodeError, KeyError, RecursionError,
            EvaluationError, HoldoutInventoryError):
        raise HoldoutInventoryError() from None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m app.holdout_text_gold <fictional-corpus-directory>", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(json.dumps(export_fictional_text_gold(Path(sys.argv[1])), sort_keys=True))
    except HoldoutInventoryError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
