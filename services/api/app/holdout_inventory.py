"""Source-safe intake validation for externally authored fictional holdouts.

This freezes file bytes and complete annotation *presence*. It does not score
the product, verify annotator independence, decode media, or authorize use of
real supplier data. Keep inventories and files outside the repository.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

from app.evaluation import ENTITY_TYPES


_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TEXT = frozenset({"txt", "csv", "json", "jsonl"})
_MEDIA = frozenset({"pdf", "png", "jpg", "jpeg"})
_MAX_MANIFEST = 262_144
_MAX_FILES = 48
_MAX_TOTAL_PER_BATCH = 1_500_000


class HoldoutInventoryError(ValueError):
    def __init__(self) -> None:
        super().__init__("Fictional holdout inventory invalid; no report was produced.")


def _fail() -> None:
    raise HoldoutInventoryError() from None


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            _fail()
        result[key] = value
    return result


def _id(value: object) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _box(value: object, width: int, height: int) -> None:
    if (type(value) is not list or len(value) != 4
            or any(type(item) is not int for item in value)):
        _fail()
    x0, y0, x1, y1 = value
    if not (0 <= x0 < x1 <= width and 0 <= y0 < y1 <= height):
        _fail()


def _text_labels(labels: object, source: str) -> int:
    if type(labels) is not list or len(labels) > 1000:
        _fail()
    seen: set[tuple[int, int, str]] = set()
    for item in labels:
        if type(item) is not dict or set(item) != {"start", "end", "entity_type", "entity_key"}:
            _fail()
        start, end, kind = item["start"], item["end"], item["entity_type"]
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= len(source)
                or type(kind) is not str or kind not in ENTITY_TYPES):
            _fail()
        _id(item["entity_key"])
        key = (start, end, kind)
        if key in seen:
            _fail()
        seen.add(key)
    return len(labels)


def _media_labels(labels: object, *, protected: bool) -> int:
    if type(labels) is not list or len(labels) > 1000:
        _fail()
    seen: set[tuple[int, tuple[int, ...]]] = set()
    for item in labels:
        keys = ({"page", "page_width", "page_height", "box", "kind"} if protected else
                {"page", "page_width", "page_height", "box", "entity_type", "entity_key"})
        if type(item) is not dict or set(item) != keys:
            _fail()
        page, width, height = item["page"], item["page_width"], item["page_height"]
        if (type(page) is not int or not 1 <= page <= 2 or type(width) is not int
                or type(height) is not int or not 16 <= width <= 4000
                or not 16 <= height <= 4000 or width * height > 2_000_000):
            _fail()
        _box(item["box"], width, height)
        if protected:
            if item["kind"] not in {"text", "table", "form", "graphic"}:
                _fail()
        elif type(item["entity_type"]) is not str or item["entity_type"] not in ENTITY_TYPES:
            _fail()
        if not protected:
            _id(item["entity_key"])
        key = (page, tuple(item["box"]))
        if key in seen:
            _fail()
        seen.add(key)
    return len(labels)


def inspect_fictional_holdout(root: Path) -> dict[str, object]:
    """Return aggregate-only intake counts; never return paths, IDs, or labels."""
    try:
        root = root.resolve(strict=True)
        files_dir = root / "files"
        if not root.is_dir() or not files_dir.is_dir() or files_dir.is_symlink():
            _fail()
        manifest_path = root / "manifest.json"
        if manifest_path.is_symlink():
            _fail()
        with manifest_path.open("rb") as stream:
            raw = stream.read(_MAX_MANIFEST + 1)
        if not 1 <= len(raw) <= _MAX_MANIFEST:
            _fail()
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: _fail())
        if (type(manifest) is not dict or set(manifest) != {"schema_version", "cases"}
                or manifest["schema_version"] != "fictional-holdout-inventory-v1"):
            _fail()
        cases = manifest["cases"]
        if type(cases) is not list or not 2 <= len(cases) <= _MAX_FILES:
            _fail()
        seen_ids: set[str] = set()
        seen_files: set[str] = set()
        batch_counts: Counter[str] = Counter()
        batch_bytes: Counter[str] = Counter()
        formats: Counter[str] = Counter()
        text_count = media_count = protected_count = 0
        for case in cases:
            if (type(case) is not dict or set(case) != {"id", "batch_id", "filename", "format",
                                                       "source_sha256", "text_spans", "media_regions",
                                                       "protected_regions", "labels_complete"}):
                _fail()
            case_id, batch_id = _id(case["id"]), _id(case["batch_id"])
            name, kind = case["filename"], case["format"]
            if (case_id in seen_ids or type(name) is not str or not _FILE.fullmatch(name)
                    or name in {".", ".."} or name in seen_files or type(kind) is not str
                    or kind not in _TEXT | _MEDIA or name.rsplit(".", 1)[-1].lower() != kind
                    or case["labels_complete"] is not True):
                _fail()
            seen_ids.add(case_id)
            seen_files.add(name)
            target = files_dir / name
            if target.is_symlink() or not target.is_file() or target.resolve(strict=True).parent != files_dir.resolve(strict=True):
                _fail()
            limit = 100_000 if kind in _TEXT else 500_000
            with target.open("rb") as stream:
                data = stream.read(limit + 1)
            if not 1 <= len(data) <= limit or "sha256:" + hashlib.sha256(data).hexdigest() != _digest(case["source_sha256"]):
                _fail()
            source = data.decode("utf-8") if kind in _TEXT else ""
            if kind in _TEXT and not source.strip():
                _fail()
            if kind in _TEXT and (case["media_regions"] or case["protected_regions"]):
                _fail()
            if kind in _MEDIA and case["text_spans"]:
                _fail()
            text_count += _text_labels(case["text_spans"], source)
            media_count += _media_labels(case["media_regions"], protected=False)
            protected_count += _media_labels(case["protected_regions"], protected=True)
            page_sizes: dict[int, tuple[int, int]] = {}
            for region in [*case["media_regions"], *case["protected_regions"]]:
                if kind != "pdf" and region["page"] != 1:
                    _fail()
                dimensions = (region["page_width"], region["page_height"])
                previous = page_sizes.setdefault(region["page"], dimensions)
                if previous != dimensions:
                    _fail()
            batch_counts[batch_id] += 1
            batch_bytes[batch_id] += len(data)
            formats[kind] += 1
        if any(not 2 <= count <= 3 or batch_bytes[batch_id] > _MAX_TOTAL_PER_BATCH
               for batch_id, count in batch_counts.items()):
            _fail()
        return {"schema_version": "fictional-holdout-inventory-report-v1",
                "status": "STRUCTURALLY_VALID_ONLY", "qualification": "NOT_QUALIFIED",
                "manifest_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "batches": len(batch_counts), "files": len(cases), "formats": dict(sorted(formats.items())),
                "text_spans": text_count, "media_regions": media_count,
                "protected_regions": protected_count,
                "limitations": ["Annotation independence and completeness are not verified by this validator.",
                                "Media bytes are hashed but not decoded or scored.",
                                "No model accuracy, layout utility, or release-safety claim follows."]}
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, HoldoutInventoryError):
        _fail()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m app.holdout_inventory <fictional-corpus-directory>", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(json.dumps(inspect_fictional_holdout(Path(sys.argv[1])), sort_keys=True))
    except HoldoutInventoryError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
