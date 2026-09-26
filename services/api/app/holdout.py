"""Strict, checksum-pinned holdout *selection*, not independence attestation.

An external curator must establish consent, annotation quality, independence,
representativeness, and lock custody. This module can only prevent accidental
split mixing and detect changes to an already-pinned local corpus.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from app.evaluation import EvaluationError, GoldDocument

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = "holdout-lock-v1"


def _invalid() -> None:
    raise EvaluationError("Invalid holdout lock or split; no report was produced.")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def select_holdout(gold: tuple[GoldDocument, ...], raw_gold_sha256: str,
                   lock_path: str) -> tuple[tuple[GoldDocument, ...], dict[str, object]]:
    try:
        raw = Path(lock_path).read_bytes()
        if len(raw) > 4096:
            _invalid()
        lock = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(lock, dict) or set(lock) != {
            "schema_version", "gold_sha256", "annotation_protocol_sha256",
            "holdout_split", "minimum_documents", "minimum_positive_documents",
        }:
            _invalid()
        if (lock["schema_version"] != _VERSION or lock["holdout_split"] != "holdout" or
                not isinstance(lock["gold_sha256"], str) or not _DIGEST.fullmatch(lock["gold_sha256"]) or
                lock["gold_sha256"] != raw_gold_sha256 or
                not isinstance(lock["annotation_protocol_sha256"], str) or
                not _DIGEST.fullmatch(lock["annotation_protocol_sha256"]) or
                type(lock["minimum_documents"]) is not int or not 1 <= lock["minimum_documents"] <= 10_000 or
                type(lock["minimum_positive_documents"]) is not int or
                not 1 <= lock["minimum_positive_documents"] <= lock["minimum_documents"]):
            _invalid()
        if not gold or any(doc.group_id is None or doc.split not in {"train", "validation", "holdout"}
                           for doc in gold):
            _invalid()
        if not any(doc.split != "holdout" for doc in gold):
            _invalid()
        # The evaluator already rejects a group assigned across splits. Also
        # refuse exact duplicate source text across splits, independent of ID.
        text_splits: dict[str, set[str]] = {}
        for doc in gold:
            text_splits.setdefault(hashlib.sha256(doc.text.encode("utf-8")).hexdigest(), set()).add(doc.split)
        if any(len(splits) > 1 for splits in text_splits.values()):
            _invalid()
        selected = tuple(doc for doc in gold if doc.split == "holdout")
        if (len(selected) < lock["minimum_documents"] or
                sum(bool(doc.annotations) for doc in selected) < lock["minimum_positive_documents"]):
            _invalid()
        evidence = {"lock_sha256": hashlib.sha256(raw).hexdigest(),
                    "annotation_protocol_sha256": lock["annotation_protocol_sha256"],
                    "holdout_documents": len(selected),
                    "non_holdout_documents": len(gold) - len(selected),
                    "split_selection": "holdout",
                    "independence_attestation": "NOT_VERIFIED_BY_SOFTWARE"}
        return selected, evidence
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        raise EvaluationError("Invalid holdout lock or split; no report was produced.") from None
