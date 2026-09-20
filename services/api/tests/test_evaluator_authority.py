"""Strict evaluator-authority configuration tests."""
import base64
import json

import pytest

from app.evaluator_authority import EvaluatorAuthorityError, load_evaluator_authorities


def valid_authority():
    return {"subject": "evaluator", "tenant": "tenant-a", "evaluator_id": "m8-harness",
            "evaluator_version": "v1", "evaluator_config_digest": "sha256:" + "a" * 64,
            "corpus_digests": ["sha256:" + "b" * 64],
            "key": base64.b64encode(b"e" * 32).decode("ascii")}


def test_authority_configuration_rejects_duplicate_members_at_any_depth(monkeypatch):
    duplicate_top = ('[{"subject":"evaluator","subject":"other","tenant":"tenant-a",'
                     '"evaluator_id":"m8-harness","evaluator_version":"v1",'
                     '"evaluator_config_digest":"sha256:' + "a" * 64 + '","corpus_digests":["sha256:' + "b" * 64 + '"],'
                     '"key":"' + base64.b64encode(b"e" * 32).decode("ascii") + '"}]')
    monkeypatch.setenv("ANONFLOW_EVALUATOR_AUTHORITIES", duplicate_top)
    with pytest.raises(EvaluatorAuthorityError):
        load_evaluator_authorities()
    nested = valid_authority()
    raw = json.dumps([nested], separators=(",", ":")).replace(
        '"corpus_digests":[', '"corpus_digests":[{"bad":1,"bad":2},')
    monkeypatch.setenv("ANONFLOW_EVALUATOR_AUTHORITIES", raw)
    with pytest.raises(EvaluatorAuthorityError):
        load_evaluator_authorities()


def test_authority_configuration_loads_only_exact_allowlisted_fields(monkeypatch):
    monkeypatch.setenv("ANONFLOW_EVALUATOR_AUTHORITIES", json.dumps([valid_authority()]))
    authority = load_evaluator_authorities()[0]
    assert authority.subject == "evaluator"
    assert "e" * 32 not in repr(authority)
