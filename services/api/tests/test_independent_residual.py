"""Independent residual-scanner regression tests."""
from app import processing
from app.independent_residual import (
    ALGORITHM_REVISION,
    ASSESSED_CATEGORIES,
    BUILD_REVISION,
    DETECTOR_CONFIG_DIGEST,
    DETECTOR_ID,
    DETECTOR_IDENTITY_CONFIG,
    _config_digest,
    scan_residual_candidate,
)
from app.main import _residual_detector


def test_independent_scanner_detects_candidate_residuals_as_aggregate_families_only():
    candidate = [
        {"note": "email ada@example.test; PAN ABCPD1234E"},
        {"note": "card 4111 1111 1111 1111; api-key: synthetic-secret"},
    ]
    result = scan_residual_candidate(candidate)
    assert dict(result.residual_counts) == {"CREDENTIAL": 1, "PAYMENT": 1, "PII": 1}
    assert result.scanned_units == 2
    assert result.assessed_categories == ASSESSED_CATEGORIES
    assert "ada@example.test" not in str(result)


def test_residual_scanner_is_not_coupled_to_transformation_detector(monkeypatch):
    def transformation_detector_must_not_run(_value):
        raise AssertionError("transformation detector must not be used for residual evidence")

    monkeypatch.setattr(processing, "detect_text", transformation_detector_must_not_run)
    # ``main`` holds an older direct import of detect_text for source intake
    # validation.  Replacing it as well proves the residual adapter itself does
    # not route through either reference.
    monkeypatch.setattr("app.main.detect_text", transformation_detector_must_not_run)
    result = _residual_detector("Authorization: Bearer synthetic.token-123456")
    assert dict(result.residual_counts) == {"CREDENTIAL": 1, "PAYMENT": 0, "PII": 0}


def test_independent_residual_scanner_finds_unlabelled_aws_key_without_returning_it():
    fictional_key = "ASIA" + "Z" * 16
    result = scan_residual_candidate([{"note": fictional_key}])
    assert dict(result.residual_counts) == {"CREDENTIAL": 1, "PAYMENT": 0, "PII": 0}
    assert fictional_key not in repr(result)


def test_independent_scanner_explicitly_leaves_nonqualified_taxonomy_unassessed():
    result = scan_residual_candidate("diagnosis: synthetic-condition; internal roadmap: synthetic-roadmap; age: 47")
    assert dict(result.residual_counts) == {"CREDENTIAL": 0, "PAYMENT": 0, "PII": 0}
    assert result.assessed_categories == frozenset({"PII", "PAYMENT", "CREDENTIAL"})


def test_residual_scanner_exposes_a_stable_source_free_configuration_identity():
    assert DETECTOR_ID == "m8-independent-residual"
    assert DETECTOR_CONFIG_DIGEST.startswith("sha256:") and len(DETECTOR_CONFIG_DIGEST) == 71
    assert DETECTOR_IDENTITY_CONFIG["algorithm_revision"] == ALGORITHM_REVISION
    assert DETECTOR_IDENTITY_CONFIG["build_revision"] == BUILD_REVISION
    assert _config_digest(algorithm_revision=ALGORITHM_REVISION + "-patched",
                          build_revision=BUILD_REVISION) != DETECTOR_CONFIG_DIGEST
    assert _config_digest(algorithm_revision=ALGORITHM_REVISION,
                          build_revision=BUILD_REVISION + "-patched") != DETECTOR_CONFIG_DIGEST


def test_direct_scanner_cycle_is_an_abstention_not_an_unbounded_walk():
    cyclic: list[object] = []
    cyclic.append(cyclic)
    result = scan_residual_candidate(cyclic)
    assert dict(result.residual_counts) == {"CREDENTIAL": 0, "PAYMENT": 0, "PII": 0}
    assert result.scanned_units == 1
    assert result.abstained_units == 1
