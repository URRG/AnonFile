"""Independent residual-scanner regression tests."""
from app import processing
from app.independent_residual import ASSESSED_CATEGORIES, DETECTOR_CONFIG_DIGEST, DETECTOR_ID, scan_residual_candidate
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


def test_independent_scanner_explicitly_leaves_nonqualified_taxonomy_unassessed():
    result = scan_residual_candidate("diagnosis: synthetic-condition; internal roadmap: synthetic-roadmap; age: 47")
    assert dict(result.residual_counts) == {"CREDENTIAL": 0, "PAYMENT": 0, "PII": 0}
    assert result.assessed_categories == frozenset({"PII", "PAYMENT", "CREDENTIAL"})


def test_residual_scanner_exposes_a_stable_source_free_configuration_identity():
    assert DETECTOR_ID == "m8-independent-residual"
    assert DETECTOR_CONFIG_DIGEST.startswith("sha256:") and len(DETECTOR_CONFIG_DIGEST) == 71
