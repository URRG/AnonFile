import pytest

from app.detector_contracts import (AdapterResult, AggregateFinding, Coverage,
                                    CoverageStatus, DetectorContractError,
                                    DetectorEvidence, DetectorIdentity,
                                    TaxonomyMapper, canonical_configuration,
                                    execute_adapter, normalize_result)
from app.policies import TAXONOMY_CATEGORIES


ASSESSED = frozenset({"PII", "PAYMENT", "CREDENTIAL"})
ABSTAINED = TAXONOMY_CATEGORIES - ASSESSED


def adapter_result(label_counts, total_units, attempted_units, abstained_units=0,
                   *, assessed_categories=ASSESSED, abstained_categories=ABSTAINED):
    return AdapterResult(label_counts, total_units, attempted_units, assessed_categories,
                         abstained_units, abstained_categories)


def identity(configuration={"model": "synthetic-v1", "threshold": 0.8}):
    return DetectorIdentity.from_configuration(detector_id="rules-adapter", version="v1", configuration=configuration)


def mapper():
    return TaxonomyMapper.create({"EMAIL": "PII", "PHONE": "PII", "CARD": "PAYMENT", "TOKEN": "CREDENTIAL"})


def test_identity_config_digest_is_stable_without_retaining_configuration():
    first = identity({"labels": ["EMAIL", "CARD"], "threshold": 0.8})
    second = identity({"threshold": 0.8, "labels": ["EMAIL", "CARD"]})
    assert first == second
    assert first.config_digest.startswith("sha256:")
    assert "threshold" not in repr(first) and "synthetic" not in repr(first)


def test_aggregate_labels_map_deterministically_to_policy_taxonomy():
    evidence = normalize_result(identity=identity(), mapper=mapper(), result=adapter_result(
        {"PHONE": 2, "EMAIL": 1, "CARD": 3}, total_units=10, attempted_units=10,
    ))
    assert [(item.category, item.count) for item in evidence.findings] == [("PAYMENT", 3), ("PII", 3)]
    record = evidence.to_record()
    assert record["findings"] == {"PAYMENT": 3, "PII": 3}
    assert record["coverage"]["status"] == "PARTIAL"
    assert record["mapped_categories"] == ["CREDENTIAL", "PAYMENT", "PII"]


def test_coverage_distinguishes_partial_unattempted_and_full_abstention():
    partial = Coverage.from_result(adapter_result({}, total_units=10, attempted_units=7, abstained_units=2))
    assert (partial.assessed_units, partial.percent, partial.status) == (5, 50, CoverageStatus.PARTIAL)
    abstained = Coverage.from_result(adapter_result({}, total_units=4, attempted_units=4, abstained_units=4))
    assert (abstained.percent, abstained.status) == (0, CoverageStatus.ABSTAINED)
    unattempted = Coverage.from_result(adapter_result({}, total_units=4, attempted_units=0))
    assert unattempted.status is CoverageStatus.PARTIAL


def test_unknown_adapter_labels_fail_closed_without_echoing_label_or_candidate():
    private_candidate = "private-person@example.test"
    with pytest.raises(DetectorContractError) as error:
        execute_adapter(adapter=lambda _: adapter_result({"UNKNOWN_PRIVATE_LABEL": 1}, 1, 1),
                        candidate=private_candidate, identity=identity(), mapper=mapper())
    assert private_candidate not in str(error.value)
    assert "UNKNOWN_PRIVATE_LABEL" not in str(error.value)


def test_adapter_exception_and_invalid_return_are_safe_and_do_not_leak_source():
    secret = "private-password=fictional"
    def broken(_):
        raise RuntimeError(secret)
    with pytest.raises(DetectorContractError) as error:
        execute_adapter(adapter=broken, candidate=secret, identity=identity(), mapper=mapper())
    assert str(error.value) == "Detector execution failed."
    with pytest.raises(DetectorContractError) as error:
        execute_adapter(adapter=lambda _: {"snippet": secret}, candidate=secret, identity=identity(), mapper=mapper())
    assert secret not in str(error.value)


@pytest.mark.parametrize("result", [
    adapter_result({}, total_units=1, attempted_units=0),
])
def test_evidence_repr_and_record_have_no_candidate_or_snippet(result):
    candidate = {"email": "private-person@example.test"}
    evidence = execute_adapter(adapter=lambda _: result, candidate=candidate, identity=identity(), mapper=mapper())
    assert "private-person@example.test" not in repr(evidence)
    assert "private-person@example.test" not in str(evidence.to_record())
    assert "snippet" not in repr(evidence)


@pytest.mark.parametrize("factory", [
    lambda: adapter_result({"EMAIL": True}, 1, 1),
    lambda: adapter_result({"bad label": 1}, 1, 1),
    lambda: adapter_result({}, 0, 0),
    lambda: adapter_result({}, 2, 1, 2),
    lambda: adapter_result({}, 1, 2),
    lambda: TaxonomyMapper.create({"EMAIL": "NOT_A_CATEGORY"}),
    lambda: TaxonomyMapper.create({}),
])
def test_invalid_counts_labels_mappings_and_coverage_are_rejected(factory):
    with pytest.raises(DetectorContractError):
        factory()


def test_canonical_config_rejects_unicode_nonfinite_cycles_and_oversize_safely():
    cycle = {}
    cycle["cycle"] = cycle
    for value in ({"value": "\ud800"}, {"value": float("nan")}, cycle, {"value": "x" * 70_000}):
        with pytest.raises(DetectorContractError) as error:
            canonical_configuration(value)
        assert str(error.value) == "Invalid detector contract."


def test_direct_construction_checks_identity_mapper_and_evidence_ordering():
    item = identity()
    with pytest.raises(DetectorContractError):
        DetectorIdentity("Bad Case", "v1", item.config_digest)
    mapping = mapper()
    with pytest.raises(DetectorContractError):
        TaxonomyMapper((("EMAIL", "PII"), ("EMAIL", "PAYMENT")))
    with pytest.raises(DetectorContractError) as error:
        TaxonomyMapper((("EMAIL", "PII"), object()))
    assert str(error.value) == "Invalid detector contract."
    coverage = Coverage.from_result(adapter_result({}, 1, 1))
    with pytest.raises(DetectorContractError):
        Coverage(1, 1, 0, 1, 0, CoverageStatus.COMPLETE, ASSESSED, ABSTAINED)
    with pytest.raises(DetectorContractError):
        DetectorEvidence(item, mapping.digest, ASSESSED, (AggregateFinding("PII", 1), AggregateFinding("CREDENTIAL", 1)), coverage)


def test_evidence_digest_changes_with_identity_mapping_or_coverage_not_raw_candidate():
    result = adapter_result({"EMAIL": 1}, total_units=2, attempted_units=2)
    first = normalize_result(identity=identity(), mapper=mapper(), result=result)
    second = normalize_result(identity=DetectorIdentity.from_configuration(detector_id="rules-adapter", version="v2", configuration={}), mapper=mapper(), result=result)
    assert first.digest != second.digest
    assert first.mapping_digest == mapper().digest


def test_complete_requires_all_taxonomy_categories_explicitly_assessed():
    # A full unit scan with only three detector families is visible PARTIAL,
    # not silently treated as clean coverage for the other policy families.
    partial = adapter_result({}, total_units=2, attempted_units=2)
    assert Coverage.from_result(partial).status is CoverageStatus.PARTIAL
    full_mapper = TaxonomyMapper.create({
        "EMAIL": "PII", "CARD": "PAYMENT", "TOKEN": "CREDENTIAL",
        "DIAGNOSIS": "HEALTH_SENSITIVE", "PROJECT": "BUSINESS_CONFIDENTIAL",
        "POSTCODE": "QUASI_IDENTIFIER",
    })
    full = adapter_result({}, total_units=2, attempted_units=2,
                          assessed_categories=TAXONOMY_CATEGORIES,
                          abstained_categories=frozenset())
    evidence = normalize_result(identity=identity(), mapper=full_mapper, result=full)
    assert evidence.coverage.status is CoverageStatus.COMPLETE
    assert evidence.mapped_categories == TAXONOMY_CATEGORIES


def test_missing_or_inconsistent_category_coverage_fails_closed():
    # Every policy family must be declared assessed or abstained.
    with pytest.raises(DetectorContractError):
        AdapterResult({}, 1, 1, frozenset({"PII"}), 0, frozenset())
    # A mapper cannot claim fewer/more families than the adapter says it
    # assessed, even if no sensitive values were found in this candidate.
    with pytest.raises(DetectorContractError):
        normalize_result(identity=identity(), mapper=mapper(), result=adapter_result(
            {}, 1, 1, assessed_categories=frozenset({"PII"}),
            abstained_categories=TAXONOMY_CATEGORIES - frozenset({"PII"}),
        ))


def test_coverage_declaration_is_bound_into_evidence_digest():
    first = normalize_result(identity=identity(), mapper=mapper(), result=adapter_result({}, 2, 2))
    altered = adapter_result({}, 2, 2, assessed_categories=frozenset({"PII", "PAYMENT", "CREDENTIAL"}),
                             abstained_categories=ABSTAINED)
    second = normalize_result(identity=identity(), mapper=mapper(), result=altered)
    assert first.digest == second.digest  # Same explicit coverage has same canonical evidence identity.
    full_mapper = TaxonomyMapper.create({
        "EMAIL": "PII", "CARD": "PAYMENT", "TOKEN": "CREDENTIAL",
        "HEALTH": "HEALTH_SENSITIVE", "BII": "BUSINESS_CONFIDENTIAL", "ZIP": "QUASI_IDENTIFIER",
    })
    full = normalize_result(identity=identity(), mapper=full_mapper, result=adapter_result(
        {}, 2, 2, assessed_categories=TAXONOMY_CATEGORIES, abstained_categories=frozenset(),
    ))
    assert first.digest != full.digest
