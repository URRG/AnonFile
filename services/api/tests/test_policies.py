import pytest

from app.policies import (PolicyError, PolicyProfile, PolicyRegistry, PolicyRule,
                          TAXONOMY_CATEGORIES, default_registry)


def profile(*, version="v1", rules=(PolicyRule("PII", "suppress", 20), PolicyRule("CREDENTIAL", "block", 0))):
    return PolicyProfile("example", version, ("external_anonymized",), ("text", "json"), ("en", "und"), rules)


def test_canonical_digest_ignores_equivalent_authoring_order():
    first = PolicyRegistry((profile(),)).resolve("example-v1")
    second = PolicyRegistry((profile(rules=(PolicyRule("CREDENTIAL", "block", 0), PolicyRule("PII", "suppress", 20))),)).resolve("example-v1")
    assert first.digest == second.digest
    assert first.digest.startswith("sha256:")


def test_sealed_snapshot_is_immutable_and_manifest_is_detached():
    snapshot = PolicyRegistry((profile(),)).resolve("example-v1")
    with pytest.raises((AttributeError, TypeError)):
        snapshot.digest = "sha256:tampered"
    with pytest.raises(TypeError):
        snapshot.manifest()["digest"] = "sha256:tampered"
    assert snapshot.rule_for("PII").action == "suppress"


def test_policy_version_collision_cannot_replace_a_sealed_snapshot():
    registry = PolicyRegistry((profile(),))
    assert registry.register(profile()).digest == registry.resolve("example-v1").digest
    with pytest.raises(PolicyError):
        registry.register(profile(rules=(PolicyRule("PII", "block", 0),)))
    assert registry.resolve("example-v1").rule_for("PII").action == "suppress"


@pytest.mark.parametrize("format,language", [("pdf", "en"), ("text", "fr"), ("TEXT", "en"), ("text", "en-US")])
def test_unknown_format_or_language_fails_closed(format, language):
    snapshot = PolicyRegistry((profile(),)).resolve("example-v1")
    assert not snapshot.supports(release_mode="external_anonymized", format=format, language=language)
    with pytest.raises(PolicyError) as error:
        snapshot.require_support(release_mode="external_anonymized", format=format, language=language)
    assert str(error.value) == "Unsupported policy configuration"


def test_unknown_or_uncovered_categories_fail_closed():
    snapshot = PolicyRegistry((profile(),)).resolve("example-v1")
    for category in ("NOT_A_CATEGORY", "HEALTH_SENSITIVE"):
        with pytest.raises(PolicyError):
            snapshot.rule_for(category)
    with pytest.raises(PolicyError):
        snapshot.effective_rule(("PII", "NOT_A_CATEGORY"))


def test_rule_precedence_is_numeric_then_category_not_input_order():
    snapshot = PolicyRegistry((profile(rules=(PolicyRule("PII", "suppress", 10), PolicyRule("CREDENTIAL", "block", 10))),)).resolve("example-v1")
    assert snapshot.effective_rule(("PII", "CREDENTIAL")).category == "CREDENTIAL"
    assert snapshot.effective_rule(("CREDENTIAL", "PII")).category == "CREDENTIAL"


def test_cross_version_profiles_remain_distinct_and_resolvable():
    registry = PolicyRegistry((profile(version="v1"), profile(version="v2", rules=(PolicyRule("PII", "generalize", 1),))))
    assert registry.keys() == ("example-v1", "example-v2")
    assert registry.resolve("example-v1").digest != registry.resolve("example-v2").digest
    assert registry.resolve("example-v1").rule_for("PII").action == "suppress"
    assert registry.resolve("example-v2").rule_for("PII").action == "generalize"


def test_default_registry_preserves_legacy_labels_and_explicit_taxonomy():
    registry = default_registry()
    assert set(registry.keys()) == {"baseline-v1", "external-release-v1", "restricted-pseudonymized-v1"}
    snapshot = registry.resolve("external-release-v1")
    assert snapshot.supports(release_mode="external_anonymized", format="csv", language="und")
    assert not snapshot.supports(release_mode="restricted_pseudonymized", format="csv", language="und")
    assert {rule.category for rule in snapshot.rules} == TAXONOMY_CATEGORIES


@pytest.mark.parametrize("bad", [
    lambda: PolicyRule("PII", "delete"),
    lambda: PolicyRule("unknown", "suppress"),
    lambda: PolicyRule("PII", "suppress", True),
    lambda: PolicyProfile("bad key", "v1", ("external_anonymized",), ("text",), ("en",), (PolicyRule("PII", "suppress"),)),
    lambda: PolicyProfile("valid", "v1", ("external_anonymized",), ("xml",), ("en",), (PolicyRule("PII", "suppress"),)),
    lambda: PolicyProfile("valid", "v1", ("external_anonymized",), ("text",), ("english",), (PolicyRule("PII", "suppress"),)),
])
def test_malformed_policy_configuration_has_safe_error(bad):
    with pytest.raises(PolicyError) as error:
        bad()
    assert str(error.value) == "Unsupported policy configuration"
