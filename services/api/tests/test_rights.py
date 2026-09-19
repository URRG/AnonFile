from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.rights import (
    AuthorizationStatus,
    GateReason,
    RightsError,
    RightsProfile,
    evaluate_rights,
    request_authorization,
    require_independent_reviewer,
    resolve_rights,
)


NOW = datetime(2030, 1, 1, 12, 0, tzinfo=UTC)
ARTIFACT = "a" * 64
POLICY = "b" * 64


def profile(**overrides):
    values = {
        "profile_id": "supplier-1",
        "version": "2029.12",
        "permitted_purposes": ["model-training", "evaluation"],
        "permitted_recipients": ["openai", "buyer-2"],
        "expires_at": NOW + timedelta(days=30),
        "resale_allowed": True,
    }
    values.update(overrides)
    return RightsProfile.create(**values)


def test_profile_digest_is_canonical_across_order_and_timezone():
    first = profile(permitted_purposes=["evaluation", "model-training"], expires_at=NOW.astimezone(timezone(timedelta(hours=5, minutes=30))) + timedelta(days=30))
    second = profile(permitted_purposes=["model-training", "evaluation"])
    assert first.digest == second.digest
    assert first.to_record()["expires_at"].endswith("Z")


@pytest.mark.parametrize("kwargs", [
    {"permitted_purposes": ["model-training", "MODEL-TRAINING"]},
    {"permitted_recipients": ["*"]},
    {"permitted_recipients": "openai"},
    {"profile_id": "has space"},
    {"expires_at": datetime(2030, 1, 2)},
    {"resale_allowed": 1},
])
def test_profile_rejects_ambiguous_rights_metadata(kwargs):
    with pytest.raises(RightsError):
        profile(**kwargs)


def test_serialized_record_detects_tampering_without_echoing_content():
    record = profile().to_record()
    record["permitted_recipients"] = ["attacker"]
    with pytest.raises(RightsError, match="integrity"):
        RightsProfile.from_record(record)


def test_exact_access_gate_denies_unknown_expired_and_unlisted_values():
    current = profile()
    registry = {current.profile_id: current}
    assert resolve_rights(registry, profile_id="missing", purpose="evaluation", recipient="openai", at=NOW).reason == GateReason.RIGHTS_UNKNOWN
    assert evaluate_rights(current, purpose="other", recipient="openai", at=NOW).reason == GateReason.PURPOSE_DENIED
    assert evaluate_rights(current, purpose="evaluation", recipient="buyer-3", at=NOW).reason == GateReason.RECIPIENT_DENIED
    assert evaluate_rights(profile(expires_at=NOW), purpose="evaluation", recipient="openai", at=NOW).reason == GateReason.RIGHTS_EXPIRED


def test_wildcard_request_is_rejected_not_interpreted():
    with pytest.raises(RightsError, match="Invalid rights request"):
        evaluate_rights(profile(), purpose="evaluation", recipient="openai*", at=NOW)


def test_resale_gate_is_separate_and_fail_closed():
    no_resale = profile(resale_allowed=False)
    assert evaluate_rights(no_resale, purpose="evaluation", recipient="openai", at=NOW).reason == GateReason.RESALE_DENIED
    assert evaluate_rights(no_resale, purpose="evaluation", recipient="openai", at=NOW, for_resale=False).allowed


def test_request_binds_exact_artifact_policy_and_rights_digest_and_never_approves():
    current = profile()
    pending = request_authorization(
        {current.profile_id: current}, request_id="request-1", profile_id=current.profile_id,
        artifact_digest=ARTIFACT, policy_digest=POLICY, rights_digest=current.digest,
        buyer="openai", purpose="evaluation", at=NOW,
    )
    assert pending.status is AuthorizationStatus.PENDING
    assert pending.rights_digest == current.digest
    assert pending.to_record()["artifact_digest"] == ARTIFACT
    assert pending.to_record()["policy_digest"] == POLICY
    assert set(AuthorizationStatus) == {AuthorizationStatus.PENDING, AuthorizationStatus.DENIED}


@pytest.mark.parametrize("rights_digest", [None, "c" * 64])
def test_request_denies_stale_or_substituted_rights_digest(rights_digest):
    current = profile()
    result = request_authorization(
        {current.profile_id: current}, request_id="request-1", profile_id=current.profile_id,
        artifact_digest=ARTIFACT, policy_digest=POLICY, rights_digest=rights_digest,
        buyer="openai", purpose="evaluation", at=NOW,
    )
    assert result.status is AuthorizationStatus.DENIED
    assert result.reason is GateReason.RIGHTS_UNKNOWN


def test_denied_request_keeps_non_authorizing_record_for_expired_rights():
    current = profile(expires_at=NOW)
    result = request_authorization(
        {current.profile_id: current}, request_id="request-2", profile_id=current.profile_id,
        artifact_digest=ARTIFACT, policy_digest=POLICY, rights_digest=current.digest,
        buyer="openai", purpose="evaluation", at=NOW,
    )
    assert result.status is AuthorizationStatus.DENIED
    assert result.reason is GateReason.RIGHTS_EXPIRED


def test_independent_reviewer_requires_distinct_normalized_subjects():
    with pytest.raises(RightsError, match="Independent reviewer"):
        require_independent_reviewer(creator_subject="reviewer-1", reviewer_subject="reviewer-1")
    require_independent_reviewer(creator_subject="creator-1", reviewer_subject="reviewer-1")
