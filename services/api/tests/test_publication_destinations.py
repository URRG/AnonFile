"""M44b pure server-owned destination registry regressions."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import secrets

import pytest

from app.publication_destinations import (PublicationDestination,
                                          PublicationDestinationError,
                                          PublicationDestinationRegistry)


NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def destination(**overrides) -> PublicationDestination:
    values = dict(
        application_tenant="tenant-a", tenant_ref=opaque("tenantref:v1:"),
        destination_ref=opaque("destinationref:v1:"), recipient_label="buyer-a",
        purpose_code="model_training", contract_digest="sha256:" + "a" * 64,
        metadata_kind="release_artifact", key_ref="keyref:v1:release-key", version=1,
        not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(days=1), status="ACTIVE")
    values.update(overrides)
    return PublicationDestination(**values)


def test_resolves_an_active_exact_tenant_destination_and_hidden_recipient_is_digest_bound():
    item = destination()
    registry = PublicationDestinationRegistry((item,))

    assert registry.resolve(application_tenant="tenant-a", destination_ref=item.destination_ref, at=NOW) == item
    assert registry.tenant_ref_for(application_tenant="tenant-a") == item.tenant_ref
    assert "buyer-a" not in repr(item)
    assert "buyer-a" not in repr(registry)
    assert item.digest.startswith("sha256:")
    assert replace(item, recipient_label="buyer-b").digest != item.digest
    with pytest.raises(TypeError):
        registry._by_destination[item.destination_ref] = item  # type: ignore[index]
    with pytest.raises(TypeError):
        registry._tenant_refs["tenant-a"] = item.tenant_ref  # type: ignore[index]
    with pytest.raises(AttributeError):
        registry._by_destination = {}  # type: ignore[misc]


def test_cross_tenant_and_unknown_destination_fail_closed():
    item = destination()
    registry = PublicationDestinationRegistry((item,))

    with pytest.raises(PublicationDestinationError):
        registry.resolve(application_tenant="tenant-b", destination_ref=item.destination_ref, at=NOW)
    with pytest.raises(PublicationDestinationError):
        registry.resolve(application_tenant="tenant-a", destination_ref=opaque("destinationref:v1:"), at=NOW)
    with pytest.raises(PublicationDestinationError):
        registry.tenant_ref_for(application_tenant="tenant-b")


def test_duplicate_destination_and_ambiguous_application_to_pg_tenant_mapping_fail_closed():
    item = destination()
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry((item, item))
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry((item, replace(item, destination_ref=opaque("destinationref:v1:"),
                                                       tenant_ref=opaque("tenantref:v1:"))))
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry((item, destination(application_tenant="tenant-b",
                                                           tenant_ref=item.tenant_ref)))
    compatible = replace(item, destination_ref=opaque("destinationref:v1:"), version=2)
    assert PublicationDestinationRegistry((item, compatible)).resolve(
        application_tenant="tenant-a", destination_ref=compatible.destination_ref, at=NOW) == compatible


@pytest.mark.parametrize("replacement", (
    {"status": "INACTIVE"},
    {"not_before": NOW + timedelta(seconds=1)},
    {"expires_at": NOW},
))
def test_inactive_or_outside_window_destination_does_not_resolve(replacement):
    item = destination(**replacement)
    registry = PublicationDestinationRegistry((item,))
    with pytest.raises(PublicationDestinationError):
        registry.resolve(application_tenant="tenant-a", destination_ref=item.destination_ref, at=NOW)


@pytest.mark.parametrize("replacement", (
    {"application_tenant": "Tenant A"},
    {"tenant_ref": "tenant-a"},
    {"destination_ref": "destinationref:v1:short"},
    {"recipient_label": "buyer label"},
    {"contract_digest": "sha256:" + "A" * 64},
    {"metadata_kind": "ReleaseArtifact"},
    {"key_ref": "keyref:v1:Bad"},
    {"version": 0},
    {"output_profile": "jsonl-utf8-v1"},
    {"status": "active"},
    {"status": []},
    {"output_profile": []},
))
def test_shape_and_profile_validation_fail_closed(replacement):
    with pytest.raises(PublicationDestinationError):
        destination(**replacement)


def test_registry_requires_a_bounded_tuple_of_server_provisioned_profiles():
    item = destination()
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry([item])  # type: ignore[arg-type]
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry(())
    with pytest.raises(PublicationDestinationError):
        PublicationDestinationRegistry(tuple(destination() for _ in range(65)))
