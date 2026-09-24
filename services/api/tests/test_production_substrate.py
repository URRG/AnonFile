"""Adversarial tests for the M22 metadata-only production substrate contract."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.production_substrate import (ControlPlaneMetadata, EncryptedObjectReference,
    LeasedWorkerClaim, ProductionSubstrateContractError, TenantMetadataTransaction,
    validate_adapter_declaration)


TENANT = "tenantref:v1:" + "A" * 43
OBJECT = "objectref:v1:" + "B" * 43
RECORD = "metarecord:v1:" + "C" * 43
OTHER_RECORD = "metarecord:v1:" + "D" * 43
TX = "metatx:v1:" + "E" * 43
WORK = "workref:v1:" + "F" * 43
CLAIM = "workerclaim:v1:" + "G" * 43
OLD_CLAIM = "workerclaim:v1:" + "H" * 43
WORKER = "workerref:v1:" + "I" * 43
NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)


def fails(constructor, *args, **kwargs):
    with pytest.raises(ProductionSubstrateContractError):
        constructor(*args, **kwargs)


def reference(**changes):
    return EncryptedObjectReference(TENANT, OBJECT, "keyref:v1:production-data-key",
                                    "sha256:" + "a" * 64, 77, **changes)


def record(**changes):
    fields = dict(tenant_ref=TENANT, record_id=RECORD, kind="processing_run", version=1,
                  attributes={"policy_digest": "sha256:" + "b" * 64}, encrypted_object=reference())
    fields.update(changes)
    return ControlPlaneMetadata(**fields)


def declaration():
    return {"schema": "anonflow-production-substrate-v1", "adapter_id": "future.pg-object-queue",
            "capabilities": {"atomic_tenant_metadata_transactions": True, "durable_metadata_commit": True,
                             "tenant_isolation": True, "encrypted_object_references": True,
                             "no_control_plane_bytes": True, "leased_at_least_once_claims": True,
                             "compare_and_swap_claims": True, "expired_lease_reclaim": True}}


def test_metadata_record_allows_only_opaque_encrypted_reference_and_safe_metadata():
    item = record()
    assert item.encrypted_object.object_ref == OBJECT
    assert item.attributes["policy_digest"].startswith("sha256:")
    fails(EncryptedObjectReference, TENANT, "s3://bucket/candidate", "keyref:v1:key", "sha256:" + "a" * 64, 1)
    fails(lambda: record(encrypted_object=replace(reference(), tenant_ref="tenantref:v1:" + "Z" * 43)))


def test_validated_metadata_and_expected_versions_cannot_be_mutated_after_construction():
    attributes = {"policy_digest": "sha256:" + "b" * 64}
    versions = {RECORD: 1}
    item = record(attributes=attributes)
    transaction = TenantMetadataTransaction(TENANT, TX, versions, (item,))
    attributes["source"] = "raw source"; versions[RECORD] = 0
    assert dict(item.attributes) == {"policy_digest": "sha256:" + "b" * 64}
    assert dict(transaction.expected_versions) == {RECORD: 1}
    with pytest.raises(TypeError):
        item.attributes["source"] = "raw source"


@pytest.mark.parametrize("attributes", [
    {"raw": "text"}, {"candidate": "text"}, {"payload_bytes": "encoded"},
    {"nested": {"ciphertext": "encoded"}}, {"digest": b"source bytes"},
    {"business_label": "unbounded source-like text"},
    {"email_digest": "sha256:" + "a" * 64},
])
def test_control_plane_records_fail_closed_on_raw_or_candidate_byte_bearing_fields(attributes):
    fails(lambda: record(attributes=attributes))


def test_tenant_transaction_is_bounded_tenant_scoped_and_uses_explicit_versions():
    transaction = TenantMetadataTransaction(TENANT, TX, {RECORD: 1}, (record(),))
    assert transaction.expected_versions == {RECORD: 1}
    fails(TenantMetadataTransaction, TENANT, TX, {RECORD: True}, (record(),))
    fails(TenantMetadataTransaction, TENANT, TX, {}, (record(), record(record_id=RECORD)))
    fails(TenantMetadataTransaction, TENANT, TX, {}, (record(),))
    other_tenant = "tenantref:v1:" + "Z" * 43
    foreign = record(tenant_ref=other_tenant, encrypted_object=replace(reference(), tenant_ref=other_tenant))
    fails(TenantMetadataTransaction, TENANT, TX, {RECORD: 0}, (foreign,))


def test_transaction_writes_are_an_immutable_exact_tuple_and_every_write_has_a_cas_version():
    writes = [record()]
    fails(TenantMetadataTransaction, TENANT, TX, {RECORD: 0}, writes)
    transaction = TenantMetadataTransaction(TENANT, TX, {RECORD: 0}, tuple(writes))
    writes.append(record(record_id=OTHER_RECORD))
    assert tuple(item.record_id for item in transaction.writes) == (RECORD,)
    fails(TenantMetadataTransaction, TENANT, TX, {RECORD: 0, OTHER_RECORD: 0}, (record(),))


def test_worker_claim_is_fenced_bounded_and_records_reclaim_as_new_claim():
    claim = LeasedWorkerClaim(TENANT, WORK, CLAIM, WORKER, 2, 9, NOW, NOW + timedelta(minutes=5), OLD_CLAIM)
    assert claim.lease_epoch == 9 and claim.delivery_attempt == 2
    fails(LeasedWorkerClaim, TENANT, WORK, CLAIM, WORKER, 1, 9, NOW, NOW + timedelta(minutes=5), OLD_CLAIM)
    fails(LeasedWorkerClaim, TENANT, WORK, CLAIM, WORKER, 2, 9, NOW, NOW + timedelta(hours=2), OLD_CLAIM)
    fails(LeasedWorkerClaim, TENANT, WORK, CLAIM, WORKER, 2, 9, NOW, NOW + timedelta(minutes=5), CLAIM)


@pytest.mark.parametrize("mutate", [
    lambda value: value.pop("capabilities"),
    lambda value: value["capabilities"].update({"unknown": True}),
    lambda value: value["capabilities"].__setitem__("tenant_isolation", False),
    lambda value: value.__setitem__("driver", "postgres"),
])
def test_adapter_declaration_rejects_missing_extra_or_false_capabilities(mutate):
    value = declaration(); mutate(value)
    fails(validate_adapter_declaration, value)


def test_adapter_declaration_has_no_implicit_production_enablement():
    accepted = validate_adapter_declaration(declaration())
    assert accepted["adapter_id"] == "future.pg-object-queue"
