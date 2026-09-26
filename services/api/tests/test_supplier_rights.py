"""M48a exact-scope supplier rights assertion tests."""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.postgres_trusted_signing_keys import (
    PostgresTrustedSigningKeyAuthority,
    PostgresTrustedSigningKeyError,
    TrustedSigningKey,
)
from app.supplier_rights import SupplierRightsAssertion, SupplierRightsError, SupplierRightsVerifier


NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def public_key(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes_raw()
    return "ed25519pub:v1:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def signature(private: Ed25519PrivateKey, assertion: SupplierRightsAssertion) -> str:
    raw = private.sign(
        b"anonflow-supplier-rights-statement:v1:\x00"
        + json.dumps(assertion.canonical(), ensure_ascii=True, allow_nan=False,
                     sort_keys=True, separators=(",", ":")).encode("ascii"))
    return "supplier-rights-sig:v1:" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def assertion_values() -> dict[str, object]:
    return {
        "tenant_ref": opaque("tenantref:v1:"),
        "supplier_actor_ref": opaque("actorref:v1:"),
        "supplier_key_ref": opaque("signingkeyref:v1:"),
        "supplier_org_ref": opaque("supplierorgref:v1:"),
        "source_dataset_ref": opaque("supplierdatasetref:v1:"),
        "source_dataset_digest": "sha256:" + secrets.token_hex(32),
        "custody_ref": opaque("custodyref:v1:"),
        "custody_intent_digest": "sha256:" + secrets.token_hex(32),
        "buyer_org_ref": opaque("buyerorgref:v1:"),
        "recipient_ref": opaque("recipientref:v1:"),
        "purpose_code": "fraud-model-evaluation",
        "processing_mode": "secure-enclave",
        "onward_transfer_permitted": False,
        "contract_ref": opaque("suppliercontractref:v1:"),
        "contract_digest": "sha256:" + secrets.token_hex(32),
        "issued_at": NOW - timedelta(minutes=1),
        "not_before": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
        "nonce": opaque("supplierrightsnonce:v1:"),
    }


def signed_assertion(private: Ed25519PrivateKey, **changes: object) -> SupplierRightsAssertion:
    values = assertion_values()
    values.update(changes)
    placeholder = "supplier-rights-sig:v1:" + base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("=")
    unsigned = SupplierRightsAssertion(**values, signature=placeholder)
    return SupplierRightsAssertion(**values, signature=signature(private, unsigned))


def trusted(assertion: SupplierRightsAssertion, private: Ed25519PrivateKey, **changes: object) -> TrustedSigningKey:
    values = {
        "tenant_ref": assertion.tenant_ref,
        "actor_ref": assertion.supplier_actor_ref,
        "key_ref": assertion.supplier_key_ref,
        "role": "SUPPLIER_RIGHTS_ATTESTER",
        "public_key": public_key(private),
        "not_before": NOW - timedelta(minutes=2),
        "expires_at": NOW + timedelta(minutes=6),
    }
    values.update(changes)
    return TrustedSigningKey(**values)


def test_verifier_binds_every_exact_scope_field_and_is_not_a_release_grant():
    private = Ed25519PrivateKey.generate()
    statement = signed_assertion(private)
    assert SupplierRightsVerifier().verify(statement, trusted_key=trusted(statement, private), at=NOW)
    assert statement.to_record()["schema"] == "supplier-rights-statement-ed25519-v1"
    assert "release" not in statement.to_record()


@pytest.mark.parametrize("field, replacement", (
    ("tenant_ref", opaque("tenantref:v1:")),
    ("supplier_actor_ref", opaque("actorref:v1:")),
    ("supplier_key_ref", opaque("signingkeyref:v1:")),
    ("supplier_org_ref", opaque("supplierorgref:v1:")),
    ("source_dataset_ref", opaque("supplierdatasetref:v1:")),
    ("source_dataset_digest", "sha256:" + "0" * 64),
    ("custody_ref", opaque("custodyref:v1:")),
    ("custody_intent_digest", "sha256:" + "2" * 64),
    ("buyer_org_ref", opaque("buyerorgref:v1:")),
    ("recipient_ref", opaque("recipientref:v1:")),
    ("purpose_code", "another-purpose"),
    ("processing_mode", "uncontrolled-copy"),
    ("contract_ref", opaque("suppliercontractref:v1:")),
    ("contract_digest", "sha256:" + "1" * 64),
    ("issued_at", NOW - timedelta(seconds=90)),
    ("not_before", NOW),
    ("expires_at", NOW + timedelta(minutes=4)),
    ("nonce", opaque("supplierrightsnonce:v1:")),
))
def test_signature_rejects_scope_drift(field, replacement):
    private = Ed25519PrivateKey.generate()
    statement = signed_assertion(private)
    changed = {name: getattr(statement, name) for name in statement.__dataclass_fields__ if name not in {"digest", "signature"}}
    changed[field] = replacement
    forged = SupplierRightsAssertion(**changed, signature=statement.signature)
    assert not SupplierRightsVerifier().verify(forged, trusted_key=trusted(statement, private), at=NOW)


def test_verifier_requires_exact_supplier_registry_identity_role_key_window_and_signature():
    private = Ed25519PrivateKey.generate()
    statement = signed_assertion(private)
    verifier = SupplierRightsVerifier()
    assert not verifier.verify(statement, trusted_key=trusted(statement, private, role="SERVICE_ISSUER"), at=NOW)
    assert not verifier.verify(statement, trusted_key=trusted(statement, private, actor_ref=opaque("actorref:v1:")), at=NOW)
    assert not verifier.verify(statement, trusted_key=trusted(statement, private, expires_at=NOW), at=NOW)
    assert not verifier.verify(statement, trusted_key=trusted(statement, Ed25519PrivateKey.generate()), at=NOW)
    assert not verifier.verify(statement, trusted_key=object(), at=NOW)


def test_statement_rejects_wildcards_raw_contract_text_and_invalid_time_order():
    private = Ed25519PrivateKey.generate()
    with pytest.raises(SupplierRightsError):
        signed_assertion(private, purpose_code="*")
    with pytest.raises(SupplierRightsError):
        signed_assertion(private, contract_ref="contract terms for Alice")
    with pytest.raises(SupplierRightsError):
        signed_assertion(private, onward_transfer_permitted=True)
    with pytest.raises(SupplierRightsError):
        signed_assertion(private, not_before=NOW - timedelta(minutes=2), issued_at=NOW - timedelta(minutes=1))
    with pytest.raises(SupplierRightsError):
        signed_assertion(private, expires_at=NOW + timedelta(days=32))
    with pytest.raises(PostgresTrustedSigningKeyError):
        trusted(signed_assertion(private), private, role="*")


@pytest.fixture
def postgres_supplier_role_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = Path(__file__).parents[1] / "migrations"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute((migrations / "014_m47_trusted_signing_keys.sql").read_text(encoding="utf-8"))
        migration = (migrations / "015_m48a_supplier_rights_attester.sql").read_text(encoding="utf-8")
        connection.execute(migration)
        connection.execute(migration)
    return dsn, psycopg, PostgresTrustedSigningKeyAuthority(
        lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_migration_preserves_closed_roles_and_allows_supplier_attester(
        postgres_supplier_role_authority):
    dsn, psycopg, authority = postgres_supplier_role_authority
    private = Ed25519PrivateKey.generate()
    statement = signed_assertion(private)
    item = trusted(
        statement,
        private,
        not_before=datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=1),
        expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5),
    )
    assert authority.create(item).state == "ACTIVE"
    with psycopg.connect(dsn, autocommit=True) as connection:
        definition = connection.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='anonflow_trusted_signing_keys'::regclass "
            "AND conname='anonflow_trusted_signing_keys_role_m48a_check'").fetchone()
        assert definition is not None
        assert "SUPPLIER_RIGHTS_ATTESTER" in definition[0]
        with pytest.raises(psycopg.errors.CheckViolation):
            connection.execute(
                "INSERT INTO anonflow_trusted_signing_keys "
                "(tenant_ref,actor_ref,key_ref,role,public_key,not_before,expires_at) "
                "VALUES (%s,%s,%s,'ANY_ROLE',%s,%s,%s)",
                (opaque("tenantref:v1:"), opaque("actorref:v1:"), opaque("signingkeyref:v1:"),
                 public_key(Ed25519PrivateKey.generate()), item.not_before, item.expires_at))
