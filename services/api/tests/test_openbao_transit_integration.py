"""Opt-in interoperability checks against a real, TLS-verified OpenBao server.

The CI harness supplies every value below for a disposable dev server.  This
test is deliberately skipped in ordinary unit-test runs: it never discovers a
server, creates a key, or accepts an unverified TLS connection on its own.
"""
from __future__ import annotations

import base64
import os

import pytest

from app.openbao_transit import (
    OpenBaoTransitConfig,
    OpenBaoTransitEd25519,
    OpenBaoTransitError,
    TransitEd25519Signature,
)


_REQUIRED = (
    "OPENBAO_TRANSIT_INTEGRATION",
    "OPENBAO_INTEGRATION_URL",
    "OPENBAO_INTEGRATION_TOKEN",
    "OPENBAO_INTEGRATION_SIGN_ONLY_TOKEN",
    "OPENBAO_INTEGRATION_PUBLIC_KEY",
    "OPENBAO_INTEGRATION_KEY_VERSION",
)


def _environment() -> dict[str, str]:
    values = {name: os.environ.get(name, "") for name in _REQUIRED}
    if values["OPENBAO_TRANSIT_INTEGRATION"] != "1":
        pytest.skip("set OPENBAO_TRANSIT_INTEGRATION=1 to enable live OpenBao checks")
    missing = [name for name, value in values.items() if not value]
    if missing:
        pytest.fail("OpenBao integration environment is incomplete: " + ", ".join(missing))
    return values


def test_real_openbao_transit_ed25519_sign_verify_and_policy_boundary():
    env = _environment()
    version = int(env["OPENBAO_INTEGRATION_KEY_VERSION"])
    client = OpenBaoTransitEd25519(
        OpenBaoTransitConfig(
            base_url=env["OPENBAO_INTEGRATION_URL"],
            mount_path="transit",
            key_name="m29-integration-ed25519",
            key_version=version,
            public_key=env["OPENBAO_INTEGRATION_PUBLIC_KEY"],
        )
    )
    message = b"m29 OpenBao Transit interoperability assertion"

    signature = client.sign(message=message, token=env["OPENBAO_INTEGRATION_TOKEN"])
    assert client.verify(message=message, signature=signature, token=env["OPENBAO_INTEGRATION_TOKEN"])

    # The adapter's pinned public-key check rejects a real Transit-issued
    # signature when it is presented for a different message.
    assert not client.verify(
        message=message + b" (forged)",
        signature=signature,
        token=env["OPENBAO_INTEGRATION_TOKEN"],
    )

    # A syntactically valid fabricated signature is rejected by the pinned
    # public-key check without treating any remote response as authoritative.
    forged = TransitEd25519Signature(
        "vault:v" + str(version) + ":" + base64.b64encode(bytes(64)).decode("ascii"),
        version,
    )
    assert not client.verify(message=message, signature=forged, token=env["OPENBAO_INTEGRATION_TOKEN"])

    # This second, short-lived token can read metadata but has no verify grant.
    # OpenBao must return a policy denial, which the adapter exposes only as its
    # fixed fail-closed error.
    with pytest.raises(OpenBaoTransitError, match="^verification unavailable$"):
        client.verify(message=message, signature=signature, token=env["OPENBAO_INTEGRATION_SIGN_ONLY_TOKEN"])
