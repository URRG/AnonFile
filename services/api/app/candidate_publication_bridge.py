"""Private M44a bridge from a verified candidate to exact publication bytes.

This is deliberately a byte-identity primitive, not an admission or signing
path.  Its caller must already have loaded and verified the live release case
and must supply a destination plan assembled by a server-owned workflow.
Neither an HTTP caller nor a worker can choose alternate release bytes,
re-serialize JSON, or select a serializer through this API.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from app.candidate import CandidateArtifact
from app.postgres_publication_intents import PublicationIntent, _plan_digest
from app.publication_payload_binding import (PublicationPayloadBinding,
                                             PublicationPayloadBindingError,
                                             payload_digest)
from app.release_case import ReleaseCaseBinding


class CandidatePublicationBridgeError(ValueError):
    """Fixed fail-closed result which never reflects candidate bytes."""

    def __init__(self) -> None:
        super().__init__("candidate publication bridge unavailable")


def _fail() -> None:
    raise CandidatePublicationBridgeError() from None


@dataclass(frozen=True, slots=True)
class ExactCandidatePublication:
    """Exact candidate encoding and the M42 binding derived from it.

    ``_payload`` remains representation-safe and is only retrievable through
    the explicitly named private-worker handoff.  This value confers neither
    approval nor an object-store/delivery capability.
    """

    binding: PublicationPayloadBinding
    _payload: bytes = field(repr=False, compare=True)

    def __post_init__(self) -> None:
        if type(self.binding) is not PublicationPayloadBinding or type(self._payload) is not bytes:
            _fail()
        if (self.binding.serialization_id != "binary-v1"
                or self.binding.payload_size_bytes != len(self._payload)
                or self.binding.payload_digest != payload_digest(self._payload)):
            _fail()

    def bytes_for_private_worker(self) -> bytes:
        """Return a detached exact payload only within a trusted worker stage."""
        return bytes(self._payload)


def derive_exact_candidate_publication(*, candidate: object, case_binding: object,
                                       intent: object) -> ExactCandidatePublication:
    """Derive an M42 binding from the candidate's original canonical bytes.

    This function intentionally takes no payload, digest, size, serializer, or
    object-store input from the caller.  The release case must have been
    verified and the intent must have been constructed by a server-owned
    destination workflow before this private bridge is called.
    """
    if (type(candidate) is not CandidateArtifact or type(case_binding) is not ReleaseCaseBinding
            or type(intent) is not PublicationIntent):
        _fail()
    try:
        metadata = candidate.metadata
        if (metadata.artifact_digest != case_binding.candidate_artifact_digest
                or metadata.run_id != case_binding.processing_run_id
                or metadata.policy_digest != case_binding.processing_policy_digest
                or intent.request_digest != case_binding.processing_request_digest
                or intent.policy_digest != case_binding.processing_policy_digest):
            _fail()
        # CandidateArtifact validates this stored encoding at construction. Do
        # not materialize and re-encode: JSON spelling/order is release scope.
        payload = candidate._encoded
        if (len(payload) != metadata.byte_count
                or "sha256:" + hashlib.sha256(payload).hexdigest() != metadata.artifact_digest):
            _fail()
        binding = PublicationPayloadBinding.create(
            tenant_ref=intent.tenant_ref, publication_ref=intent.publication_ref,
            object_ref=intent.object_ref, key_ref=intent.key_ref,
            plan_digest=_plan_digest(intent), payload_digest=payload_digest(payload),
            payload_size_bytes=len(payload), serialization_id="binary-v1")
        return ExactCandidatePublication(binding=binding, _payload=payload)
    except (AttributeError, PublicationPayloadBindingError, ValueError, TypeError):
        _fail()
