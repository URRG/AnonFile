"""Observation-bound, non-remediating verification of a stale publication object.

This adapter intentionally cannot put, delete, finalize, acknowledge, claim, or
return a storage reference.  It records only a bounded result for one current
M41 observation lease after cryptographically authenticating the object outside
of database locks.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re
from typing import Any

from app.postgres_publication_intents import (_MAX_ROW_BYTES, _database_now, _decode,
                                               _decode_authorization, _decode_binding,
                                               _text)
from app.publication_authorization import (PinnedPublicationAuthorizationVerifier,
                                            PublicationAuthorizationAttestation)
from app.publication_payload_binding import PublicationPayloadBinding
from app.production_substrate import EncryptedObjectReference
from app.worker_encrypted_objects import WorkerEncryptedObjects


_TENANT = re.compile(r"tenantref:v1:[A-Za-z0-9_-]{43}\Z")
_PUBLICATION = re.compile(r"publicationref:v1:[A-Za-z0-9_-]{43}\Z")
_OBSERVATION = re.compile(r"observation:v1:[A-Za-z0-9_-]{43}\Z")
_OUTCOMES = frozenset({"VERIFIED", "NOT_VERIFIED"})


class PostgresPublicationVerificationError(RuntimeError):
    """Fixed failure that carries no provider error, object detail, or token."""

    def __init__(self) -> None:
        super().__init__("PostgreSQL publication verification unavailable")


def _fail() -> None:
    raise PostgresPublicationVerificationError() from None


def _epoch(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= 2**63 - 1:
        _fail()
    return value


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class PublicationObjectVerification:
    """A non-authorizing outcome for one M41 observation epoch."""

    tenant_ref: str
    publication_ref: str
    observation_epoch: int
    outcome: str
    recorded: bool
    actionable: bool = False

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.publication_ref, _PUBLICATION)
        _epoch(self.observation_epoch)
        if (self.outcome not in _OUTCOMES or type(self.recorded) is not bool
                or self.actionable is not False):
            _fail()


class PostgresPublicationObservationVerifier:
    """Verify only the object bound to a live, claim-free M41 observation.

    The lock order is intent, payload binding, authorization, observation,
    completion, then worker job.  Remote OpenBao/S3 work is deliberately
    between a short preflight read and this postflight transaction.
    """

    def __init__(self, connection_factory: Callable[[], Any],
                 encrypted_objects: WorkerEncryptedObjects,
                 authorization_verifier: PinnedPublicationAuthorizationVerifier) -> None:
        if (not callable(connection_factory) or type(encrypted_objects) is not WorkerEncryptedObjects
                or type(authorization_verifier) is not PinnedPublicationAuthorizationVerifier):
            _fail()
        self._connection_factory = connection_factory
        self._encrypted_objects = encrypted_objects
        self._authorization_verifier = authorization_verifier

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.cursor().execute("ROLLBACK")
        except Exception:
            pass

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    @staticmethod
    def _live_observation(cursor: Any, *, tenant_ref: str, publication_ref: str,
                          observation_epoch: int, observation_token: str,
                          lock: bool) -> bool:
        cursor.execute(
            "SELECT observation_epoch, observation_token, state, "
            "lease_expires_at > clock_timestamp() FROM anonflow_publication_observations "
            "WHERE tenant_ref=%s AND publication_ref=%s" + (" FOR UPDATE" if lock else ""),
            (tenant_ref, publication_ref))
        row = _row(cursor)
        return (row is not None and len(row) == 4 and row[0] == observation_epoch
                and row[1] == observation_token and row[2] == "OBSERVED" and row[3] is True)

    @staticmethod
    def _no_finalization_or_live_claim(cursor: Any, *, tenant_ref: str,
                                        publication_ref: str, work_ref: str,
                                        lock: bool) -> bool:
        cursor.execute("SELECT 1 FROM anonflow_publication_finalizations WHERE tenant_ref=%s "
                       "AND publication_ref=%s" + (" FOR UPDATE" if lock else ""),
                       (tenant_ref, publication_ref))
        if _row(cursor) is not None:
            return False
        cursor.execute("SELECT completed_at, lease_expires_at > clock_timestamp() "
                       "FROM anonflow_worker_jobs WHERE tenant_ref=%s AND work_ref=%s"
                       + (" FOR UPDATE" if lock else ""), (tenant_ref, work_ref))
        job = _row(cursor)
        # A missing job cannot be distinguished from an enqueue/claim racing
        # this observation. Refuse to classify that orphan rather than record
        # evidence concurrently with a newly claimed worker.
        return job is not None and len(job) == 2 and (job[0] is not None or job[1] is not True)

    def _load(self, cursor: Any, *, tenant_ref: str, publication_ref: str,
              lock: bool) -> tuple[object, PublicationPayloadBinding,
                                   PublicationAuthorizationAttestation]:
        cursor.execute(
            "SELECT transaction_id, plan_digest, CASE WHEN octet_length(document::text) <= %s "
            "THEN document ELSE NULL END FROM anonflow_publication_intents WHERE tenant_ref=%s "
            "AND publication_ref=%s" + (" FOR UPDATE" if lock else ""),
            (_MAX_ROW_BYTES, tenant_ref, publication_ref))
        row = _row(cursor)
        if row is None or len(row) != 3:
            _fail()
        intent = _decode(row[2], tenant_ref=tenant_ref, publication_ref=publication_ref,
                         transaction_id=row[0], plan_digest=row[1])
        cursor.execute(
            "SELECT object_ref, key_ref, plan_digest, payload_digest, payload_size_bytes, "
            "serialization_id, binding_digest FROM anonflow_publication_payload_bindings "
            "WHERE tenant_ref=%s AND publication_ref=%s" + (" FOR UPDATE" if lock else ""),
            (tenant_ref, publication_ref))
        binding = _decode_binding(_row(cursor), intent=intent, plan_digest=row[1])
        cursor.execute(
            "SELECT attestation_digest, expires_at, CASE WHEN octet_length(document::text) <= %s "
            "THEN document ELSE NULL END FROM anonflow_publication_authorizations WHERE tenant_ref=%s "
            "AND publication_ref=%s" + (" FOR UPDATE" if lock else ""),
            (_MAX_ROW_BYTES, tenant_ref, publication_ref))
        authorization = _decode_authorization(_row(cursor), intent=intent, binding=binding,
                                              verifier=self._authorization_verifier,
                                              at=_database_now(cursor))
        if type(authorization) is not PublicationAuthorizationAttestation:
            _fail()
        return intent, binding, authorization

    def _preflight(self, *, tenant_ref: str, publication_ref: str,
                   observation_epoch: int, observation_token: str) -> tuple[object,
                                                                             PublicationPayloadBinding,
                                                                             PublicationAuthorizationAttestation] | None:
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN READ ONLY")
            intent, binding, authorization = self._load(cursor, tenant_ref=tenant_ref,
                                                         publication_ref=publication_ref, lock=False)
            eligible = (self._live_observation(cursor, tenant_ref=tenant_ref,
                                                publication_ref=publication_ref,
                                                observation_epoch=observation_epoch,
                                                observation_token=observation_token, lock=False)
                        and self._no_finalization_or_live_claim(
                            cursor, tenant_ref=tenant_ref, publication_ref=publication_ref,
                            work_ref=intent.work_ref, lock=False))
            cursor.execute("COMMIT")
            return (intent, binding, authorization) if eligible else None
        except PostgresPublicationVerificationError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def verify(self, *, tenant_ref: str, publication_ref: str, observation_epoch: int,
               observation_token: str, openbao_token: str) -> PublicationObjectVerification | None:
        """Authenticate and classify one observation without making it actionable.

        ``None`` is a deliberately non-actionable race/expired-lease result.
        Provider, envelope, marker, object and key failures collapse into the
        persisted ``NOT_VERIFIED`` outcome when the observation remains live.
        """
        _text(tenant_ref, _TENANT)
        _text(publication_ref, _PUBLICATION)
        _text(observation_token, _OBSERVATION)
        _epoch(observation_epoch)
        loaded = self._preflight(tenant_ref=tenant_ref, publication_ref=publication_ref,
                                 observation_epoch=observation_epoch,
                                 observation_token=observation_token)
        if loaded is None:
            return None
        intent, binding, authorization = loaded
        try:
            reference = self._encrypted_objects.recover(
                tenant_ref=tenant_ref, object_ref=binding.object_ref,
                publication_ref=publication_ref, key_ref=binding.key_ref,
                binding=binding, openbao_token=openbao_token)
            verified = (type(reference) is EncryptedObjectReference
                        and reference.tenant_ref == tenant_ref
                        and reference.object_ref == binding.object_ref
                        and reference.publication_ref == publication_ref
                        and reference.key_ref == binding.key_ref
                        and reference.binding_digest == binding.binding_digest)
        except Exception:
            verified = False
        outcome = "VERIFIED" if verified else "NOT_VERIFIED"
        ciphertext_digest = reference.ciphertext_digest if verified else None
        ciphertext_size_bytes = reference.ciphertext_size_bytes if verified else None
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            locked_intent, locked_binding, locked_authorization = self._load(
                cursor, tenant_ref=tenant_ref, publication_ref=publication_ref, lock=True)
            if (locked_intent != intent or locked_binding != binding
                    or locked_authorization != authorization):
                _fail()
            eligible = (self._live_observation(cursor, tenant_ref=tenant_ref,
                                                publication_ref=publication_ref,
                                                observation_epoch=observation_epoch,
                                                observation_token=observation_token, lock=True)
                        and self._no_finalization_or_live_claim(
                            cursor, tenant_ref=tenant_ref, publication_ref=publication_ref,
                            work_ref=locked_intent.work_ref, lock=True))
            if not eligible:
                cursor.execute("COMMIT")
                return None
            cursor.execute(
                "INSERT INTO anonflow_publication_observation_verifications "
                "(tenant_ref, publication_ref, observation_epoch, outcome, binding_digest, authorization_digest, "
                "ciphertext_digest, ciphertext_size_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING outcome, binding_digest, authorization_digest, "
                "ciphertext_digest, ciphertext_size_bytes",
                (tenant_ref, publication_ref, observation_epoch, outcome, binding.binding_digest,
                 authorization.digest, ciphertext_digest, ciphertext_size_bytes))
            stored = _row(cursor)
            if stored is None:
                cursor.execute(
                    "SELECT outcome, binding_digest, authorization_digest, ciphertext_digest, ciphertext_size_bytes "
                    "FROM anonflow_publication_observation_verifications WHERE tenant_ref=%s "
                    "AND publication_ref=%s AND observation_epoch=%s FOR UPDATE",
                    (tenant_ref, publication_ref, observation_epoch))
                stored = _row(cursor)
                if stored is None:
                    _fail()
            if (len(stored) != 5 or stored[0] != outcome or stored[1] != binding.binding_digest
                    or stored[2] != authorization.digest or stored[0] not in _OUTCOMES):
                _fail()
            if ((outcome == "VERIFIED" and (stored[3] != ciphertext_digest
                                              or stored[4] != ciphertext_size_bytes))
                    or (outcome == "NOT_VERIFIED" and (stored[3] is not None or stored[4] is not None))):
                _fail()
            # A write could wait on the observation, completion, or job lock.
            # Re-evaluate the immutable signed grant at PostgreSQL's clock
            # immediately before committing even this non-authorizing record.
            if _decode_authorization(
                    (locked_authorization.digest, locked_authorization.expires_at,
                     locked_authorization.to_record()), intent=locked_intent,
                    binding=locked_binding, verifier=self._authorization_verifier,
                    at=_database_now(cursor)) != locked_authorization:
                _fail()
            # The INSERT/replay path can wait on another verifier. Check the
            # same fenced lease again immediately before committing evidence.
            if not self._live_observation(cursor, tenant_ref=tenant_ref,
                                          publication_ref=publication_ref,
                                          observation_epoch=observation_epoch,
                                          observation_token=observation_token, lock=True):
                _fail()
            cursor.execute("COMMIT")
            return PublicationObjectVerification(tenant_ref, publication_ref, observation_epoch,
                                                 stored[0], True)
        except PostgresPublicationVerificationError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)
