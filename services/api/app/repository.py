"""Bounded development repository contract and in-memory reference adapter.

Audit capacity fails closed rather than silently dropping history. Expiry/deletion
are logical operations, never a guarantee of erasure from memory or backups.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from threading import RLock

from fastapi import HTTPException
from app.candidate import (CandidateError, LedgerAction, LedgerReason, PayloadKind,
                           SchemaContract, TransformLedgerEntry)
from app.evaluation_harness import EvaluationHarnessError, ScoredEvaluation
from app.evaluator_authority import EvaluatorAuthority, EvaluatorAuthorityError
from app.utility_evidence import DataUtilityReport, UtilityEvidenceError
from app.utility_evidence_authority import UtilityEvidenceAuthorityError, UtilityEvidenceControlAuthority
from app.disclosure_risk import DisclosureRiskError, DisclosureRiskReport
from app.disclosure_risk_authority import DisclosureRiskAuthorityError, DisclosureRiskControlAuthority


def unavailable():
    return HTTPException(503, "Storage unavailable or integrity verification failed")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def detached(value):
    return json.loads(encoded(value))


def _evaluation_evidence_status(payload):
    """Return the digest-bound report status, rejecting ambiguous metadata.

    The canonical value is ``report.evidence_status`` because it belongs to the
    immutable residual report.  A top-level mirror is accepted only when it is
    identical, which keeps future writers compatible without allowing a stale
    or forged wrapper field to suppress quarantine.
    """
    try:
        report = payload["report"]
        status = report["evidence_status"]
    except (KeyError, TypeError):
        raise unavailable() from None
    if status not in {"INSUFFICIENT_EVIDENCE", "FAILS_PROFILE"}:
        raise unavailable()
    mirrored = payload.get("evidence_status")
    if mirrored is not None and mirrored != status:
        raise unavailable()
    return status


class DevelopmentStore:
    MAX_DATASETS = 100
    MAX_DATASETS_PER_TENANT = 25
    MAX_RELEASES = 500
    MAX_RELEASES_PER_TENANT = 100
    MAX_SOURCE_BYTES = 20_000_000
    MAX_TENANT_SOURCE_BYTES = 5_000_000
    MAX_AUDIT_EVENTS = 10_000
    MAX_AUDIT_EVENTS_PER_TENANT = 2_000
    MAX_RELEASE_BYTES = 1_000_000
    MAX_CONTROLS = 1_000
    MAX_CONTROLS_PER_TENANT = 250
    MAX_CONTROL_BYTES = 2_000_000
    # A claimed run has no durable worker lease.  Treat an abandoned claim as a
    # terminal failure after this bounded interval rather than allowing an old
    # worker to complete it indefinitely.  A later retry must be a new run.
    RUN_LEASE_SECONDS = 15 * 60
    # ``private_candidate`` is deliberately a private worker artifact, never a
    # public control-plane resource.  It shares the encrypted durable-record
    # envelope so plaintext never reaches SQLite, but has no GET/list route.
    CONTROL_KINDS = frozenset({"rights_profile", "policy_snapshot", "processing_run", "authorization_request",
                                "private_candidate", "evaluation_report", "qualification",
                                "detector_evaluation_evidence", "utility_evidence", "disclosure_risk_evidence"})
    TTL_SECONDS = 3600

    def __init__(self):
        self.lock = RLock()
        self.datasets = {}
        self.releases = {}
        self.controls = {kind: {} for kind in self.CONTROL_KINDS}
        self._audit = {}
        self._audit_key = secrets.token_bytes(32)

    @contextmanager
    def _transaction(self):
        with self.lock:
            self._verify_all()
            before = copy.deepcopy((self.datasets, self.releases, self.controls, self._audit))
            try:
                yield
            except BaseException:
                self.datasets, self.releases, self.controls, self._audit = before
                raise

    def _verify_all(self):
        for tenant in self._audit:
            self._verify(tenant)

    def _verify(self, tenant):
        previous = "0" * 64
        for sequence, entry in enumerate(self._audit.get(tenant, []), 1):
            try:
                event = entry["event"]
                if set(event) != {"actor", "action", "object_id", "time", "seq"} or event["seq"] != sequence:
                    raise ValueError
                if set(entry) != {"event", "mac", "record_commitment", "parent_id"}:
                    raise ValueError
                signature = hmac.new(self._audit_key, encoded([tenant, previous, event, entry["record_commitment"], entry["parent_id"]]), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, entry["mac"]):
                    raise ValueError
                previous = signature
            except (KeyError, ValueError, TypeError, UnicodeError):
                raise unavailable() from None

    def _append_event(self, tenant, action, object_id, actor, event_time=None, record=None):
        entries = self._audit.get(tenant, [])
        # Reserve the final 20% for review/deletion/expiry. Once admission stops,
        # bounded live dataset/release quotas leave ample lifecycle capacity.
        admission = action.endswith(".created")
        tenant_limit = int(self.MAX_AUDIT_EVENTS_PER_TENANT * .8) if admission else self.MAX_AUDIT_EVENTS_PER_TENANT
        global_limit = int(self.MAX_AUDIT_EVENTS * .8) if admission else self.MAX_AUDIT_EVENTS
        # Claimed M3 runs persist slots for their terminal evidence.  Account
        # for those reservations for every unrelated lifecycle event so another
        # tenant/thread cannot exhaust history and strand a run in RUNNING.
        reserved_tenant = sum(record["payload"].get("audit_reservation", 0)
                              for record in self.controls["processing_run"].values()
                              if record["tenant"] == tenant)
        reserved_global = sum(record["payload"].get("audit_reservation", 0)
                              for record in self.controls["processing_run"].values())
        if (len(entries) + reserved_tenant >= tenant_limit
                or sum(map(len, self._audit.values())) + reserved_global >= global_limit):
            raise HTTPException(429, "Development audit capacity exceeded")
        event = {"actor": actor, "action": action, "object_id": object_id,
                 "time": event_time or datetime.now(UTC).isoformat(), "seq": len(entries) + 1}
        if any(type(value) is not str or not value or len(value) > 256 for key, value in event.items() if key != "seq"):
            raise unavailable()
        previous = entries[-1]["mac"] if entries else "0" * 64
        commitment = hashlib.sha256(encoded(record)).hexdigest() if record is not None else None
        parent = record.get("dataset_id") if record is not None else None
        signature = hmac.new(self._audit_key, encoded([tenant, previous, event, commitment, parent]), hashlib.sha256).hexdigest()
        self._audit.setdefault(tenant, []).append({"event": event, "mac": signature, "record_commitment": commitment, "parent_id": parent})

    def _reserve_audit_slots(self, tenant, slots):
        """Refuse a claim unless its success/failure terminal evidence fits."""
        if type(slots) is not int or slots < 1:
            raise unavailable()
        reserved_tenant = sum(record["payload"].get("audit_reservation", 0)
                              for record in self.controls["processing_run"].values()
                              if record["tenant"] == tenant)
        reserved_global = sum(record["payload"].get("audit_reservation", 0)
                              for record in self.controls["processing_run"].values())
        if (len(self._audit.get(tenant, [])) + reserved_tenant + slots > self.MAX_AUDIT_EVENTS_PER_TENANT
                or sum(map(len, self._audit.values())) + reserved_global + slots > self.MAX_AUDIT_EVENTS):
            raise HTTPException(429, "Development audit capacity exceeded")

    def _purge(self):
        expired = [d for d in self.datasets.values() if d["expires_at"] <= time.time()]
        for record in expired:
            # Invalidate first: a RUNNING child may have reserved the exact
            # slots needed for its terminal evidence.  Leaving that reservation
            # in place would make the parent expiry audit write reject at
            # capacity and roll back the whole cleanup transaction.
            self._invalidate_runs(record["tenant"], "dataset_id", record["id"])
            self._append_event(record["tenant"], "dataset.expired", record["id"], "system")
            self._delete(record["id"], record["tenant"])
        return len(expired)

    def _purge_controls(self):
        expired = [(kind, identifier, record) for kind, values in self.controls.items()
                   for identifier, record in values.items() if record["expires_at"] <= time.time()]
        for kind, identifier, record in expired:
            # A dependent rights/policy expiry can invalidate a run that was
            # also present in this precomputed expiry list.
            if identifier not in self.controls[kind]:
                continue
            if kind in {"rights_profile", "policy_snapshot"}:
                self._invalidate_runs(record["tenant"], kind + "_id", identifier)
            self._append_event(record["tenant"], kind + ".expired", identifier, "system")
            del self.controls[kind][identifier]
        return len(expired)

    def purge(self):
        with self._transaction():
            return self._purge() + self._purge_controls()

    def _delete(self, identifier, tenant):
        del self.datasets[identifier]
        for key in list(self.releases):
            if self.releases[key]["dataset_id"] == identifier and self.releases[key]["tenant"] == tenant:
                del self.releases[key]
        self._invalidate_runs(tenant, "dataset_id", identifier)

    def _invalidate_runs(self, tenant, dependency_key, identifier):
        """Tombstone runs and their private evidence when a prerequisite disappears."""
        for run_id, record in list(self.controls["processing_run"].items()):
            if record["tenant"] != tenant or record["payload"].get(dependency_key) != identifier:
                continue
            # A claim reserved capacity for a terminal transition.  This
            # invalidation *is* that transition, so release the reservation
            # before appending its authenticated tombstone.  The run is deleted
            # in this transaction; no transient record state is persisted.
            if record["payload"].get("state") == "RUNNING":
                record["payload"]["audit_reservation"] = 0
            for kind in ("qualification", "evaluation_report", "detector_evaluation_evidence", "utility_evidence", "disclosure_risk_evidence",
                         "private_candidate"):
                for evidence_id, evidence in list(self.controls[kind].items()):
                    if evidence["tenant"] == tenant and evidence["payload"].get("run_id") == run_id:
                        self._append_event(tenant, kind + ".invalidated", evidence_id, "system")
                        del self.controls[kind][evidence_id]
            self._append_event(tenant, "processing_run.invalidated", run_id, "system")
            del self.controls["processing_run"][run_id]

    def _dataset(self, identifier, tenant):
        result = self.datasets.get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Dataset not found")
        return result

    def _used_identifier(self, identifier, kind):
        return any(entry["event"]["object_id"] == identifier
                   and entry["event"]["action"] == kind + ".created"
                   for entries in self._audit.values() for entry in entries)

    def _control(self, kind, identifier, tenant):
        if kind not in self.CONTROL_KINDS:
            raise unavailable()
        result = self.controls[kind].get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Control record not found")
        return result

    def _validate_control(self, data):
        if not isinstance(data, dict) or set(data) != {"id", "kind", "tenant", "created_at", "expires_at", "size_bytes", "payload"}:
            raise unavailable()
        if data["kind"] not in self.CONTROL_KINDS:
            raise unavailable()
        if any(type(data[key]) is not str or not data[key] or len(data[key]) > 256
               for key in ("id", "kind", "tenant", "created_at")):
            raise unavailable()
        if type(data["expires_at"]) not in (int, float) or isinstance(data["expires_at"], bool) or data["expires_at"] <= 0:
            raise unavailable()
        if not isinstance(data["payload"], dict):
            raise unavailable()
        supplied_size = data["size_bytes"]
        if type(supplied_size) is not int or isinstance(supplied_size, bool) or supplied_size < 0:
            raise unavailable()
        # The indexed size is part of the authenticated record. Iterate to a
        # fixed point so an extra digit in the decimal representation cannot
        # make a restarted durable store see a different record commitment.
        data["size_bytes"] = 0
        for _ in range(4):
            calculated = len(encoded(data))
            if calculated == data["size_bytes"]:
                break
            data["size_bytes"] = calculated
        else:
            raise unavailable()
        if supplied_size not in {0, data["size_bytes"]}:
            raise unavailable()
        if data["size_bytes"] > self.MAX_CONTROL_BYTES:
            raise HTTPException(429, "Development control capacity exceeded")

    def add_control(self, record, actor):
        data = detached(record)
        with self._transaction():
            self._purge()
            self._purge_controls()
            self._validate_control(data)
            kind = data["kind"]
            if data["id"] in self.controls[kind] or self._used_identifier(data["id"], kind):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == data["tenant"] for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(data["tenant"], kind + ".created", data["id"], actor, record=data)
            self.controls[kind][data["id"]] = data
            return detached(data)

    def get_control(self, kind, identifier, tenant):
        self.purge()
        with self._transaction():
            result = self._control(kind, identifier, tenant)
            if result["expires_at"] <= time.time():
                raise HTTPException(404, "Control record not found")
            return detached(result)

    def list_controls(self, kind, tenant):
        if kind not in self.CONTROL_KINDS:
            raise unavailable()
        with self._transaction():
            self._purge()
            self._purge_controls()
            return detached([record for record in self.controls[kind].values() if record["tenant"] == tenant])

    def register_run_control(self, record, actor):
        """Atomically implement tenant-scoped idempotency for registered runs."""
        data = detached(record)
        with self._transaction():
            self._purge()
            self._purge_controls()
            self._validate_control(data)
            if data["kind"] != "processing_run":
                raise unavailable()
            payload = data["payload"]
            key, digest = payload.get("idempotency_key"), payload.get("request_digest")
            if type(key) is not str or type(digest) is not str:
                raise unavailable()
            for existing in self.controls["processing_run"].values():
                if existing["tenant"] != data["tenant"] or existing["payload"].get("idempotency_key") != key:
                    continue
                if existing["payload"].get("request_digest") != digest:
                    raise HTTPException(409, "Idempotency key conflicts with a different request")
                return detached(existing), True
            self._validate_run_dependencies(data)
            if data["id"] in self.controls["processing_run"] or self._used_identifier(data["id"], "processing_run"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == data["tenant"] for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(data["tenant"], "processing_run.created", data["id"], actor, record=data)
            self.controls["processing_run"][data["id"]] = data
            return detached(data), False

    def _validate_run_dependencies(self, data):
        payload = data["payload"]
        dependency_ids = {key: payload.get(key) for key in ("dataset_id", "rights_profile_id", "policy_snapshot_id")}
        if any(type(value) is not str or not value for value in dependency_ids.values()):
            raise unavailable()
        dataset = self._dataset(dependency_ids["dataset_id"], data["tenant"])
        rights = self._control("rights_profile", dependency_ids["rights_profile_id"], data["tenant"])
        policy = self._control("policy_snapshot", dependency_ids["policy_snapshot_id"], data["tenant"])
        if any(record["expires_at"] <= time.time() for record in (dataset, rights, policy)):
            raise HTTPException(409, "Run dependency is unavailable")
        if (payload.get("rights_digest") != rights["payload"].get("digest")
                or payload.get("policy_digest") != policy["payload"].get("digest")):
            raise HTTPException(409, "Run dependency is unavailable")

    @staticmethod
    def _run_event(payload, *, state, action, attempt, error_code=None):
        events = payload.get("events")
        if not isinstance(events, list) or not 1 <= len(events) < 16:
            raise unavailable()
        if state not in {"RUNNING", "CANDIDATE", "QUARANTINED", "FAILED"}:
            raise unavailable()
        if type(attempt) is not int or not 0 <= attempt <= 3:
            raise unavailable()
        event = {"sequence": len(events) + 1, "state": state, "action": action,
                 "occurred_at": datetime.now(UTC).isoformat(), "attempt": attempt}
        if error_code is not None:
            if type(error_code) is not str or not error_code.isupper() or len(error_code) > 64:
                raise unavailable()
            event["error_code"] = error_code
        events.append(event)

    def claim_processing_run(self, identifier, tenant, actor):
        """Atomically claim a registered run, rechecking live prerequisites.

        The returned dataset is a detached, private in-process value.  Callers
        must complete with a second atomic dependency check; it must never be
        included in an HTTP response, event or exception.
        """
        with self._transaction():
            self._purge()
            self._purge_controls()
            current = self._control("processing_run", identifier, tenant)
            self._validate_run_dependencies(current)
            if current["payload"].get("state") != "REGISTERED":
                raise HTTPException(409, "Processing run is not available for execution")
            # STARTED plus either CANDIDATE_CREATED/update or FAILED/update.
            # Do this before changing state so an audit-full store cannot strand
            # a run in RUNNING without a terminal lifecycle record.
            self._reserve_audit_slots(tenant, 3)
            revised = detached(current)
            payload = revised["payload"]
            attempts = payload.get("attempts")
            if type(attempts) is not int or not 0 <= attempts < 3:
                raise unavailable()
            payload["state"] = "RUNNING"
            payload["attempts"] = attempts + 1
            payload["audit_reservation"] = 2
            self._run_event(payload, state="RUNNING", action="STARTED", attempt=payload["attempts"])
            revised["size_bytes"] = 0
            self._validate_control(revised)
            # Make the reservation visible to _append_event before it admits
            # STARTED; transaction rollback restores the old snapshot on error.
            self.controls["processing_run"][identifier] = revised
            self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
            self.controls["processing_run"][identifier] = revised
            dataset = detached(self._dataset(payload["dataset_id"], tenant))
            return detached(revised), dataset

    def complete_processing_run(self, identifier, tenant, candidate, actor):
        """Persist an encrypted private candidate and metadata-only run state."""
        return self._finish_processing_run(identifier, tenant, candidate, actor,
                                           state="CANDIDATE", action="CANDIDATE_CREATED")

    def quarantine_processing_run(self, identifier, tenant, candidate, code, actor):
        """Persist a private candidate but terminally quarantine the run.

        Policy enforcement can retain private evidence for authorized review
        without falsely representing a blocked/review-required transform as a
        candidate ready for residual evaluation or qualification.
        """
        return self._finish_processing_run(identifier, tenant, candidate, actor,
                                           state="QUARANTINED", action="QUARANTINED",
                                           error_code=code)

    def _finish_processing_run(self, identifier, tenant, candidate, actor, *, state, action, error_code=None):
        if state not in {"CANDIDATE", "QUARANTINED"} or type(action) is not str:
            raise unavailable()
        if state == "QUARANTINED" and error_code is None:
            raise unavailable()
        candidate_data = detached(candidate)
        with self._transaction():
            self._purge()
            self._purge_controls()
            current = self._control("processing_run", identifier, tenant)
            self._validate_run_dependencies(current)
            if current["payload"].get("state") != "RUNNING":
                raise HTTPException(409, "Processing run is not awaiting completion")
            self._validate_control(candidate_data)
            if candidate_data["kind"] != "private_candidate" or candidate_data["tenant"] != tenant:
                raise unavailable()
            candidate_payload = candidate_data["payload"]
            if (candidate_payload.get("run_id") != identifier
                    or candidate_payload.get("policy_digest") != current["payload"].get("policy_digest")
                    or candidate_payload.get("input_digest") != current["payload"].get("source_digest")):
                raise unavailable()
            self._validate_private_candidate(candidate_payload)
            if candidate_data["id"] in self.controls["private_candidate"] or self._used_identifier(candidate_data["id"], "private_candidate"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            revised = detached(current)
            payload = revised["payload"]
            payload["state"] = state
            payload["audit_reservation"] = 1
            payload["candidate"] = {key: candidate_payload[key] for key in ("artifact_digest", "byte_count", "media_type", "schema_digest", "payload_kind", "ledger")}
            self._run_event(payload, state=state, action=action, attempt=payload["attempts"], error_code=error_code)
            revised["size_bytes"] = 0
            self._validate_control(revised)
            self.controls["processing_run"][identifier] = revised
            self._append_event(tenant, "private_candidate.created", candidate_data["id"], actor, record=candidate_data)
            self.controls["private_candidate"][candidate_data["id"]] = candidate_data
            payload["audit_reservation"] = 0
            revised["size_bytes"] = 0
            self._validate_control(revised)
            self.controls["processing_run"][identifier] = revised
            self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
            self.controls["processing_run"][identifier] = revised
            return detached(revised)

    @staticmethod
    def _validate_private_candidate(payload):
        """Check private bytes against metadata before they enter encrypted storage."""
        body = payload.get("body")
        media_type, byte_count, digest = payload.get("media_type"), payload.get("byte_count"), payload.get("artifact_digest")
        if media_type == "text/plain" and type(body) is str:
            try:
                raw = body.encode("utf-8")
            except UnicodeError:
                raise unavailable() from None
        elif media_type == "application/json" and type(body) in (list, dict):
            try:
                raw = encoded(body)
            except (TypeError, ValueError, UnicodeError):
                raise unavailable() from None
        else:
            raise unavailable()
        calculated = "sha256:" + hashlib.sha256(raw).hexdigest()
        evaluation_schema = payload.get("evaluation_schema_digest")
        def digest_value(value):
            return (type(value) is str and len(value) == 71 and value.startswith("sha256:")
                    and all(char in "0123456789abcdef" for char in value[7:]))
        if (type(byte_count) is not int or byte_count != len(raw) or digest != calculated
                or not digest_value(payload.get("schema_digest"))
                or (media_type == "application/json" and not digest_value(evaluation_schema))
                or (media_type == "text/plain" and evaluation_schema is not None)):
            raise unavailable()
        try:
            kind = PayloadKind(payload.get("payload_kind"))
            if media_type != ("text/plain" if kind is PayloadKind.TEXT else "application/json"):
                raise CandidateError()
            schema = SchemaContract.from_private_descriptor(kind=kind, digest=payload["schema_digest"],
                                                             descriptor=payload.get("schema_descriptor"))
            if not schema.accepts(body):
                raise CandidateError()
            ledger = payload.get("ledger")
            if type(ledger) is not list:
                raise CandidateError()
            entries = tuple(TransformLedgerEntry(item["entity_type"], LedgerAction(item["action"]),
                                                  LedgerReason(item["reason"]), item["count"])
                            for item in ledger)
            if (len(entries) != len(ledger)
                    or tuple(sorted(entries, key=lambda item: (item.entity_type, item.action.value, item.reason.value))) != entries
                    or len({(item.entity_type, item.action, item.reason) for item in entries}) != len(entries)):
                raise CandidateError()
        except (CandidateError, KeyError, TypeError, ValueError):
            raise unavailable() from None

    def fail_processing_run(self, identifier, tenant, code, actor):
        """Record a fixed-code local worker failure without serializing errors."""
        with self._transaction():
            self._purge()
            self._purge_controls()
            current = self._control("processing_run", identifier, tenant)
            if current["payload"].get("state") != "RUNNING":
                raise HTTPException(409, "Processing run is not awaiting completion")
            revised = detached(current)
            payload = revised["payload"]
            payload["state"] = "FAILED"
            payload["audit_reservation"] = 0
            self._run_event(payload, state="FAILED", action="FAILED", attempt=payload["attempts"], error_code=code)
            revised["size_bytes"] = 0
            self._validate_control(revised)
            self.controls["processing_run"][identifier] = revised
            self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
            self.controls["processing_run"][identifier] = revised
            return detached(revised)

    @staticmethod
    def _running_started_at(payload):
        """Return the authenticated RUNNING event time or fail closed."""
        events = payload.get("events")
        attempts = payload.get("attempts")
        if not isinstance(events, list) or not events or type(attempts) is not int:
            raise unavailable()
        event = events[-1]
        if (not isinstance(event, dict) or event.get("state") != "RUNNING"
                or event.get("action") != "STARTED" or event.get("attempt") != attempts
                or type(event.get("occurred_at")) is not str):
            raise unavailable()
        try:
            moment = datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00"))
            if moment.tzinfo is None or moment.utcoffset() is None:
                raise ValueError
            return moment.timestamp()
        except (OverflowError, OSError, ValueError):
            raise unavailable() from None

    def recover_stale_processing_run(self, identifier, tenant, actor):
        """Terminally fail an abandoned claim without permitting stale output.

        There is deliberately no requeue here: a worker that still holds an old
        detached source can no longer complete after this transition.  A caller
        that wants to retry must register a new, independently audited run.
        """
        with self._transaction():
            self._purge()
            self._purge_controls()
            current = self._control("processing_run", identifier, tenant)
            if current["payload"].get("state") != "RUNNING":
                raise HTTPException(409, "Processing run is not awaiting recovery")
            started_at = self._running_started_at(current["payload"])
            if time.time() - started_at < self.RUN_LEASE_SECONDS:
                raise HTTPException(409, "Processing run lease has not expired")
            revised = detached(current)
            payload = revised["payload"]
            payload["state"] = "FAILED"
            # Recovery consumes the terminal slot reserved at claim time.
            payload["audit_reservation"] = 0
            self._run_event(payload, state="FAILED", action="LEASE_EXPIRED",
                            attempt=payload["attempts"], error_code="LEASE_EXPIRED")
            revised["size_bytes"] = 0
            self._validate_control(revised)
            self.controls["processing_run"][identifier] = revised
            self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
            self.controls["processing_run"][identifier] = revised
            return detached(revised)

    def private_candidate_for_run(self, identifier, tenant):
        """Trusted internal accessor; deliberately not mapped to an API route."""
        with self._transaction():
            self._purge()
            self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            if run["payload"].get("state") not in {"CANDIDATE", "QUARANTINED"}:
                raise HTTPException(409, "Processing run has no candidate")
            candidates = [record for record in self.controls["private_candidate"].values()
                          if record["tenant"] == tenant and record["payload"].get("run_id") == identifier]
            if len(candidates) != 1:
                raise unavailable()
            return detached(candidates[0]), detached(run)

    def record_evaluation(self, identifier, tenant, evaluation, actor):
        """Atomically bind aggregate residual evidence to the exact candidate."""
        data = detached(evaluation)
        with self._transaction():
            self._purge()
            self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            if run["payload"].get("state") != "CANDIDATE":
                raise HTTPException(409, "Processing run is not available for evaluation")
            candidates = [record for record in self.controls["private_candidate"].values()
                          if record["tenant"] == tenant and record["payload"].get("run_id") == identifier]
            if len(candidates) != 1:
                raise unavailable()
            self._validate_control(data)
            payload = data["payload"]
            if (data["kind"] != "evaluation_report" or data["tenant"] != tenant or payload.get("run_id") != identifier
                    or payload.get("candidate_digest") != candidates[0]["payload"].get("artifact_digest")
                    or payload.get("policy_digest") != run["payload"].get("policy_digest")
                    or payload.get("rights_digest") != run["payload"].get("rights_digest")):
                raise unavailable()
            if data["id"] in self.controls["evaluation_report"] or self._used_identifier(data["id"], "evaluation_report"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(tenant, "evaluation_report.created", data["id"], actor, record=data)
            self.controls["evaluation_report"][data["id"]] = data
            if _evaluation_evidence_status(payload) == "FAILS_PROFILE":
                revised = detached(run)
                revised_payload = revised["payload"]
                revised_payload["state"] = "QUARANTINED"
                self._run_event(revised_payload, state="QUARANTINED", action="QUARANTINED",
                                attempt=revised_payload["attempts"], error_code="RESIDUAL_FINDINGS")
                revised["size_bytes"] = 0
                self._validate_control(revised)
                self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
                self.controls["processing_run"][identifier] = revised
                run = revised
            return detached(data), detached(run)

    def record_detector_evaluation_evidence(self, identifier, tenant, evidence, actor, authority):
        """Atomically retain M8 aggregate method evidence, never a run decision.

        This differs from ``record_evaluation``: it is benchmark/corpus score
        evidence associated with a processing method, not a private-candidate
        residual scan.  No branch mutates the run state.
        """
        data = detached(evidence)
        with self._transaction():
            self._purge()
            self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            self._validate_control(data)
            payload = data["payload"]
            expected = {"run_id", "processing_request_digest", "policy_digest", "rights_digest",
                        "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest",
                        "idempotency_key", "evaluator_subject", "evaluator_authority_id",
                        "attestation_signature", "report"}
            if (data["kind"] != "detector_evaluation_evidence" or data["tenant"] != tenant
                    or set(payload) != expected or payload.get("run_id") != identifier
                    or payload.get("processing_request_digest") != run["payload"].get("request_digest")
                    or payload.get("policy_digest") != run["payload"].get("policy_digest")
                    or payload.get("rights_digest") != run["payload"].get("rights_digest")
                    or payload.get("method_id") != run["payload"].get("method_id")
                    or payload.get("method_version") != run["payload"].get("method_version")
                    or payload.get("method_config_digest") != run["payload"].get("method_config_digest")
                    or payload.get("taxonomy_mapping_digest") != run["payload"].get("taxonomy_mapping_digest")
                    or data["expires_at"] > run["expires_at"]
                    or type(authority) is not EvaluatorAuthority
                    or payload.get("evaluator_subject") != authority.subject
                    or payload.get("evaluator_authority_id") != authority.authority_id
                    or type(payload.get("idempotency_key")) is not str
                    or not 1 <= len(payload["idempotency_key"]) <= 200
                    or not payload["idempotency_key"].isascii()
                    or any(char.isspace() for char in payload["idempotency_key"])):
                raise unavailable()
            try:
                report = ScoredEvaluation.from_record(payload["report"])
                if not authority.verify(subject=payload["evaluator_subject"], tenant=tenant, run_id=identifier,
                                        processing_request_digest=payload["processing_request_digest"], report=report,
                                        signature=payload["attestation_signature"]):
                    raise EvaluatorAuthorityError()
            except (EvaluationHarnessError, EvaluatorAuthorityError):
                raise unavailable() from None
            if (report.binding.detector_id, report.binding.detector_version,
                report.binding.detector_config_digest, report.binding.taxonomy_mapping_digest) != (
                    payload["method_id"], payload["method_version"], payload["method_config_digest"],
                    payload["taxonomy_mapping_digest"]):
                raise unavailable()
            for existing in self.controls["detector_evaluation_evidence"].values():
                existing_payload = existing["payload"]
                if (existing["tenant"] == tenant and existing_payload.get("run_id") == identifier
                        and existing_payload.get("idempotency_key") == payload["idempotency_key"]):
                    if existing_payload.get("report", {}).get("digest") != report.digest:
                        raise HTTPException(409, "Idempotency key conflicts with a different request")
                    return detached(existing), True
            if (data["id"] in self.controls["detector_evaluation_evidence"]
                    or self._used_identifier(data["id"], "detector_evaluation_evidence")):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(tenant, "detector_evaluation_evidence.created", data["id"], actor, record=data)
            self.controls["detector_evaluation_evidence"][data["id"]] = data
            return detached(data), False

    def record_utility_evidence(self, identifier, tenant, evidence, actor, authority):
        """Persist trusted-worker structural evidence without lifecycle authority.

        The caller has already performed the private comparison locally.  This
        method verifies its aggregate report and exact run/candidate/method
        bindings atomically, but never changes candidate, qualification,
        release, or delivery state.
        """
        data = detached(evidence)
        with self._transaction():
            self._purge()
            self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            candidates = [record for record in self.controls["private_candidate"].values()
                          if record["tenant"] == tenant and record["payload"].get("run_id") == identifier]
            if len(candidates) != 1:
                raise unavailable()
            self._validate_control(data)
            payload = data["payload"]
            expected = {"run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest",
                        "rights_digest", "method_id", "method_version", "method_config_digest",
                        "taxonomy_mapping_digest", "idempotency_key", "utility_authority_id",
                        "attestation_signature", "report"}
            if (data["kind"] != "utility_evidence" or data["tenant"] != tenant or set(payload) != expected
                    or payload.get("run_id") != identifier
                    or payload.get("processing_request_digest") != run["payload"].get("request_digest")
                    or payload.get("candidate_artifact_digest") != candidates[0]["payload"].get("artifact_digest")
                    or payload.get("policy_digest") != run["payload"].get("policy_digest")
                    or payload.get("rights_digest") != run["payload"].get("rights_digest")
                    or payload.get("method_id") != run["payload"].get("method_id")
                    or payload.get("method_version") != run["payload"].get("method_version")
                    or payload.get("method_config_digest") != run["payload"].get("method_config_digest")
                    or payload.get("taxonomy_mapping_digest") != run["payload"].get("taxonomy_mapping_digest")
                    # The run's control TTL and the private candidate's source
                    # TTL can differ by a few milliseconds.  Evidence may not
                    # outlive either prerequisite, so its caller must bind it
                    # to their earlier expiry rather than invent a new lifetime.
                    or data["expires_at"] > run["expires_at"] or data["expires_at"] > candidates[0]["expires_at"]
                    or type(payload.get("idempotency_key")) is not str
                    or not 1 <= len(payload["idempotency_key"]) <= 200
                    or not payload["idempotency_key"].isascii()
                    or any(char.isspace() for char in payload["idempotency_key"])
                    or type(payload.get("utility_authority_id")) is not str
                    or not payload["utility_authority_id"].startswith("sha256:")
                    or len(payload["utility_authority_id"]) != 71
                    or any(char not in "0123456789abcdef" for char in payload["utility_authority_id"][7:])):
                raise unavailable()
            try:
                report = DataUtilityReport.from_record(payload["report"])
            except UtilityEvidenceError:
                raise unavailable() from None
            if (report.candidate_artifact_digest != payload["candidate_artifact_digest"]
                    or report.status.value != "ASSESSED"):
                # An unavailable/invalid server authority must never result in
                # a retained partial metric record.  A healthy worker can only
                # persist a completed comparison.
                raise unavailable()
            try:
                if (not isinstance(authority, UtilityEvidenceControlAuthority) or not authority.is_active()
                        or authority.tenant != tenant or authority.authority_id != payload["utility_authority_id"]
                        or not authority.verify(
                            signature=payload["attestation_signature"], tenant=tenant, run_id=identifier,
                            processing_request_digest=payload["processing_request_digest"],
                            candidate_artifact_digest=payload["candidate_artifact_digest"],
                            policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"],
                            method_id=payload["method_id"], method_version=payload["method_version"],
                            method_config_digest=payload["method_config_digest"],
                            taxonomy_mapping_digest=payload["taxonomy_mapping_digest"],
                            idempotency_key=payload["idempotency_key"], report=report)):
                    raise UtilityEvidenceAuthorityError()
            except UtilityEvidenceAuthorityError:
                raise unavailable() from None
            for existing in self.controls["utility_evidence"].values():
                existing_payload = existing["payload"]
                if (existing["tenant"] == tenant and existing_payload.get("run_id") == identifier
                        and existing_payload.get("idempotency_key") == payload["idempotency_key"]):
                    if existing_payload.get("report", {}).get("digest") != report.digest:
                        raise HTTPException(409, "Idempotency key conflicts with a different request")
                    return detached(existing), True
            if (data["id"] in self.controls["utility_evidence"]
                    or self._used_identifier(data["id"], "utility_evidence")):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(tenant, "utility_evidence.created", data["id"], actor, record=data)
            self.controls["utility_evidence"][data["id"]] = data
            return detached(data), False

    def record_disclosure_risk_evidence(self, identifier, tenant, evidence, actor, authority):
        """Retain signed aggregate risk evidence; never mutate run lifecycle."""
        data = detached(evidence)
        with self._transaction():
            self._purge(); self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            candidates = [item for item in self.controls["private_candidate"].values()
                          if item["tenant"] == tenant and item["payload"].get("run_id") == identifier]
            if len(candidates) != 1: raise unavailable()
            self._validate_control(data); payload = data["payload"]
            expected = {"run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest", "rights_digest",
                        "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest", "idempotency_key",
                        "risk_authority_id", "attestation_signature", "report"}
            valid_id = lambda value: (type(value) is str and len(value) == 71 and value.startswith("sha256:")
                                      and all(char in "0123456789abcdef" for char in value[7:]))
            if (data["kind"] != "disclosure_risk_evidence" or data["tenant"] != tenant or set(payload) != expected
                    or payload.get("run_id") != identifier or payload.get("processing_request_digest") != run["payload"].get("request_digest")
                    or payload.get("candidate_artifact_digest") != candidates[0]["payload"].get("artifact_digest")
                    or payload.get("policy_digest") != run["payload"].get("policy_digest")
                    or payload.get("rights_digest") != run["payload"].get("rights_digest")
                    or payload.get("method_id") != run["payload"].get("method_id")
                    or payload.get("method_version") != run["payload"].get("method_version")
                    or payload.get("method_config_digest") != run["payload"].get("method_config_digest")
                    or payload.get("taxonomy_mapping_digest") != run["payload"].get("taxonomy_mapping_digest")
                    or data["expires_at"] > run["expires_at"] or data["expires_at"] > candidates[0]["expires_at"]
                    or type(payload.get("idempotency_key")) is not str or not 1 <= len(payload["idempotency_key"]) <= 200
                    or not payload["idempotency_key"].isascii() or any(char.isspace() for char in payload["idempotency_key"])
                    or not valid_id(payload.get("risk_authority_id"))):
                raise unavailable()
            try:
                report = DisclosureRiskReport.from_record(payload["report"])
                verified = (isinstance(authority, DisclosureRiskControlAuthority) and authority.is_active()
                            and authority.tenant == tenant and authority.authority_id == payload["risk_authority_id"]
                            and authority.verify(signature=payload["attestation_signature"], tenant=tenant, run_id=identifier,
                                processing_request_digest=payload["processing_request_digest"], candidate_artifact_digest=payload["candidate_artifact_digest"],
                                policy_digest=payload["policy_digest"], rights_digest=payload["rights_digest"], method_id=payload["method_id"],
                                method_version=payload["method_version"], method_config_digest=payload["method_config_digest"],
                                taxonomy_mapping_digest=payload["taxonomy_mapping_digest"], idempotency_key=payload["idempotency_key"], report=report))
            except (DisclosureRiskError, DisclosureRiskAuthorityError):
                raise unavailable() from None
            if not verified or report.candidate_artifact_digest != payload["candidate_artifact_digest"]: raise unavailable()
            for existing in self.controls["disclosure_risk_evidence"].values():
                old = existing["payload"]
                if existing["tenant"] == tenant and old.get("run_id") == identifier and old.get("idempotency_key") == payload["idempotency_key"]:
                    if old.get("report", {}).get("digest") != report.digest: raise HTTPException(409, "Idempotency key conflicts with a different request")
                    return detached(existing), True
            if data["id"] in self.controls["disclosure_risk_evidence"] or self._used_identifier(data["id"], "disclosure_risk_evidence"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(items) for items in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for items in self.controls.values() for item in items.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(tenant, "disclosure_risk_evidence.created", data["id"], actor, record=data)
            self.controls["disclosure_risk_evidence"][data["id"]] = data
            return detached(data), False

    def record_qualification(self, identifier, tenant, qualification, evaluation_id, actor):
        """Persist only a candidate/evidence-bound, non-authorizing decision."""
        data = detached(qualification)
        with self._transaction():
            self._purge()
            self._purge_controls()
            run = self._control("processing_run", identifier, tenant)
            if run["payload"].get("state") not in {"CANDIDATE", "QUARANTINED"}:
                raise HTTPException(409, "Processing run is not available for qualification")
            evaluation = self._control("evaluation_report", evaluation_id, tenant)
            candidates = [record for record in self.controls["private_candidate"].values()
                          if record["tenant"] == tenant and record["payload"].get("run_id") == identifier]
            if len(candidates) != 1 or evaluation["payload"].get("run_id") != identifier:
                raise unavailable()
            self._validate_control(data)
            payload = data["payload"]
            if (data["kind"] != "qualification" or data["tenant"] != tenant or payload.get("run_id") != identifier
                    or payload.get("candidate_artifact_digest") != candidates[0]["payload"].get("artifact_digest")
                    or payload.get("evaluation_report_digest") != evaluation["payload"].get("report", {}).get("digest")
                    or payload.get("policy_digest") != run["payload"].get("policy_digest")
                    or payload.get("rights_digest") != run["payload"].get("rights_digest")
                    or payload.get("buyer") != run["payload"].get("recipient")
                    or payload.get("purpose") != run["payload"].get("purpose")):
                raise unavailable()
            if data["id"] in self.controls["qualification"] or self._used_identifier(data["id"], "qualification"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self.controls.values()) >= self.MAX_CONTROLS
                    or sum(item["tenant"] == tenant for values in self.controls.values() for item in values.values()) >= self.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._append_event(tenant, "qualification.created", data["id"], actor, record=data)
            self.controls["qualification"][data["id"]] = data
            if payload.get("outcome") == "QUARANTINED" and run["payload"].get("state") == "CANDIDATE":
                revised = detached(run)
                revised_payload = revised["payload"]
                revised_payload["state"] = "QUARANTINED"
                self._run_event(revised_payload, state="QUARANTINED", action="QUARANTINED",
                                attempt=revised_payload["attempts"], error_code="QUALIFICATION_FAILURE")
                revised["size_bytes"] = 0
                self._validate_control(revised)
                self._append_event(tenant, "processing_run.updated", identifier, actor, record=revised)
                self.controls["processing_run"][identifier] = revised
                run = revised
            return detached(data), detached(run)

    def _release(self, identifier, tenant):
        result = self.releases.get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Release not found")
        return result

    def add_dataset(self, record):
        data = detached(record)
        with self._transaction():
            self._purge()
            if data["id"] in self.datasets or self._used_identifier(data["id"], "dataset"):
                raise HTTPException(409, "Object already exists")
            tenant_records = [r for r in self.datasets.values() if r["tenant"] == data["tenant"]]
            # Caller byte counts must include original serialized ingestion plus
            # normalized source. Never trust a smaller caller-provided counter.
            actual = len(encoded(data))
            data["size_bytes"] = max(actual, data.get("size_bytes", 0))
            if (len(self.datasets) >= self.MAX_DATASETS or len(tenant_records) >= self.MAX_DATASETS_PER_TENANT
                    or sum(r["size_bytes"] for r in self.datasets.values()) + data["size_bytes"] > self.MAX_SOURCE_BYTES
                    or sum(r["size_bytes"] for r in tenant_records) + data["size_bytes"] > self.MAX_TENANT_SOURCE_BYTES):
                raise HTTPException(429, "Development storage capacity exceeded")
            data["expires_at"] = time.time() + min(self.TTL_SECONDS, 3600)
            self._append_event(data["tenant"], "dataset.created", data["id"], data["owner"], record=data)
            self.datasets[data["id"]] = data

    def list_datasets(self, tenant):
        with self._transaction():
            self._purge()
            return detached([r for r in self.datasets.values() if r["tenant"] == tenant])

    def get_dataset(self, identifier, tenant):
        # Commit expiry independently of the expected missing-object response.
        self._purge_for_lookup(identifier, tenant, release=False)
        with self._transaction():
            record = self._dataset(identifier, tenant)
            if record["expires_at"] <= time.time():
                raise HTTPException(404, "Dataset not found")
            return detached(record)

    def check_release_capacity(self, tenant):
        if len(self.releases) >= self.MAX_RELEASES or sum(r["tenant"] == tenant for r in self.releases.values()) >= self.MAX_RELEASES_PER_TENANT:
            raise HTTPException(429, "Development release capacity exceeded")

    def add_release(self, record):
        data = detached(record)
        with self._transaction():
            self._purge()
            parent = self._dataset(data["dataset_id"], data["tenant"])
            if data["id"] in self.releases or self._used_identifier(data["id"], "release"):
                raise HTTPException(409, "Object already exists")
            self.check_release_capacity(data["tenant"])
            data["expires_at"] = parent["expires_at"]
            data["size_bytes"] = len(encoded(data)) + 32
            if data["size_bytes"] > self.MAX_RELEASE_BYTES:
                raise HTTPException(429, "Development release capacity exceeded")
            self._append_event(data["tenant"], "release.created", data["id"], data["creator"], record=data)
            self.releases[data["id"]] = data

    def get_release(self, identifier, tenant):
        self._purge_for_lookup(identifier, tenant, release=True)
        with self._transaction():
            record = self._release(identifier, tenant)
            parent = self._dataset(record["dataset_id"], tenant)
            if parent["expires_at"] <= time.time():
                raise HTTPException(404, "Release not found")
            return detached(record)

    def _purge_for_lookup(self, identifier, tenant, *, release):
        try:
            self.purge()
        except HTTPException as error:
            if error.status_code != 429:
                raise
            # If an operator lowered/exhausted audit limits, expiry still denies
            # retrieval. A blocked physical purge must not extend authorization.
            with self._transaction():
                record = self._release(identifier, tenant) if release else self._dataset(identifier, tenant)
                parent = self._dataset(record["dataset_id"], tenant) if release else record
                if parent["expires_at"] <= time.time():
                    raise HTTPException(404, "Release not found" if release else "Dataset not found")
            raise

    def reject_release(self, identifier, tenant, reviewer, decided_at):
        self.purge()
        with self._transaction():
            record = self._release(identifier, tenant)
            if self._dataset(record["dataset_id"], tenant)["expires_at"] <= time.time():
                raise HTTPException(404, "Release not found")
            if record["creator"] == reviewer:
                raise HTTPException(403, "Independent reviewer required")
            if record["card"]["eligibility"] != "REVIEW_REQUIRED":
                raise HTTPException(409, "Release is not awaiting review")
            revised = detached(record)
            card = revised["card"]
            card.update(eligibility="BLOCKED", revision=card["revision"] + 1, generated_at=decided_at,
                        gates=[*card["gates"], "REVIEW_REJECTED"])
            revised["review"] = {"decision": "reject", "reviewer": reviewer, "decided_at": decided_at}
            revised["events"].append({"revision": card["revision"], "card": copy.deepcopy(card), "review": copy.deepcopy(revised["review"])})
            revised["size_bytes"] = len(encoded(revised)) + 32
            if revised["size_bytes"] > self.MAX_RELEASE_BYTES:
                raise HTTPException(429, "Development release capacity exceeded")
            self._append_event(tenant, "review.rejected", identifier, reviewer, decided_at, revised)
            self.releases[identifier] = revised
            return detached(revised)

    def delete_dataset(self, identifier, tenant, actor):
        self.purge()
        with self._transaction():
            self._dataset(identifier, tenant)
            self._append_event(tenant, "dataset.deleted", identifier, actor)
            self._delete(identifier, tenant)

    def audit_events(self, tenant, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise HTTPException(429, "Audit result limit exceeded")
        with self._transaction():
            return detached([entry["event"] for entry in self._audit.get(tenant, [])[-limit:]])

    def verify_audit(self, tenant):
        with self._transaction():
            self._verify(tenant)
            return True

    def close(self):
        pass
