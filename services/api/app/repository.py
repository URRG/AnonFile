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


def unavailable():
    return HTTPException(503, "Storage unavailable or integrity verification failed")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def detached(value):
    return json.loads(encoded(value))


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
    CONTROL_KINDS = frozenset({"rights_profile", "policy_snapshot", "processing_run", "authorization_request"})
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
        admission = action in {"dataset.created", "release.created"}
        tenant_limit = int(self.MAX_AUDIT_EVENTS_PER_TENANT * .8) if admission else self.MAX_AUDIT_EVENTS_PER_TENANT
        global_limit = int(self.MAX_AUDIT_EVENTS * .8) if admission else self.MAX_AUDIT_EVENTS
        if len(entries) >= tenant_limit or sum(map(len, self._audit.values())) >= global_limit:
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

    def _purge(self):
        expired = [d for d in self.datasets.values() if d["expires_at"] <= time.time()]
        for record in expired:
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
            self._append_event(record["tenant"], kind + ".expired", identifier, "system")
            del self.controls[kind][identifier]
            if kind in {"rights_profile", "policy_snapshot"}:
                self._invalidate_runs(record["tenant"], kind + "_id", identifier)
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
        """Tombstone registered metadata when a bound prerequisite disappears."""
        for run_id, record in list(self.controls["processing_run"].items()):
            if record["tenant"] != tenant or record["payload"].get(dependency_key) != identifier:
                continue
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
