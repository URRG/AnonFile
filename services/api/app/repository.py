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
    TTL_SECONDS = 3600

    def __init__(self):
        self.lock = RLock()
        self.datasets = {}
        self.releases = {}
        self._audit = {}
        self._audit_key = secrets.token_bytes(32)

    @contextmanager
    def _transaction(self):
        with self.lock:
            self._verify_all()
            before = copy.deepcopy((self.datasets, self.releases, self._audit))
            try:
                yield
            except BaseException:
                self.datasets, self.releases, self._audit = before
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

    def purge(self):
        with self._transaction():
            return self._purge()

    def _delete(self, identifier, tenant):
        del self.datasets[identifier]
        for key in list(self.releases):
            if self.releases[key]["dataset_id"] == identifier and self.releases[key]["tenant"] == tenant:
                del self.releases[key]

    def _dataset(self, identifier, tenant):
        result = self.datasets.get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Dataset not found")
        return result

    def _used_identifier(self, identifier, kind):
        return any(entry["event"]["object_id"] == identifier
                   and entry["event"]["action"] == kind + ".created"
                   for entries in self._audit.values() for entry in entries)

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
