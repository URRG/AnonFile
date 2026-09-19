"""Bounded, expiring process-local development store, not durable infrastructure."""
import copy
import time
from threading import RLock
from fastapi import HTTPException

class DevelopmentStore:
    MAX_DATASETS = 100
    MAX_DATASETS_PER_TENANT = 25
    MAX_RELEASES = 500
    MAX_RELEASES_PER_TENANT = 100
    MAX_SOURCE_BYTES = 20_000_000
    MAX_TENANT_SOURCE_BYTES = 5_000_000
    TTL_SECONDS = 3600

    def __init__(self):
        self.lock = RLock()
        self.datasets = {}
        self.releases = {}

    def purge(self):
        """Caller holds lock. Expiry is enforced on access, not secure erasure."""
        clock = time.monotonic()
        expired = {key for key, record in self.datasets.items() if record["expires_at"] <= clock}
        for key in expired:
            del self.datasets[key]
        for key in list(self.releases):
            if self.releases[key]["dataset_id"] not in self.datasets:
                del self.releases[key]

    def add_dataset(self, record):
        with self.lock:
            self.purge()
            tenant_records = [r for r in self.datasets.values() if r["tenant"] == record["tenant"]]
            if (len(self.datasets) >= self.MAX_DATASETS or len(tenant_records) >= self.MAX_DATASETS_PER_TENANT
                    or sum(r["size_bytes"] for r in self.datasets.values()) + record["size_bytes"] > self.MAX_SOURCE_BYTES
                    or sum(r["size_bytes"] for r in tenant_records) + record["size_bytes"] > self.MAX_TENANT_SOURCE_BYTES):
                raise HTTPException(429, "Development storage capacity exceeded")
            record["expires_at"] = time.monotonic() + self.TTL_SECONDS
            self.datasets[record["id"]] = copy.deepcopy(record)

    def get_dataset(self, identifier, tenant):
        self.purge()
        result = self.datasets.get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Dataset not found")
        return result

    def get_release(self, identifier, tenant):
        self.purge()
        result = self.releases.get(identifier)
        if result is None or result["tenant"] != tenant:
            raise HTTPException(404, "Release not found")
        return result

    def check_release_capacity(self, tenant):
        if len(self.releases) >= self.MAX_RELEASES or sum(r["tenant"] == tenant for r in self.releases.values()) >= self.MAX_RELEASES_PER_TENANT:
            raise HTTPException(429, "Development release capacity exceeded")
