"""Encrypted, transactional LOCAL development SQLite adapter.

The database, WAL/journal and backups contain ciphertext rather than source text.
Opaque identifiers, tenant, byte counts, expiry and audit sequences remain visible.
Keys are caller-managed. This is not KMS, secure deletion or multi-host storage.
The HMAC chain detects modification/reordering/interior deletion, not whole-store
rollback or terminal audit truncation; those require an external trusted anchor.

Each operation authenticates a bounded snapshot in a BEGIN IMMEDIATE transaction.
This deliberately favors a small verifiable local adapter over scalable throughput.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException

from app.repository import DevelopmentStore, encoded, unavailable


class DurableStore(DevelopmentStore):
    SCHEMA_VERSION = b"anonflow-local-v1"
    MAX_RECORD_BLOB = 6_000_000
    MAX_AUDIT_BLOB = 4096

    @staticmethod
    def _derive_keys(key):
        """Derive the two local-adapter subkeys from one operator-held root key."""
        if type(key) is not bytes or len(key) != 32:
            raise unavailable()
        encryption_key = HKDF(algorithm=hashes.SHA256(), length=32,
                              salt=b"anonflow-local-v1", info=b"record-encryption").derive(key)
        audit_key = HKDF(algorithm=hashes.SHA256(), length=32,
                         salt=b"anonflow-local-v1", info=b"audit-authentication").derive(key)
        return encryption_key, audit_key

    @staticmethod
    def _key_identifier(value):
        """Accept only opaque, non-secret operator key labels.

        The label is encrypted in the key-check sentinel.  It is deliberately
        not an authentication mechanism and is never exposed through the API.
        """
        if (type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii()
                or any(not (character.isalnum() or character in "._-") for character in value)):
            raise unavailable()
        return value

    def __init__(self, path: str, key: bytes):
        super().__init__()
        self._connection = None
        if type(key) is not bytes or len(key) != 32 or not isinstance(path, str) or not path or path == ":memory:":
            raise unavailable()
        try:
            self._encryption_key, self._audit_key = self._derive_keys(key)
            self._cipher = AESGCM(self._encryption_key)
            existed = Path(path).exists()
            self._connection = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in self._connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables and not existed:
                self._connection.execute("CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL)")
                self._connection.execute("CREATE TABLE records (kind TEXT NOT NULL, id TEXT NOT NULL, tenant TEXT NOT NULL, size_bytes INTEGER NOT NULL, expires_at REAL NOT NULL, blob BLOB NOT NULL, PRIMARY KEY(kind,id))")
                self._connection.execute("CREATE TABLE audit (tenant TEXT NOT NULL, seq INTEGER NOT NULL, blob BLOB NOT NULL, PRIMARY KEY(tenant,seq))")
                self._connection.execute("INSERT INTO meta VALUES (?,?)", ("schema", self.SCHEMA_VERSION))
                self._connection.execute("INSERT INTO meta VALUES (?,?)", ("key-check", self._seal({"sentinel": "anonflow-key-check-v1"}, ["meta", "key-check"])))
            else:
                if tables != {"meta", "records", "audit"}:
                    raise unavailable()
                self._check_meta()
            self._load()
            self._connection.execute("COMMIT")
            self.datasets, self.releases, self.controls, self._audit = {}, {}, {kind: {} for kind in self.CONTROL_KINDS}, {}
        except Exception:
            if self._connection is not None:
                try:
                    self._connection.rollback()
                except sqlite3.Error:
                    pass
                try:
                    self._connection.close()
                except sqlite3.Error:
                    pass
                self._connection = None
            raise unavailable() from None

    def _seal(self, record, aad):
        return self._seal_with(self._cipher, record, aad)

    @staticmethod
    def _seal_with(cipher, record, aad):
        nonce = os.urandom(12)
        return nonce + cipher.encrypt(nonce, encoded(record), encoded(["anonflow-local-v1", *aad]))

    def _open(self, blob, aad, maximum):
        if not isinstance(blob, bytes) or not 28 <= len(blob) <= maximum:
            raise unavailable()
        try:
            return json.loads(self._cipher.decrypt(blob[:12], blob[12:], encoded(["anonflow-local-v1", *aad])))
        except (InvalidTag, ValueError, TypeError, UnicodeError):
            raise unavailable() from None

    def _check_meta(self):
        entries = dict(self._connection.execute("SELECT name,value FROM meta"))
        if set(entries) != {"schema", "key-check"} or entries["schema"] != self.SCHEMA_VERSION:
            raise unavailable()
        sentinel = self._open(entries["key-check"], ["meta", "key-check"], 1024)
        if sentinel == {"sentinel": "anonflow-key-check-v1"}:
            return {"generation": 0, "key_id": None}
        if (not isinstance(sentinel, dict) or set(sentinel) != {"sentinel", "generation", "key_id", "previous_key_id"}
                or sentinel.get("sentinel") != "anonflow-key-check-v1" or type(sentinel.get("generation")) is not int
                or not 1 <= sentinel["generation"] <= 1_000_000):
            raise unavailable()
        self._key_identifier(sentinel.get("key_id"))
        previous = sentinel.get("previous_key_id")
        if previous is not None:
            self._key_identifier(previous)
        return {"generation": sentinel["generation"], "key_id": sentinel["key_id"]}

    @classmethod
    def rotate_key(cls, path: str, old_key: bytes, new_key: bytes, *, new_key_id: str) -> None:
        """Atomically re-encrypt a closed local SQLite store under ``new_key``.

        This is a trusted, offline operator primitive; it is intentionally not
        wired to HTTP or environment-driven startup.  It verifies every record
        and authenticated audit event with ``old_key`` before writing anything,
        re-chains audit MACs under the new audit subkey, and verifies the whole
        new state before the single transaction commits.  Any ordinary failure
        rolls back, so the old key remains the only usable key.
        """
        if (not isinstance(path, str) or not path or path == ":memory:" or type(old_key) is not bytes
                or type(new_key) is not bytes or len(old_key) != 32 or len(new_key) != 32
                or hmac.compare_digest(old_key, new_key)):
            raise unavailable()
        new_key_id = cls._key_identifier(new_key_id)
        store = None
        try:
            # Rotation is never an initialization path.  In particular, a
            # spelling error in an operator database path must not create a
            # fresh, apparently successful empty store under the new key.
            if not Path(path).is_file():
                raise unavailable()
            # Constructor authentication also refuses a missing, malformed,
            # wrong-key, or tampered existing database without initializing it.
            store = cls(path, old_key)
            new_encryption_key, new_audit_key = cls._derive_keys(new_key)
            new_cipher = AESGCM(new_encryption_key)
            with store.lock:
                store._connection.execute("BEGIN IMMEDIATE")
                try:
                    # Re-authenticate after acquiring the write lock.  Another
                    # process may have committed between construction and here.
                    prior_key = store._check_meta()
                    store._load()
                    record_rows = list(store._connection.execute(
                        "SELECT kind,id,tenant,size_bytes,expires_at,length(blob) FROM records ORDER BY kind,id"))
                    audit_rows = list(store._connection.execute(
                        "SELECT tenant,seq,length(blob) FROM audit ORDER BY tenant,seq"))
                    # Bound and authenticate the individual encrypted records
                    # before replacing them.  Only one plaintext object exists
                    # at a time and no migration file is created.
                    for kind, identifier, tenant, _size, _expiry, blob_length in record_rows:
                        if kind not in {"dataset", "release", *store.CONTROL_KINDS} or type(blob_length) is not int or not 28 <= blob_length <= store.MAX_RECORD_BLOB:
                            raise unavailable()
                        blob = store._connection.execute(
                            "SELECT blob FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()[0]
                        record = store._open(blob, [tenant, kind, identifier], store.MAX_RECORD_BLOB)
                        replacement = store._seal_with(new_cipher, record, [tenant, kind, identifier])
                        if len(replacement) > store.MAX_RECORD_BLOB:
                            raise unavailable()
                        store._connection.execute("UPDATE records SET blob=? WHERE kind=? AND id=?", (replacement, kind, identifier))
                    # Audit MACs are bound to an audit subkey.  Preserve events
                    # and commitments but reconstruct every chain under the new
                    # key before encrypting the resulting entries.
                    for tenant in sorted(store._audit):
                        previous = "0" * 64
                        for entry in store._audit[tenant]:
                            signature = hmac.new(new_audit_key, encoded([
                                tenant, previous, entry["event"], entry["record_commitment"], entry["parent_id"]
                            ]), hashlib.sha256).hexdigest()
                            entry["mac"] = signature
                            previous = signature
                    for tenant, sequence, blob_length in audit_rows:
                        if type(blob_length) is not int or not 28 <= blob_length <= store.MAX_AUDIT_BLOB:
                            raise unavailable()
                        entries = store._audit.get(tenant)
                        if entries is None or not 1 <= sequence <= len(entries):
                            raise unavailable()
                        replacement = store._seal_with(new_cipher, entries[sequence - 1], [tenant, "audit", sequence])
                        if len(replacement) > store.MAX_AUDIT_BLOB:
                            raise unavailable()
                        store._connection.execute("UPDATE audit SET blob=? WHERE tenant=? AND seq=?", (replacement, tenant, sequence))
                    sentinel = {
                        "sentinel": "anonflow-key-check-v1",
                        "generation": prior_key["generation"] + 1,
                        "key_id": new_key_id,
                        "previous_key_id": prior_key["key_id"],
                    }
                    store._connection.execute("UPDATE meta SET value=? WHERE name='key-check'",
                                              (store._seal_with(new_cipher, sentinel, ["meta", "key-check"]),))
                    # Validate the post-rotation rows, AAD and re-chained audit
                    # before making the transaction durable.
                    store._encryption_key, store._audit_key, store._cipher = new_encryption_key, new_audit_key, new_cipher
                    store._load()
                    store._connection.execute("COMMIT")
                except Exception:
                    try:
                        store._connection.rollback()
                    except sqlite3.Error:
                        pass
                    raise
                except BaseException:
                    try:
                        store._connection.rollback()
                    except sqlite3.Error:
                        pass
                    raise
        except HTTPException:
            raise unavailable() from None
        except Exception:
            raise unavailable()
        finally:
            if store is not None:
                store.close()

    def _load(self):
        self._check_meta()
        self.datasets, self.releases, self.controls, self._audit = {}, {}, {kind: {} for kind in self.CONTROL_KINDS}, {}
        # Upper physical limits are fixed independently of per-instance lowered
        # quota settings used by callers/tests. SELECT limits avoid unbounded load.
        count = self._connection.execute("SELECT COUNT(*) FROM (SELECT 1 FROM records LIMIT ?)",
                                         (DevelopmentStore.MAX_DATASETS + DevelopmentStore.MAX_RELEASES + DevelopmentStore.MAX_CONTROLS + 1,)).fetchone()[0]
        if count > DevelopmentStore.MAX_DATASETS + DevelopmentStore.MAX_RELEASES + DevelopmentStore.MAX_CONTROLS:
            raise unavailable()
        # Read SQLite metadata before any BLOB payload. A corrupted database can
        # otherwise force Python to materialize an unbounded value during load.
        for kind, identifier, tenant, size, expiry, blob_length in self._connection.execute("SELECT kind,id,tenant,size_bytes,expires_at,length(blob) FROM records"):
            if kind not in {"dataset", "release", *self.CONTROL_KINDS}:
                raise unavailable()
            if type(blob_length) is not int or not 28 <= blob_length <= self.MAX_RECORD_BLOB:
                raise unavailable()
            blob = self._connection.execute("SELECT blob FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()[0]
            record = self._open(blob, [tenant, kind, identifier], self.MAX_RECORD_BLOB)
            if record["id"] != identifier or record["tenant"] != tenant or record["size_bytes"] != size or record["expires_at"] != expiry:
                raise unavailable()
            if kind in self.CONTROL_KINDS:
                try:
                    self._validate_control(record)
                except HTTPException:
                    raise unavailable() from None
                if record["kind"] != kind:
                    raise unavailable()
            target = self.datasets if kind == "dataset" else self.releases if kind == "release" else self.controls[kind]
            target[identifier] = record
        if len(self.datasets) > DevelopmentStore.MAX_DATASETS or len(self.releases) > DevelopmentStore.MAX_RELEASES:
            raise unavailable()
        if sum(record["size_bytes"] for record in self.datasets.values()) > DevelopmentStore.MAX_SOURCE_BYTES:
            raise unavailable()
        if (sum(len(values) for values in self.controls.values()) > DevelopmentStore.MAX_CONTROLS
                or any(sum(record["tenant"] == tenant for values in self.controls.values() for record in values.values()) > DevelopmentStore.MAX_CONTROLS_PER_TENANT
                       for tenant in {record["tenant"] for values in self.controls.values() for record in values.values()})):
            raise unavailable()
        for record in self.releases.values():
            parent = self.datasets.get(record["dataset_id"])
            if parent is None or parent["tenant"] != record["tenant"] or parent["expires_at"] != record["expires_at"]:
                raise unavailable()
        count = self._connection.execute("SELECT COUNT(*) FROM (SELECT 1 FROM audit LIMIT ?)",
                                         (DevelopmentStore.MAX_AUDIT_EVENTS + 1,)).fetchone()[0]
        if count > DevelopmentStore.MAX_AUDIT_EVENTS:
            raise unavailable()
        for tenant, sequence, blob_length in self._connection.execute("SELECT tenant,seq,length(blob) FROM audit ORDER BY tenant,seq"):
            if type(blob_length) is not int or not 28 <= blob_length <= self.MAX_AUDIT_BLOB:
                raise unavailable()
            blob = self._connection.execute("SELECT blob FROM audit WHERE tenant=? AND seq=?", (tenant, sequence)).fetchone()[0]
            entry = self._open(blob, [tenant, "audit", sequence], self.MAX_AUDIT_BLOB)
            entries = self._audit.setdefault(tenant, [])
            if sequence != len(entries) + 1 or entry["event"]["seq"] != sequence:
                raise unavailable()
            entries.append(entry)
        self._verify_all()
        self._verify_current_records()

    def _verify_current_records(self):
        """Bind current state to latest authenticated event; isolated replay fails.

        No local check can detect a consistent rollback of BOTH records/history.
        Commitments stay inside encrypted audit entries, never public API output.
        """
        latest = {}
        for tenant, entries in self._audit.items():
            for entry in entries:
                action = entry["event"]["action"]
                kind = "release" if action.startswith("review.") else action.split(".", 1)[0]
                if kind not in {"dataset", "release", *self.CONTROL_KINDS}:
                    raise unavailable()
                latest[(tenant, kind, entry["event"]["object_id"])] = entry
        live = {(record["tenant"], kind, identifier): record for kind, records in
                (("dataset", self.datasets), ("release", self.releases), *self.controls.items()) for identifier, record in records.items()}
        for identity, record in live.items():
            entry = latest.get(identity)
            if entry is None or entry["record_commitment"] is None:
                raise unavailable()
            if not hmac.compare_digest(hashlib.sha256(encoded(record)).hexdigest(), entry["record_commitment"]):
                raise unavailable()
        for (tenant, kind, identifier), entry in latest.items():
            if entry["record_commitment"] is None or (tenant, kind, identifier) in live:
                continue
            # Dataset deletion/expiry intentionally cascades its release rows.
            parent = latest.get((tenant, "dataset", entry["parent_id"])) if kind == "release" else None
            if parent is None or parent["record_commitment"] is not None:
                raise unavailable()

    def _save(self, before):
        old_datasets, old_releases, old_controls, old_audit = before
        for kind, old, current in (("dataset", old_datasets, self.datasets), ("release", old_releases, self.releases),
                                   *((kind, old_controls[kind], self.controls[kind]) for kind in self.CONTROL_KINDS)):
            for identifier in old.keys() - current.keys():
                self._connection.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, identifier))
            for identifier, record in current.items():
                if old.get(identifier) == record:
                    continue
                blob = self._seal(record, [record["tenant"], kind, identifier])
                if len(blob) > self.MAX_RECORD_BLOB:
                    raise HTTPException(429, "Development storage capacity exceeded")
                self._connection.execute("INSERT INTO records(kind,id,tenant,size_bytes,expires_at,blob) VALUES (?,?,?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET tenant=excluded.tenant,size_bytes=excluded.size_bytes,expires_at=excluded.expires_at,blob=excluded.blob",
                                         (kind, identifier, record["tenant"], record["size_bytes"], record["expires_at"], blob))
        for tenant, entries in self._audit.items():
            for entry in entries[len(old_audit.get(tenant, [])):]:
                sequence = entry["event"]["seq"]
                blob = self._seal(entry, [tenant, "audit", sequence])
                if len(blob) > self.MAX_AUDIT_BLOB:
                    raise HTTPException(429, "Development audit capacity exceeded")
                self._connection.execute("INSERT INTO audit(tenant,seq,blob) VALUES (?,?,?)", (tenant, sequence, blob))

    @contextmanager
    def _transaction(self):
        with self.lock:
            if self._connection is None:
                raise unavailable()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._load()
                before = copy.deepcopy((self.datasets, self.releases, self.controls, self._audit))
                yield
                self._save(before)
                self._connection.execute("COMMIT")
            except HTTPException:
                self._rollback()
                raise
            except Exception:
                self._rollback()
                raise unavailable() from None
            except BaseException:
                self._rollback()
                raise
            finally:
                # Avoid a long-lived decrypted cache spanning tenants/requests.
                self.datasets, self.releases, self.controls, self._audit = {}, {}, {kind: {} for kind in self.CONTROL_KINDS}, {}

    def _rollback(self):
        try:
            self._connection.rollback()
        except sqlite3.Error:
            raise unavailable() from None

    def close(self):
        with self.lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self.datasets, self.releases, self.controls, self._audit = {}, {}, {kind: {} for kind in self.CONTROL_KINDS}, {}
