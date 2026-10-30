"""Encrypted one-shot repair journal. No eviction, retry, or recovery execution."""

import os
import sqlite3
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gargoyl.repair_contract import (
    MAX_REPAIR_BYTES,
    RepairAuditEntry,
    RepairConfirmation,
    RepairPlan,
    RepairReceipt,
    canonical,
    integer,
    require,
)
from gargoyl.telemetry import PolicyError, host_id

_CONTEXT = b"gargoyl:repair:audit:v1\x00"


class AuditError(PolicyError):
    """Storage unavailable, without exposing filesystem or decrypted content."""


def _error():
    return AuditError("repair audit unavailable")


class RepairAuditStore:
    def __init__(self, directory, *, key, max_records=1000):
        require(type(key) is bytes and len(key) == 32)
        integer(max_records, 1, 10000)
        self._lock = threading.RLock()
        self._cipher = AESGCM(key)
        self._limit = max_records
        self._db = None
        try:
            directory = Path(directory)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._path = directory / "repair-audit.sqlite3"
            existed = self._path.exists()
            if not existed and any(directory.iterdir()):
                raise _error()
            if not existed:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            self._db = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA journal_mode=DELETE")
            if not existed:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("CREATE TABLE records (id TEXT PRIMARY KEY, payload BLOB NOT NULL)")
                self._db.execute("CREATE TABLE inventory (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
                self._db.execute("INSERT INTO inventory VALUES (1, ?)", (self._seal(b"0", b"inventory"),))
                self._commit()
            self._read_all()
        except Exception:
            self.close()
            raise _error() from None

    def _seal(self, payload, identity):
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, payload, _CONTEXT + identity)

    def _open(self, payload, identity):
        return self._cipher.decrypt(payload[:12], payload[12:], _CONTEXT + identity)

    def _commit(self):
        self._db.commit()

    def _read_all(self):
        if self._db is None or not self._path.is_file():
            raise _error()
        # Inspect SQL types and lengths without materializing attacker-sized blobs.
        inventory = self._db.execute(
            "SELECT id, typeof(payload), length(payload) FROM inventory LIMIT 2").fetchall()
        require(len(inventory) == 1 and inventory[0][0] == 1
                and inventory[0][1] == "blob" and 29 <= inventory[0][2] <= 33)
        bounds = self._db.execute(
            "SELECT typeof(id), length(CAST(id AS BLOB)), typeof(payload), length(payload) "
            "FROM records LIMIT 10001").fetchall()
        require(len(bounds) <= 10000)
        require(all(kind == "text" and size == 36 and payload_kind == "blob"
                    and 29 <= payload_size <= MAX_REPAIR_BYTES + 28
                    for kind, size, payload_kind, payload_size in bounds))
        inventory_payload = self._db.execute(
            "SELECT payload FROM inventory WHERE id=1").fetchone()[0]
        count = int(self._open(inventory_payload, b"inventory"))
        require(0 <= count <= 10000 and len(bounds) == count)
        rows = self._db.execute("SELECT id, payload FROM records LIMIT 10000")
        entries = {}
        for identity, payload in rows:
            host_id(identity)
            entry = RepairAuditEntry(self._open(payload, identity.encode("ascii")))
            require(entry.as_dict()["confirmation"]["click_id"] == identity)
            entries[identity] = entry
        return entries

    def _transaction(self, action):
        with self._lock:
            try:
                if self._db is None:
                    raise _error()
                self._db.execute("BEGIN IMMEDIATE")
                result = action(self._read_all())
                self._commit()
                return result
            except Exception:
                if self._db is not None:
                    self._db.rollback()
                raise _error() from None

    def claim(self, plan, confirmation, *, now):
        require(type(plan) is RepairPlan and type(confirmation) is RepairConfirmation)
        entry = RepairAuditEntry(canonical(dict(
            schema_version=1, state="started", plan=plan.as_dict(),
            confirmation=confirmation.as_dict(), started_at=now, receipt=None,
        )))
        identity = confirmation.as_dict()["click_id"]

        def action(entries):
            if identity in entries:
                previous = entries[identity].as_dict()
                require(previous["plan"] == plan.as_dict()
                        and previous["confirmation"] == confirmation.as_dict())
                return False
            require(len(entries) < self._limit)
            self._db.execute("INSERT INTO records VALUES (?, ?)",
                             (identity, self._seal(entry.payload, identity.encode("ascii"))))
            self._db.execute("UPDATE inventory SET payload=? WHERE id=1",
                             (self._seal(str(len(entries) + 1).encode("ascii"), b"inventory"),))
            return True
        return self._transaction(action)

    def lookup(self, click_id):
        host_id(click_id)
        return self._transaction(lambda entries: entries.get(click_id))

    def finalize(self, click_id, receipt):
        host_id(click_id)
        require(type(receipt) is RepairReceipt)
        receipt = RepairReceipt(receipt.payload)

        def action(entries):
            require(click_id in entries)
            value = entries[click_id].as_dict()
            if value["state"] == "finished":
                require(value["receipt"] == receipt.as_dict())
                return entries[click_id]
            value.update(state="finished", receipt=receipt.as_dict())
            terminal = RepairAuditEntry(canonical(value))
            self._db.execute("UPDATE records SET payload=? WHERE id=?",
                             (self._seal(terminal.payload, click_id.encode("ascii")), click_id))
            return terminal
        return self._transaction(action)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
