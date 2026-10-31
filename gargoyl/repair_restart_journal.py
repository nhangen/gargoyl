"""Single-host v2 encrypted attempt journal and atomic unresolved-attempt gate.

Every claimed attempt keeps the host gated until explicit signed read-only
reconciliation, even after success. Consumed IDs are never reset or evicted.
"""

import hashlib
import os
import sqlite3
import stat
import threading
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gargoyl.repair_contract import (
    MAX_REPAIR_BYTES,
    canonical,
    exact,
    integer,
    key_id,
    parse,
    require,
)
from gargoyl.repair_restart_contract import (
    ProviderProof,
    RestartConfirmation,
    RestartPlan,
    RestartReceipt,
    bind_confirmation,
    request_bytes,
)
from gargoyl.repair_restart_policy import RestartPolicy
from gargoyl.telemetry import PolicyError, host_id, timestamp


class RestartJournalError(PolicyError):
    pass


class RestartPending(PolicyError):
    pass


def _entry(value, target_host):
    exact(
        value,
        "schema_version plan confirmation operator_proof request_digest started_at state receipt resolution",
    )
    integer(value["schema_version"], 2, 2)
    plan = RestartPlan(canonical(value["plan"]))
    confirmation = RestartConfirmation(canonical(value["confirmation"]))
    bind_confirmation(plan, confirmation, value["started_at"])
    require(plan.as_dict()["target_host"] == target_host)
    exact(value["operator_proof"], "key_id signature")
    key_id(value["operator_proof"]["key_id"])
    sig = value["operator_proof"]["signature"]
    require(type(sig) is str and len(sig) == 128 and sig == sig.lower())
    operator = dict(
        key_id=value["operator_proof"]["key_id"], signature=bytes.fromhex(sig)
    )
    require(
        value["request_digest"]
        == hashlib.sha256(request_bytes(plan, confirmation, operator)).hexdigest()
    )
    require(value["state"] in {"started", "finished"})
    if value["state"] == "started":
        require(value["receipt"] is None)
    else:
        receipt = RestartReceipt(canonical(value["receipt"])).as_dict()
        require(
            receipt["target_host"] == target_host
            and receipt["attempt_id"] == value["confirmation"]["click_id"]
            and receipt["plan_digest"] == plan.digest
        )
    if value["resolution"] is not None:
        proof = ProviderProof(canonical(value["resolution"])).as_dict()
        require(
            proof["kind"] == "reconciliation"
            and proof["body"]["host_id"] == target_host
            and proof["body"]["attempt_id"] == value["confirmation"]["click_id"]
            and proof["body"]["request_digest"] == value["request_digest"]
        )
    return value


class RestartJournal:
    @classmethod
    def create(cls, directory, *, target_host, key, max_records=1000):
        """Explicit provisioning only, never an automatic runtime fallback."""
        return cls(
            directory,
            target_host=target_host,
            key=key,
            max_records=max_records,
            _create=True,
        )

    def __init__(self, directory, *, target_host, key, max_records=1000, _create=False):
        host_id(target_host)
        require(type(key) is bytes and len(key) == 32)
        integer(max_records, 1, 1000)
        self.target_host, self._limit = target_host, max_records
        self._cipher, self._lock, self._db = AESGCM(key), threading.RLock(), None
        self._context = (
            b"gargoyl:pre-drained-restart:journal:v2\x00" + target_host.encode("ascii")
        )
        try:
            directory = Path(directory)
            require(directory.is_absolute() and type(_create) is bool)
            parent = directory.parent.lstat()
            require(
                stat.S_ISDIR(parent.st_mode)
                and parent.st_uid == os.getuid()
                and not parent.st_mode & 0o077
            )
            if _create:
                directory.mkdir(mode=0o700, exist_ok=True)
            info = directory.lstat()
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and not info.st_mode & 0o077
            )
            self._directory_identity = info.st_dev, info.st_ino
            self._path = directory / "restart-v2.sqlite3"
            existed = self._path.exists()
            require(existed != _create)
            if _create:
                require(not any(directory.iterdir()))
                fd = os.open(
                    self._path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                    0o600,
                )
                os.close(fd)
            info = self._path.lstat()
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and not info.st_mode & 0o077
                and info.st_nlink == 1
            )
            self._file_identity = info.st_dev, info.st_ino
            self._db = sqlite3.connect(
                self._path.as_uri() + "?mode=rw",
                uri=True,
                isolation_level=None,
                check_same_thread=False,
            )
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA journal_mode=DELETE")
            if _create:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(
                    "CREATE TABLE records (id TEXT PRIMARY KEY,payload BLOB NOT NULL)"
                )
                self._db.execute(
                    "CREATE TABLE inventory (id INTEGER PRIMARY KEY,payload BLOB NOT NULL)"
                )
                self._db.execute(
                    "INSERT INTO inventory VALUES (1,?)",
                    (self._seal(canonical(dict(count=0, active=None)), b"inventory"),),
                )
                self._commit()
            self._read()
        except Exception:
            self.close()
            raise RestartJournalError("restart journal unavailable") from None

    def _seal(self, data, identity):
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, data, self._context + identity)

    def _open(self, data, identity):
        return self._cipher.decrypt(data[:12], data[12:], self._context + identity)

    def _commit(self):
        self._db.commit()

    def _read(self):
        directory = self._path.parent.lstat()
        require(
            stat.S_ISDIR(directory.st_mode)
            and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077
            and (directory.st_dev, directory.st_ino) == self._directory_identity
        )
        info = self._path.lstat()
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077
            and info.st_nlink == 1
            and (info.st_dev, info.st_ino) == self._file_identity
        )
        inventory = self._db.execute(
            "SELECT id,typeof(payload),length(payload) FROM inventory LIMIT 2"
        ).fetchall()
        require(
            len(inventory) == 1
            and inventory[0][0] == 1
            and inventory[0][1] == "blob"
            and 29 <= inventory[0][2] <= 1024
        )
        bounds = self._db.execute(
            "SELECT typeof(id),length(CAST(id AS BLOB)),typeof(payload),length(payload) FROM records LIMIT 1001"
        ).fetchall()
        require(
            len(bounds) <= 1000
            and all(
                t == "text"
                and n == 36
                and b == "blob"
                and 29 <= s <= MAX_REPAIR_BYTES + 28
                for t, n, b, s in bounds
            )
        )
        data = self._db.execute("SELECT payload FROM inventory WHERE id=1").fetchone()[
            0
        ]
        inventory = parse(self._open(data, b"inventory"))
        exact(inventory, "count active")
        integer(inventory["count"], 0, 1000)
        require(inventory["count"] == len(bounds))
        if inventory["active"] is not None:
            host_id(inventory["active"])
        entries = {}
        for identity, payload in self._db.execute(
            "SELECT id,payload FROM records LIMIT 1000"
        ):
            host_id(identity)
            entry = _entry(
                parse(self._open(payload, identity.encode("ascii"))), self.target_host
            )
            require(entry["confirmation"]["click_id"] == identity)
            entries[identity] = entry
        active = inventory["active"]
        require(
            active is None
            or active in entries
            and entries[active]["resolution"] is None
        )
        return inventory, entries

    def _transaction(self, action):
        with self._lock:
            try:
                require(self._db is not None)
                self._db.execute("BEGIN IMMEDIATE")
                inventory, entries = self._read()
                result = action(inventory, entries)
                self._commit()
                return result
            except RestartPending:
                self._db.rollback()
                raise
            except Exception:
                if self._db is not None:
                    try:
                        self._db.rollback()
                    except Exception:
                        pass
                raise RestartJournalError("restart journal unavailable") from None

    def _write(self, identity, value):
        data = canonical(_entry(value, self.target_host))
        self._db.execute(
            "INSERT OR REPLACE INTO records VALUES (?,?)",
            (identity, self._seal(data, identity.encode("ascii"))),
        )

    def _inventory(self, value):
        self._db.execute(
            "UPDATE inventory SET payload=? WHERE id=1",
            (self._seal(canonical(value), b"inventory"),),
        )

    def claim(self, plan, confirmation, operator, *, now):
        bind_confirmation(plan, confirmation, now)
        require(plan.as_dict()["target_host"] == self.target_host)
        request = request_bytes(plan, confirmation, operator)
        identity = confirmation.as_dict()["click_id"]
        value = dict(
            schema_version=2,
            plan=plan.as_dict(),
            confirmation=confirmation.as_dict(),
            operator_proof=dict(
                key_id=operator["key_id"], signature=operator["signature"].hex()
            ),
            request_digest=hashlib.sha256(request).hexdigest(),
            started_at=now,
            state="started",
            receipt=None,
            resolution=None,
        )
        canonical(_entry(value, self.target_host))

        def action(inventory, entries):
            if identity in entries:
                prior = entries[identity]
                require(
                    all(
                        prior[k] == value[k]
                        for k in (
                            "plan",
                            "confirmation",
                            "operator_proof",
                            "request_digest",
                        )
                    )
                )
                return False
            if inventory["active"] is not None:
                raise RestartPending("read-only reconciliation required")
            require(len(entries) < self._limit)
            self._write(identity, value)
            inventory.update(count=len(entries) + 1, active=identity)
            self._inventory(inventory)
            return True

        return self._transaction(action)

    def finish(self, receipt):
        require(type(receipt) is RestartReceipt)
        value = receipt.as_dict()
        identity = value["attempt_id"]

        def action(inventory, entries):
            require(identity in entries)
            entry = entries[identity]
            if entry["state"] == "finished":
                require(entry["receipt"] == value)
                return
            require(inventory["active"] == identity and entry["resolution"] is None)
            entry.update(state="finished", receipt=value)
            self._write(identity, entry)
            # Never release the gate based on timeout, a client receipt or age.
            # Even known success uses explicit read-only reconciliation before
            # another separately confirmed attempt.

        self._transaction(action)

    def pending(self):
        return self._transaction(
            lambda inventory, entries: entries.get(inventory["active"])
        )

    def lookup(self, identity):
        host_id(identity)
        return self._transaction(lambda inventory, entries: entries.get(identity))

    def reconcile(self, proof, *, policy, wall_clock):
        require(
            type(proof) is ProviderProof
            and type(policy) is RestartPolicy
            and policy.target_host == self.target_host
            and callable(wall_clock)
        )

        def action(inventory, entries):
            identity = inventory["active"]
            require(identity is not None)
            entry = entries[identity]
            now = wall_clock()
            timestamp(now)
            policy.reconciliation(proof, entry, now)
            checked = wall_clock()
            require(timestamp(checked) >= timestamp(now))
            body = proof.as_dict()["body"]
            require(
                timestamp(body["observed_at"])
                <= timestamp(checked)
                < timestamp(body["expires_at"])
            )
            entry["resolution"] = proof.as_dict()
            self._write(identity, entry)
            inventory["active"] = None
            self._inventory(inventory)
            return True

        return self._transaction(action)

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
