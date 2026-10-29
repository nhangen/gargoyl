"""Single-writer encrypted local history and outbound delivery.

Use a private, application-owned directory on a trusted local filesystem. Keys
are supplied externally and never stored here. SQLite transactions retain either
the previous or next complete history; only encrypted snapshots reach SQLite.
Delivery is at-least-once: a crash after server acceptance can replay a snapshot.
The receiver must deduplicate. No deployment or credential provisioning is provided.
"""
import http.client
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from gargoyl.security import export_batch, prepare_transmission
from gargoyl.telemetry import PolicyError, decode_snapshot, timestamp


class EncryptedHistory:
    def __init__(self, directory, cipher, policy, now):
        self.cipher, self.policy = cipher, policy
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise PermissionError("spool requires a private owned directory")
        path = directory / "history.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
                raise PermissionError("spool requires a private owned file")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path)
        try:
            self.db.execute("PRAGMA secure_delete = ON")
            self.db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL, sent INTEGER NOT NULL DEFAULT 0)")
            with self._transaction():
                self._prune(now)
        except Exception:
            self.db.close()
            raise

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _prune(self, now):
        if self.db.execute("SELECT 1 FROM history WHERE length(payload) > 65568 LIMIT 1").fetchone():
            raise PolicyError("spool record exceeds size bound")
        rows = self.db.execute("SELECT id, payload, sent FROM history ORDER BY id").fetchmany(10002)
        if len(rows) > 10001:
            raise PolicyError("spool exceeds record bound")
        current = timestamp(now)
        # Authentication/validation precedes retention decisions for every row.
        decoded = [(key, self.cipher.open(payload), sent) for key, payload, sent in rows]
        # Storage age has only a lower cutoff. A future-relative record can be
        # evidence of clock rollback, so quarantine it rather than deleting it.
        eligible = [row for row in decoded
                    if (current - timestamp(row[1]["collected_at"])).total_seconds()
                    <= self.policy.max_age_seconds]
        newest = sorted(eligible, key=lambda row: (timestamp(row[1]["collected_at"]), row[0]))
        keep = {row[0] for row in newest[-self.policy.max_records:]}
        for key, _, _ in decoded:
            if key not in keep:
                self.db.execute("DELETE FROM history WHERE id = ?", (key,))
        return [row for row in decoded if row[0] in keep]

    def append(self, snapshot, now):
        encrypted = self.cipher.seal(snapshot)  # validation before any disk mutation
        with self._transaction():
            self._prune(now)
            self.db.execute("INSERT INTO history(payload) VALUES (?)", (encrypted,))
            self._prune(now)

    def pending(self, now):
        with self._transaction():
            rows = self._prune(now)
            # Export eligibility is narrower than retention: future-relative
            # records remain encrypted but cannot be sent until time catches up.
            return [(key, item) for key, item, sent in rows
                    if not sent and timestamp(item["collected_at"]) <= timestamp(now)]

    def acknowledge(self, record_id):
        with self._transaction():
            self.db.execute("UPDATE history SET sent = 1 WHERE id = ?", (record_id,))

    def close(self):
        self.db.close()


class OutboundHTTPS:
    """POST bounded telemetry with foundation mTLS; redirects are failures."""
    def __init__(self, config, identity):
        self.identity = identity
        self.context = config.ssl_context()  # fail closed before any network call
        self.url = urlsplit(config.endpoint)

    def send(self, snapshot):
        payload = prepare_transmission(snapshot, self.identity)
        connection = http.client.HTTPSConnection(self.url.hostname, self.url.port,
                                                  context=self.context, timeout=10)
        try:
            connection.request("POST", self.url.path or "/", body=payload,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            # 202 means accepted for later handling, not durable acknowledgement.
            return response.status in (200, 201, 204)
        finally:
            connection.close()


def deliver_pending(history, transport, schedule, *, now, monotonic_now):
    """Try one retained snapshot per tick. Keep recording independently of this.

    Return idle/sent/retry. No remote exception text is persisted or exported.
    Transport success must mean durable acceptance by the configured receiver.
    """
    if not schedule.ready(monotonic_now):
        return "idle"
    pending = history.pending(now)
    if not pending:
        return "idle"
    record_id, snapshot = pending[0]
    payloads = export_batch([snapshot], now, history.policy)
    if not payloads:
        return "idle"
    try:
        success = transport.send(decode_snapshot(payloads[0]))
    except Exception:
        success = False
    if success is True:
        history.acknowledge(record_id)
        schedule.succeeded(monotonic_now)
        return "sent"
    schedule.failed(monotonic_now)
    return "retry"
