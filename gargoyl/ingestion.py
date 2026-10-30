"""Bounded encrypted receiver history and explicit certificate authorization.

The directory must live under a trusted, application-owned parent. Keys and the
certificate grant registry are supplied by the caller; this module provisions
nothing and never grants repair authority.
"""

import hashlib
import os
import re
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from gargoyl.security import RetentionPolicy, SpoolCipher
from gargoyl.telemetry import (
    MAX_PAYLOAD_BYTES,
    METRICS,
    SOURCES,
    PolicyError,
    decode_snapshot,
    encode_snapshot,
    host_id,
    timestamp,
)

MAX_HOSTS = 16
MAX_TOTAL_RECORDS = 10000
MAX_PRINCIPALS = 64


class EvidenceReadError(RuntimeError):
    """Safe error indicating that no complete evidence view can be returned."""


class EvidenceWriteError(RuntimeError):
    """Safe error indicating that durable acceptance was not established."""


def _private_directory(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise PermissionError("evidence requires a private owned directory")
    path = directory / "evidence.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise PermissionError("evidence requires a private owned file")
    finally:
        os.close(fd)
    return path


class EvidenceStore:
    """Serialized transactional reads/writes, with per-host encrypted payloads.

    Cipher inventory is fixed for the store lifetime. At most 16 hosts and 10000
    total retained records are allowed. Each host uses the supplied retention
    policy. Deleting hosts/rotating keys requires a separate migration, not an
    automatic fallback. snapshots() includes future-relative evidence.
    """

    def __init__(self, directory, ciphers_by_host, policy, now):
        timestamp(now)
        if not isinstance(policy, RetentionPolicy):
            raise ValueError("explicit retention policy required")
        if (
            type(ciphers_by_host) is not dict
            or not 1 <= len(ciphers_by_host) <= MAX_HOSTS
            or len(ciphers_by_host) * policy.max_records > MAX_TOTAL_RECORDS
        ):
            raise ValueError("invalid bounded evidence inventory")
        for identity, cipher in ciphers_by_host.items():
            host_id(identity)
            if (
                not isinstance(cipher, SpoolCipher)
                or cipher.identity.host_id != identity
            ):
                raise ValueError("cipher inventory identity mismatch")
        self._ciphers = dict(ciphers_by_host)
        self._policy = policy
        self._limit = len(self._ciphers) * policy.max_records
        self._lock = threading.RLock()
        self._db = None
        try:
            self._db = sqlite3.connect(
                _private_directory(directory), check_same_thread=False
            )
            self._db.execute("PRAGMA journal_mode = DELETE")
            self._db.execute("PRAGMA synchronous = FULL")
            self._db.execute("PRAGMA secure_delete = ON")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS evidence ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, "
                "digest TEXT UNIQUE NOT NULL, payload BLOB NOT NULL)"
            )
            with self._transaction():
                self._retained(now)
        except Exception:
            if self._db is not None:
                self._db.close()
            raise EvidenceReadError("evidence unavailable") from None

    @property
    def configured_hosts(self):
        """Immutable inventory identifiers only; never expose ciphers or keys."""
        return frozenset(self._ciphers)

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def _retained(self, now, *, inserting=False):
        current = timestamp(now)
        # Bound the bytes and row count before fetching any encrypted payloads.
        oversized = self._db.execute(
            "SELECT 1 FROM evidence WHERE typeof(payload) != 'blob' "
            "OR length(payload) > ? OR typeof(host) != 'text' OR length(host) != 36 "
            "OR typeof(digest) != 'text' OR length(digest) != 64 LIMIT 1",
            (MAX_PAYLOAD_BYTES + 32,),
        ).fetchone()
        if oversized:
            raise PolicyError("invalid evidence record")
        rows = self._db.execute(
            "SELECT id, host, digest, payload FROM evidence ORDER BY id LIMIT ?",
            (self._limit + 2,),
        ).fetchall()
        if len(rows) > self._limit + int(inserting):
            raise PolicyError("evidence count exceeds configured bound")
        decoded = []
        for sequence, identity, digest, payload in rows:
            cipher = self._ciphers.get(identity)
            if cipher is None:
                raise PolicyError("evidence identity unavailable")
            snapshot = cipher.open(payload)
            actual_digest = hashlib.sha256(encode_snapshot(snapshot)).hexdigest()
            if snapshot["host_id"] != identity or actual_digest != digest:
                raise PolicyError("evidence metadata mismatch")
            decoded.append((sequence, snapshot))
        # Authenticate every row before pruning; corruption cannot hide behind expiry.
        keep = set()
        for identity in self._ciphers:
            eligible = [
                (sequence, item)
                for sequence, item in decoded
                if item["host_id"] == identity
                and (current - timestamp(item["collected_at"])).total_seconds()
                <= self._policy.max_age_seconds
            ]
            eligible.sort(key=lambda row: (timestamp(row[1]["collected_at"]), row[0]))
            keep.update(
                sequence for sequence, _ in eligible[-self._policy.max_records :]
            )
        for sequence, _ in decoded:
            if sequence not in keep:
                self._db.execute("DELETE FROM evidence WHERE id = ?", (sequence,))
        return [item for sequence, item in decoded if sequence in keep]

    def accept(self, snapshot, *, now):
        # Validate and seal before any persistence mutation.
        payload = encode_snapshot(snapshot)
        snapshot = decode_snapshot(payload)
        current = timestamp(now)
        identity = snapshot["host_id"]
        cipher = self._ciphers.get(identity)
        if cipher is None:
            raise PermissionError("evidence host is not configured")
        if (
            current - timestamp(snapshot["collected_at"])
        ).total_seconds() > self._policy.max_age_seconds:
            raise PolicyError("evidence outside retention")
        encrypted = cipher.seal(snapshot)
        digest = hashlib.sha256(payload).hexdigest()
        try:
            with self._transaction():
                self._retained(now)
                existing = self._db.execute(
                    "SELECT payload FROM evidence WHERE digest = ?", (digest,)
                ).fetchone()
                if existing:
                    if encode_snapshot(cipher.open(existing[0])) != payload:
                        raise PolicyError("evidence digest collision")
                else:
                    self._db.execute(
                        "INSERT INTO evidence(host, digest, payload) VALUES (?, ?, ?)",
                        (identity, digest, encrypted),
                    )
                self._retained(now, inserting=True)
                if not self._db.execute(
                    "SELECT 1 FROM evidence WHERE digest = ?", (digest,)
                ).fetchone():
                    raise PolicyError("evidence excluded by retention capacity")
            return True
        except Exception:
            raise EvidenceWriteError("evidence was not durably accepted") from None

    def snapshots(self, *, now):
        try:
            with self._transaction():
                return self._retained(now)
        except Exception:
            raise EvidenceReadError("evidence unavailable") from None

    def close(self):
        with self._lock:
            self._db.close()


@dataclass(frozen=True)
class Principal:
    host_ids: frozenset[str]
    grants: frozenset[tuple[str, str]]

    def __post_init__(self):
        if (
            type(self.host_ids) is not frozenset
            or not 1 <= len(self.host_ids) <= MAX_HOSTS
        ):
            raise ValueError("invalid principal host inventory")
        for identity in self.host_ids:
            host_id(identity)
        if type(self.grants) is not frozenset or not self.grants:
            raise ValueError("explicit metric/source grants required")
        for grant in self.grants:
            if (
                type(grant) is not tuple
                or len(grant) != 2
                or grant[0] not in METRICS
                or grant[1] not in SOURCES
            ):
                raise ValueError("invalid metric/source grant")


class IngestionService:
    """Authorize a peer certificate supplied ONLY by a verified mTLS connection."""

    def __init__(self, store, principals_by_certificate_sha256):
        registry = principals_by_certificate_sha256
        if type(registry) is not dict or not 1 <= len(registry) <= MAX_PRINCIPALS:
            raise ValueError("invalid certificate registry")
        for digest, principal in registry.items():
            if (
                type(digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or not isinstance(principal, Principal)
            ):
                raise ValueError("invalid certificate registry entry")
        self._store = store
        self._principals = dict(registry)

    def accept(self, payload, peer_certificate_der, *, now):
        if (
            type(peer_certificate_der) is not bytes
            or not 1 <= len(peer_certificate_der) <= 16384
        ):
            raise PermissionError("peer identity rejected")
        principal = self._principals.get(
            hashlib.sha256(peer_certificate_der).hexdigest()
        )
        if principal is None:
            raise PermissionError("peer identity rejected")
        snapshot = decode_snapshot(payload)
        if snapshot["host_id"] not in principal.host_ids or any(
            (metric, field["source"]) not in principal.grants
            for metric, field in snapshot["fields"].items()
        ):
            raise PermissionError("telemetry authority rejected")
        return self._store.accept(snapshot, now=now)
