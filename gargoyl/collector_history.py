"""Single-writer encrypted local history and outbound delivery.

Use a private, application-owned directory on a trusted local filesystem. Keys
are supplied externally and never stored here. SQLite transactions retain either
the previous or next complete history; only encrypted snapshots reach SQLite.
Delivery is at-least-once: a crash after server acceptance can replay a snapshot.
The receiver must deduplicate. No deployment or credential provisioning is provided.
"""
import ipaddress
import math
import os
import re
import socket
import sqlite3
import stat
import time
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


MAX_RESPONSE_HEADER_BYTES = 32768
MAX_RESPONSE_HEADERS = 100


class OutboundHTTPS:
    """One synchronous mTLS POST with an absolute network deadline and no DNS.

    Hostnames other than localhost require an explicit numeric connect_address.
    TLS verification/SNI and HTTP Host always use the original endpoint hostname.
    No worker threads/processes or response body reads are used.
    """
    def __init__(self, config, identity, *, total_timeout_seconds=10.0,
                 connect_address=None):
        if (type(total_timeout_seconds) not in (int, float)
                or not math.isfinite(total_timeout_seconds)
                or not 0 < total_timeout_seconds <= 30):
            raise ValueError("invalid outbound deadline")
        try:
            url = urlsplit(config.endpoint)
            hostname = url.hostname.encode('idna').decode('ascii')
            port = 443 if url.port is None else url.port
            target = url.path or '/'
            if (url.scheme != 'https' or url.username or url.password or url.query
                    or url.fragment or not hostname or not 1 <= port <= 65535
                    or len(config.endpoint) > 8192
                    or any(ord(c) < 33 or ord(c) > 126 for c in config.endpoint)
                    or any(ord(c) < 33 or ord(c) > 126 for c in hostname + target)
                    or '%' in hostname):
                raise ValueError
            try:
                endpoint_ip = ipaddress.ip_address(hostname)
            except ValueError:
                endpoint_ip = None
            if connect_address is None:
                destination = (str(endpoint_ip) if endpoint_ip is not None
                               else '127.0.0.1' if hostname == 'localhost' else None)
            else:
                if type(connect_address) is not str or '%' in connect_address:
                    raise ValueError
                destination = str(ipaddress.ip_address(connect_address))
                if endpoint_ip is not None and destination != str(endpoint_ip):
                    raise ValueError
                if hostname == 'localhost' and not ipaddress.ip_address(destination).is_loopback:
                    raise ValueError
            address = ipaddress.ip_address(destination)
        except (ValueError, AttributeError, UnicodeError, TypeError):
            raise ValueError("outbound endpoint requires a valid numeric destination") from None
        self.identity = identity
        self.total_timeout_seconds = float(total_timeout_seconds)
        self.hostname, self.port, self.target = hostname, port, target
        self.destination = str(address)
        self.family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        authority = '[' + hostname + ']' if ':' in hostname else hostname
        self.authority = authority + (':' + str(port) if port != 443 else '')
        # All explicit configuration is validated before trust/key file access.
        self.context = config.ssl_context()

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("outbound deadline exceeded")
        return remaining

    def _acknowledged(self, connection, deadline):
        # Read only header bytes, never prefetch a body. Each byte gets the
        # remaining total budget, so continuous delivery cannot extend it.
        header = bytearray()
        newlines = 0
        while not header.endswith(b'\r\n\r\n'):
            if len(header) >= MAX_RESPONSE_HEADER_BYTES:
                return False
            connection.settimeout(self._remaining(deadline))
            byte = connection.recv(1)
            if not byte:
                return False
            header.extend(byte)
            newlines += byte == b'\n'
            if newlines > MAX_RESPONSE_HEADERS + 2:
                return False
        self._remaining(deadline)
        lines = bytes(header[:-4]).split(b'\r\n')
        if not re.fullmatch(rb'HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e]*)?', lines[0]):
            return False
        fields = {}
        for line in lines[1:]:
            match = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[\t\x20-\x7e]*", line)
            if not match:
                return False
            name, value = line.split(b':', 1)
            fields.setdefault(name.lower(), []).append(value.strip())
        lengths = fields.get(b'content-length', [])
        if (b'transfer-encoding' in fields or len(lengths) > 1
                or lengths and not re.fullmatch(rb'[0-9]{1,20}', lengths[0])):
            return False
        status = int(lines[0][9:12])
        if status == 204 and lengths and int(lengths[0]) != 0:
            return False
        self._remaining(deadline)
        return status in (200, 201, 204)

    def send(self, snapshot):
        deadline = time.monotonic() + self.total_timeout_seconds
        payload = prepare_transmission(snapshot, self.identity)
        request = (f'POST {self.target} HTTP/1.1\r\nHost: {self.authority}\r\n'
                   f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n'
                   'Connection: close\r\n\r\n').encode('ascii') + payload
        connection = None
        try:
            connection = socket.socket(self.family, socket.SOCK_STREAM)
            connection.settimeout(self._remaining(deadline))
            connection.connect((self.destination, self.port))
            connection.settimeout(self._remaining(deadline))
            connection = self.context.wrap_socket(connection, server_hostname=self.hostname,
                                                  do_handshake_on_connect=False)
            connection.settimeout(self._remaining(deadline))
            connection.do_handshake()
            connection.settimeout(self._remaining(deadline))
            connection.sendall(request)
            return self._acknowledged(connection, deadline)
        except TimeoutError:
            raise TimeoutError("outbound deadline exceeded") from None
        except OSError:
            raise OSError("outbound transmission failed") from None
        finally:
            if connection is not None:
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
