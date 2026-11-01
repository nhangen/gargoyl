import hashlib
import http.client
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path

from ingestion_test_support import test_pki
from test_telemetry import snapshot

from gargoyl.collector import RetrySchedule, collect
from gargoyl.collector_history import EncryptedHistory, OutboundHTTPS, deliver_pending
from gargoyl.dashboard import build_dashboard
from gargoyl.ingestion import EvidenceStore, IngestionService, Principal
from gargoyl.ingestion_http import make_ingestion_server
from gargoyl.security import (
    CollectionIdentity,
    RetentionPolicy,
    SpoolCipher,
    TransportConfig,
)
from gargoyl.telemetry import MAX_PAYLOAD_BYTES, encode_snapshot

NOW = "2026-01-01T00:00:00Z"


class HTTPSIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = test_pki(self.root)
        self.identity = CollectionIdentity(snapshot()["host_id"])
        self.policy = RetentionPolicy(max_records=10)
        self.store = EvidenceStore(
            self.root / "receiver",
            {self.identity.host_id: SpoolCipher(self.identity, b"r" * 32)},
            self.policy,
            NOW,
        )
        self.addCleanup(self.store.close)
        collected = collect(self.identity.host_id, NOW, {})
        grants = {
            (metric, field["source"]) for metric, field in collected["fields"].items()
        }
        principal = Principal(frozenset({self.identity.host_id}), frozenset(grants))
        self.service = IngestionService(
            self.store, {hashlib.sha256(self.pki["client"][2]).hexdigest(): principal}
        )
        self.server = make_ingestion_server(
            self.service,
            ca_file=self.pki["ca"],
            certificate_file=self.pki["server"][0],
            private_key_file=self.pki["server"][1],
            clock=lambda: NOW,
            timeout=0.5,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.port = self.server.server_port

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.assertFalse(self.thread.is_alive())

    def context(self, client="client"):
        context = ssl.create_default_context(cafile=self.pki["ca"])
        if client:
            context.load_cert_chain(*self.pki[client][:2])
        return context

    def request(
        self,
        payload=None,
        *,
        client="client",
        path="/v1/snapshots",
        method="POST",
        headers=None,
    ):
        connection = http.client.HTTPSConnection(
            "localhost", self.port, context=self.context(client), timeout=2
        )
        try:
            connection.request(
                method,
                path,
                body=payload if payload is not None else encode_snapshot(snapshot()),
                headers=headers or {"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_real_mtls_and_durable_replay_ack(self):
        self.assertEqual(self.request(), (204, b""))
        self.assertEqual(self.request(), (204, b""))
        self.assertEqual(self.store.snapshots(now=NOW), [snapshot()])
        # Reopen after successful response: the acknowledged record is on disk.
        restored = EvidenceStore(
            self.root / "receiver",
            {self.identity.host_id: SpoolCipher(self.identity, b"r" * 32)},
            self.policy,
            NOW,
        )
        try:
            self.assertEqual(restored.snapshots(now=NOW), [snapshot()])
        finally:
            restored.close()

    def test_missing_client_certificate_fails_handshake(self):
        with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
            self.request(client=None)
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_untrusted_client_certificate_fails_handshake(self):
        foreign_directory = self.root / "foreign"
        foreign_directory.mkdir()
        foreign = test_pki(foreign_directory)
        context = ssl.create_default_context(cafile=self.pki["ca"])
        context.load_cert_chain(*foreign["client"][:2])
        connection = http.client.HTTPSConnection(
            "localhost", self.port, context=context, timeout=2
        )
        try:
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                connection.request(
                    "POST",
                    "/v1/snapshots",
                    body=encode_snapshot(snapshot()),
                    headers={"Content-Type": "application/json"},
                )
                connection.getresponse()
        finally:
            connection.close()
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_registered_identity_not_headers_controls_access(self):
        self.assertEqual(
            self.request(
                client="other",
                headers={
                    "Content-Type": "application/json",
                    "X-Host-ID": self.identity.host_id,
                    "X-Client-Cert": self.pki["client"][2].hex(),
                },
            ),
            (403, b""),
        )
        data = snapshot()
        data["host_id"] = "00000000-0000-4000-8000-000000000002"
        self.assertEqual(self.request(encode_snapshot(data)), (403, b""))
        data = snapshot()
        data["fields"]["daemon_state"]["source"] = "coordinator"
        self.assertEqual(self.request(encode_snapshot(data)), (403, b""))
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_server_trust_and_hostname_verification(self):
        untrusted = ssl.create_default_context()
        untrusted.load_cert_chain(*self.pki["client"][:2])
        connection = http.client.HTTPSConnection(
            "localhost", self.port, context=untrusted, timeout=2
        )
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connection.request(
                    "POST", "/v1/snapshots", body=encode_snapshot(snapshot())
                )
        finally:
            connection.close()
        with socket.create_connection(("localhost", self.port), timeout=2) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.context().wrap_socket(raw, server_hostname="wrong.synthetic.test")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_invalid_payload_routes_methods_and_framing_never_ack(self):
        cases = (
            ({"payload": b'{"raw_logs":"synthetic-marker"}'}, 400),
            ({"path": "/elsewhere"}, 404),
            ({"method": "GET"}, 405),
            ({"headers": {"Content-Type": "text/plain"}}, 400),
            (
                {
                    "headers": {
                        "Content-Type": "application/json",
                        "Transfer-Encoding": "chunked",
                    }
                },
                400,
            ),
            (
                {
                    "headers": {
                        "Content-Type": "application/json",
                        "Content-Encoding": "gzip",
                    }
                },
                400,
            ),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments.keys(), expected=expected):
                self.assertEqual(self.request(**arguments), (expected, b""))
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_oversized_length_rejected_before_body(self):
        # Send only headers: a full body write can race the deliberate early
        # close and raise BrokenPipeError before http.client reads the 413.
        with socket.create_connection(("localhost", self.port), timeout=2) as raw:
            with self.context().wrap_socket(raw, server_hostname="localhost") as client:
                client.sendall(
                    b"POST /v1/snapshots HTTP/1.1\r\nHost: localhost\r\n"
                    b"Content-Type: application/json\r\nContent-Length: "
                    + str(MAX_PAYLOAD_BYTES + 1).encode("ascii")
                    + b"\r\n\r\n"
                )
                response = http.client.HTTPResponse(client)
                try:
                    response.begin()
                    self.assertEqual(response.status, 413)
                    self.assertEqual(response.getheader("Content-Length"), "0")
                    self.assertEqual(response.getheader("Connection"), "close")
                    self.assertEqual(response.read(), b"")
                finally:
                    response.close()
        self.assertEqual(self.store.snapshots(now=NOW), [])
        self.assertEqual(self.request(), (204, b""))

    def test_duplicate_length_and_truncated_body_rejected(self):
        for headers, body in (
            (b"Content-Length: 1\r\nContent-Length: 1\r\n", b"x"),
            (b"Content-Length: -1\r\n", b""),
        ):
            with socket.create_connection(("localhost", self.port), timeout=2) as raw:
                with self.context().wrap_socket(
                    raw, server_hostname="localhost"
                ) as client:
                    client.sendall(
                        b"POST /v1/snapshots HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                        + headers
                        + b"\r\n"
                        + body
                    )
                    response = client.recv(4096)
                    self.assertIn(b" 400 ", response)
        # An incomplete body times out and closes without acknowledgement.
        with socket.create_connection(("localhost", self.port), timeout=2) as raw:
            with self.context().wrap_socket(raw, server_hostname="localhost") as client:
                client.sendall(
                    b"POST /v1/snapshots HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nx"
                )
                response = client.recv(4096)
                self.assertNotIn(b" 204 ", response)
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def assert_drip_deadline_and_recovery(self, prefix):
        started = threading.Event()
        finished = threading.Event()
        stop = threading.Event()
        errors = []

        def drip():
            try:
                with socket.create_connection(
                    ("localhost", self.port), timeout=2
                ) as raw:
                    with self.context().wrap_socket(
                        raw, server_hostname="localhost"
                    ) as client:
                        client.sendall(prefix)
                        started.set()
                        end = time.monotonic() + 3
                        while time.monotonic() < end and not stop.wait(0.04):
                            try:
                                client.sendall(b" ")
                            except OSError:
                                break
            except BaseException as error:
                errors.append(error)
                started.set()
            finally:
                finished.set()

        dripper = threading.Thread(target=drip)
        dripper.start()
        try:
            self.assertTrue(started.wait(2))
            self.assertFalse(errors)
            start = time.monotonic()
            # The serial listener must recover while the attacker is still
            # prepared to drip for three seconds, well beyond its .5s deadline.
            self.assertEqual(self.request(), (204, b""))
            self.assertLess(time.monotonic() - start, 1.5)
            self.assertTrue(finished.wait(1))
            self.assertEqual(self.store.snapshots(now=NOW), [snapshot()])
        finally:
            stop.set()
            dripper.join(timeout=2)
            self.assertFalse(dripper.is_alive())

    def test_absolute_header_deadline_and_recovery(self):
        self.assert_drip_deadline_and_recovery(
            b"POST /v1/snapshots HTTP/1.1\r\nHost: localhost\r\nX-Drip: "
        )

    def test_absolute_body_deadline_and_recovery(self):
        self.assert_drip_deadline_and_recovery(
            b"POST /v1/snapshots HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Type: application/json\r\nContent-Length: 65536\r\n\r\n{"
        )

    def test_persistence_failure_returns_503(self):
        with closing(sqlite3.connect(self.root / "receiver" / "evidence.sqlite3")) as db, db:
            db.execute(
                "CREATE TRIGGER fail_write BEFORE INSERT ON evidence BEGIN SELECT RAISE(ABORT, 'synthetic-marker'); END"
            )
        self.assertEqual(self.request(), (503, b""))
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_encrypted_collector_to_receiver_to_dashboard(self):
        history = EncryptedHistory(
            self.root / "collector",
            SpoolCipher(self.identity, b"c" * 32),
            self.policy,
            NOW,
        )
        self.addCleanup(history.close)
        data = collect(
            self.identity.host_id,
            NOW,
            {"daemon_state": snapshot()["fields"]["daemon_state"]},
        )
        history.append(data, NOW)
        sender = OutboundHTTPS(
            TransportConfig(
                f"https://localhost:{self.port}/v1/snapshots",
                self.pki["ca"],
                self.pki["client"][0],
                self.pki["client"][1],
            ),
            self.identity,
        )
        self.assertEqual(
            deliver_pending(history, sender, RetrySchedule(), now=NOW, monotonic_now=0),
            "sent",
        )
        self.assertEqual(history.pending(NOW), [])
        view = build_dashboard(
            self.store.snapshots(now=NOW), [self.identity.host_id], NOW
        )
        self.assertEqual(
            view["hosts"][0]["latest"]["daemon_state"][0]["value"], "running"
        )
        future = "2026-01-01T00:01:01Z"
        aged = build_dashboard(
            self.store.snapshots(now=future), [self.identity.host_id], future
        )
        self.assertIn("collector_heartbeat_not_current", aged["hosts"][0]["incidents"])
        for directory in (self.root / "collector", self.root / "receiver"):
            for path in directory.iterdir():
                self.assertNotIn(b'"daemon_state"', path.read_bytes())
