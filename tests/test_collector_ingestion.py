"""Synthetic parser/tick integration over real localhost mTLS and durable stores."""
import hashlib
import http.client
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ingestion_test_support import test_pki
from test_collector_adapters import DOCTOR, DOCTOR_TEXT, STATUS

from gargoyl.collector import collect
from gargoyl.collector_history import EncryptedHistory, OutboundHTTPS
from gargoyl.collector_runtime import CollectorRuntime
from gargoyl.dashboard.runtime import EvidenceViewer
from gargoyl.ingestion import EvidenceStore, IngestionService, Principal
from gargoyl.ingestion_http import make_ingestion_server
from gargoyl.security import (
    CollectionIdentity,
    RetentionPolicy,
    SpoolCipher,
    TransportConfig,
)

NOW = "2026-01-01T00:00:00Z"
IDENTITY = CollectionIdentity("00000000-0000-4000-8000-000000000001")


class CollectorIngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pki = test_pki(self.root)
        self.wall, self.mono = NOW, 0
        self.policy = RetentionPolicy(max_records=10)
        self.receiver_cipher = SpoolCipher(IDENTITY, os.urandom(32))
        self.store = EvidenceStore(self.root / "receiver", {IDENTITY.host_id: self.receiver_cipher},
                                   self.policy, NOW)
        self.addCleanup(self.store.close)
        self.history = EncryptedHistory(self.root / "collector", SpoolCipher(IDENTITY, os.urandom(32)),
                                        self.policy, NOW)
        self.addCleanup(self.history.close)
        fields = collect(IDENTITY.host_id, NOW, {})["fields"]
        grants = frozenset((metric, field["source"]) for metric, field in fields.items())
        full = Principal(frozenset({IDENTITY.host_id}), grants)
        # Remove an UNKNOWN placeholder grant, not an observed parser metric.
        limited = Principal(frozenset({IDENTITY.host_id}), grants - {("model_state", "daemon")})
        principals = {hashlib.sha256(self.pki[name][2]).hexdigest(): principal
                      for name, principal in (("client", full), ("other", limited))}
        self.service = IngestionService(self.store, principals)
        self.server = make_ingestion_server(
            self.service, ca_file=self.pki["ca"], certificate_file=self.pki["server"][0],
            private_key_file=self.pki["server"][1], clock=lambda: self.wall, timeout=.5)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": .01})
        self.thread.start()
        self.stopped = False
        self.addCleanup(self.stop_server)
        self.sender = self.sender_for("client")
        self.runtime = CollectorRuntime(IDENTITY, self.history, self.sender,
                                        wall_clock=lambda: self.wall,
                                        monotonic_clock=lambda: self.mono)

    def stop_server(self):
        if not self.stopped:
            self.server.shutdown()
            self.thread.join(timeout=2)
            self.server.server_close()
            self.stopped = True
            self.assertFalse(self.thread.is_alive())

    def sender_for(self, certificate):
        return OutboundHTTPS(TransportConfig(
            f"https://localhost:{self.server.server_port}/v1/snapshots", self.pki["ca"],
            self.pki[certificate][0], self.pki[certificate][1]), IDENTITY)

    def capture(self):
        return self.runtime.collect_tick({
            STATUS: "Status: ● Running — serving synthetic-private-model".encode(),
            DOCTOR: DOCTOR_TEXT.encode(),
        })

    def test_parsers_spool_mtls_durable_restart(self):
        snapshot = self.capture()
        self.assertEqual(snapshot["fields"]["daemon_state"]["value"], "running")
        self.assertEqual(snapshot["fields"]["doctor_state"]["value"], "passed")
        self.assertEqual(snapshot["fields"]["model_state"]["state"], "unknown")
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(self.history.pending(NOW), [])
        self.assertEqual(self.store.snapshots(now=NOW), [snapshot])
        self.stop_server()  # listeners must stop/join before closing the shared store
        self.store.close()
        restored = EvidenceStore(self.root / "receiver", {IDENTITY.host_id: self.receiver_cipher},
                                 self.policy, NOW)
        try:
            self.assertEqual(restored.snapshots(now=NOW), [snapshot])
        finally:
            restored.close()
        for directory in (self.root / "receiver", self.root / "collector"):
            for path in directory.iterdir():
                for forbidden in (b"synthetic-private-model", b"Synthetic Chip", b'"doctor_state"'):
                    self.assertNotIn(forbidden, path.read_bytes())

    def test_parser_to_tls_store_to_live_viewer(self):
        absent = "00000000-0000-4000-8000-000000000002"
        viewer = EvidenceViewer(self.store, [IDENTITY.host_id, absent],
                                clock=lambda: self.wall)
        thread = threading.Thread(target=viewer.serve_forever,
                                  kwargs={"poll_interval": .01})
        thread.start()

        def stop_viewer():
            viewer.shutdown()
            thread.join(timeout=2)
            viewer.server_close()
            self.assertFalse(thread.is_alive())

        self.addCleanup(stop_viewer)

        def page():
            connection = http.client.HTTPConnection("127.0.0.1", viewer.server_port, timeout=2)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                return response.read().decode()
            finally:
                connection.close()

        self.assertIn("No report", page())
        self.capture()
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        rendered = page()
        for expected in ("daemon_state", "<td>running</td>", "doctor_state",
                         "<td>passed</td>", absent, "missing_collector_heartbeat",
                         'content="30"'):
            self.assertIn(expected, rendered)
        self.assertNotIn("synthetic-private-model", rendered)
        self.assertNotIn("Synthetic Chip", rendered)
        self.wall = "2026-01-01T00:01:01Z"
        aged = page()
        self.assertIn("collector_heartbeat_not_current", aged)
        self.assertIn("stale (reported: observed)", aged)

    def test_lost_response_replay_deduplicates_after_durable_acceptance(self):
        snapshot = self.capture()
        original = OutboundHTTPS._acknowledged

        def lose_response(sender, connection, deadline):
            # Complete actual TLS/HTTP and durable receiver commit before losing
            # the acknowledgement at the sender boundary. No network path is mocked.
            self.assertTrue(original(sender, connection, deadline))
            raise OSError("synthetic lost acknowledgement")

        with patch.object(OutboundHTTPS, "_acknowledged", lose_response):
            self.assertEqual(self.runtime.deliver_tick(), "retry")
        self.assertEqual(self.store.snapshots(now=NOW), [snapshot])
        self.assertEqual(len(self.history.pending(NOW)), 1)
        self.mono = 1
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(self.history.pending(NOW), [])
        self.assertEqual(self.store.snapshots(now=NOW), [snapshot])

    def test_unknown_placeholder_grant_rejection_retains_pending(self):
        snapshot = self.capture()
        self.runtime.transport = self.sender_for("other")
        self.assertEqual(self.runtime.deliver_tick(), "retry")
        self.assertEqual(self.store.snapshots(now=NOW), [])
        self.assertEqual(len(self.history.pending(NOW)), 1)
        self.runtime.transport = self.sender
        self.mono = 1
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(self.store.snapshots(now=NOW), [snapshot])

    def test_receiver_storage_failure_keeps_pending_and_collection_continues(self):
        first = self.capture()
        with sqlite3.connect(self.root / "receiver" / "evidence.sqlite3") as database:
            database.execute("CREATE TRIGGER fail_write BEFORE INSERT ON evidence BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.assertEqual(self.runtime.deliver_tick(), "retry")
        self.assertEqual(self.store.snapshots(now=NOW), [])
        self.wall, self.mono = "2026-01-01T00:00:30Z", 30
        second = self.capture()
        self.assertEqual(len(self.history.pending(self.wall)), 2)
        with sqlite3.connect(self.root / "receiver" / "evidence.sqlite3") as database:
            database.execute("DROP TRIGGER fail_write")
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(self.store.snapshots(now=self.wall), [first, second])

    def test_missing_listener_does_not_disable_later_collection(self):
        self.capture()
        self.stop_server()
        self.assertEqual(self.runtime.deliver_tick(), "retry")
        self.wall, self.mono = "2026-01-01T00:00:30Z", 30
        self.assertIsNotNone(self.capture())
        self.assertEqual(len(self.history.pending(self.wall)), 2)
