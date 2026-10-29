from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from gargoyl.collector import RetrySchedule, collect
from gargoyl.collector_history import EncryptedHistory, OutboundHTTPS, deliver_pending
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher, TransportConfig
from gargoyl.telemetry import PolicyError

IDENTITY = CollectionIdentity("00000000-0000-4000-8000-000000000001")
NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-01T00:00:10Z"


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "spool"
        self.cipher = SpoolCipher(IDENTITY, b"x" * 32)
        self.policy = RetentionPolicy(max_age_seconds=60, max_records=2)

    def history(self, now=NOW, cipher=None):
        history = EncryptedHistory(self.path, cipher or self.cipher, self.policy, now)
        self.addCleanup(history.close)
        return history

    def test_encrypted_restart_and_offline_retention(self):
        history = self.history()
        first = collect(IDENTITY.host_id, NOW, {})
        history.append(first, NOW)
        history.append(collect(IDENTITY.host_id, LATER, {}), LATER)
        history.append(collect(IDENTITY.host_id, "2026-01-01T00:00:20Z", {}), "2026-01-01T00:00:20Z")
        self.assertEqual(len(history.pending("2026-01-01T00:00:20Z")), 2)
        history.close()
        for file in self.path.iterdir():
            raw = file.read_bytes()
            for marker in (IDENTITY.host_id.encode(), b'"schema_version"', b'"daemon_state"'):
                self.assertNotIn(marker, raw)
        restored = self.history("2026-01-01T00:00:20Z")
        self.assertEqual(restored.pending("2026-01-01T00:00:20Z")[0][1]["collected_at"], LATER)
        restored.close()
        expired = self.history("2026-01-01T00:02:00Z")
        self.assertEqual(expired.pending("2026-01-01T00:02:00Z"), [])

    def test_reject_before_persistence(self):
        history = self.history()
        for key in ("prompt", "completion", "credentials", "raw_logs", "customer_id", "ip_address"):
            snapshot = collect(IDENTITY.host_id, NOW, {})
            snapshot[key] = "synthetic-marker"
            with self.assertRaises(PolicyError): history.append(snapshot, NOW)
        self.assertEqual(history.pending(NOW), [])
        self.assertNotIn(b"synthetic-marker", (self.path / "history.sqlite3").read_bytes())

    def test_tamper_and_wrong_key_fail_closed(self):
        history = self.history()
        history.append(collect(IDENTITY.host_id, NOW, {}), NOW)
        history.close()
        with self.assertRaises(PolicyError): self.history(cipher=SpoolCipher(IDENTITY, b"y" * 32))
        history = self.history()
        history.db.execute("UPDATE history SET payload = ?", (b"GSP1" + b"z" * 40,))
        history.db.commit()
        with self.assertRaises(PolicyError): history.pending(NOW)

    def test_transaction_rollback_preserves_history(self):
        history = self.history()
        snapshot = collect(IDENTITY.host_id, NOW, {})
        history.append(snapshot, NOW)
        history.db.execute("CREATE TRIGGER fail_write BEFORE INSERT ON history BEGIN SELECT RAISE(ABORT, 'synthetic disk failure'); END")
        with self.assertRaises(Exception): history.append(snapshot, NOW)
        self.assertEqual(len(history.pending(NOW)), 1)

    def test_outage_collection_and_acknowledged_history(self):
        history = self.history()
        history.append(collect(IDENTITY.host_id, NOW, {}), NOW)
        transport, retry = Mock(), RetrySchedule()
        transport.send.side_effect = OSError("synthetic-marker")
        self.assertEqual(deliver_pending(history, transport, retry, now=NOW, monotonic_now=0), "retry")
        history.append(collect(IDENTITY.host_id, LATER, {}), LATER)
        self.assertEqual(len(history.pending(LATER)), 2)
        self.assertEqual(deliver_pending(history, transport, retry, now=LATER, monotonic_now=.5), "idle")
        transport.send.side_effect = None
        transport.send.return_value = True
        self.assertEqual(deliver_pending(history, transport, retry, now=LATER, monotonic_now=1), "sent")
        self.assertEqual(len(history.pending(LATER)), 1)
        self.assertEqual(history.db.execute("SELECT count(*) FROM history").fetchone()[0], 2)
        history.close()
        self.assertEqual(len(self.history(LATER).pending(LATER)), 1)

    def test_private_directory_and_symlink(self):
        self.path.mkdir(mode=0o755)
        self.path.chmod(0o755)
        with self.assertRaises(PermissionError): self.history()
        self.path.chmod(0o700)
        (self.path / "history.sqlite3").symlink_to(self.path / "other")
        with self.assertRaises(OSError): self.history()


class TransportTests(unittest.TestCase):
    def test_tls_context_redirects_and_revalidation(self):
        config = TransportConfig("https://example.invalid/telemetry", "ca", "cert", "key")
        with patch.object(TransportConfig, "ssl_context", return_value=object()) as context, patch("gargoyl.collector_history.http.client.HTTPSConnection") as connection:
            sender = OutboundHTTPS(config, IDENTITY)
            snapshot = collect(IDENTITY.host_id, NOW, {})
            for status, expected in ((200, True), (201, True), (204, True), (202, False), (302, False), (500, False)):
                connection.return_value.getresponse.return_value.status = status
                self.assertEqual(sender.send(snapshot), expected)
            self.assertIs(connection.call_args.kwargs["context"], context.return_value)
            calls = connection.call_count
            snapshot["raw_logs"] = "synthetic-marker"
            with self.assertRaises(PolicyError): sender.send(snapshot)
            self.assertEqual(connection.call_count, calls)
            self.assertEqual(connection.return_value.close.call_count, 6)

    def test_missing_credentials_prevent_network(self):
        config = TransportConfig("https://example.invalid", "missing-ca", "missing-cert", "missing-key")
        with patch("gargoyl.collector_history.http.client.HTTPSConnection") as connection:
            with self.assertRaises(OSError): OutboundHTTPS(config, IDENTITY)
            connection.assert_not_called()
