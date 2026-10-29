import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from gargoyl.collector_history import EncryptedHistory
from gargoyl.collector_runtime import CollectorRuntime, SourceFailure
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError

IDENTITY = CollectionIdentity("00000000-0000-4000-8000-000000000001")
STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
NOW = "2026-01-01T00:00:00Z"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "history"
        self.history = EncryptedHistory(self.directory, SpoolCipher(IDENTITY, b"x" * 32),
                                        RetentionPolicy(), NOW)
        self.addCleanup(self.history.close)
        self.wall, self.mono = NOW, 0
        self.transport = Mock()
        self.runtime = CollectorRuntime(IDENTITY, self.history, self.transport,
                                       wall_clock=lambda: self.wall,
                                       monotonic_clock=lambda: self.mono)

    def test_ticks_independent_after_transport_failure(self):
        first = self.runtime.collect_tick({STATUS: "Status: ● Running".encode()})
        self.assertEqual(first["fields"]["daemon_state"]["value"], "running")
        self.transport.send.side_effect = OSError("synthetic-secret")
        self.assertEqual(self.runtime.deliver_tick(), "retry")
        self.wall, self.mono = "2026-01-01T00:00:30Z", 30
        second = self.runtime.collect_tick({STATUS: "Status: ○ Stopped".encode()})
        self.assertEqual(second["fields"]["daemon_state"]["value"], "stopped")
        self.assertEqual(len(self.history.pending(self.wall)), 2)
        self.transport.send.side_effect = None
        self.transport.send.return_value = True
        self.assertEqual(self.runtime.deliver_tick(), "sent")
        self.assertEqual(len(self.history.pending(self.wall)), 1)
        self.assertEqual(self.transport.send.call_args.args[0], first)

    def test_cadence_and_delivery_backoff_are_separate(self):
        self.runtime.collect_tick({})
        self.transport.send.return_value = False
        self.runtime.deliver_tick()
        self.mono = .5
        self.assertEqual(self.runtime.deliver_tick(), "idle")
        self.assertIsNone(self.runtime.collect_tick({}))
        self.mono = 30
        self.wall = "2026-01-01T00:00:30Z"
        self.assertIsNotNone(self.runtime.collect_tick({}))
        self.assertEqual(len(self.history.pending(self.wall)), 2)

    def test_bad_sources_fail_closed_without_prose_at_rest(self):
        snapshot = self.runtime.collect_tick({STATUS: b"synthetic-secret", DOCTOR: SourceFailure("timeout")})
        self.assertEqual(snapshot["fields"]["daemon_state"]["state"], "unknown")
        self.assertEqual(snapshot["fields"]["doctor_state"]["state"], "unknown")
        self.assertEqual(snapshot["fields"]["error_code"]["value"], "timeout")
        self.assertNotIn("synthetic-secret", repr(snapshot))
        for file in self.directory.iterdir():
            self.assertNotIn(b"synthetic-secret", file.read_bytes())
        self.assertFalse(any(isinstance(value, bytes) for value in vars(self.runtime).values()))

    def test_missing_sources_do_not_fabricate_evidence(self):
        result = self.runtime.collect_tick({STATUS: "Status: ● Running — serving synthetic-private-model".encode()})
        for name in ("model_state", "memory_pressure", "thermal_pressure", "launchd_state",
                     "attestation_state", "coordinator_reachable", "clock_skew_seconds"):
            self.assertEqual(result["fields"][name]["state"], "unknown")
        self.assertEqual(result["fields"]["heartbeat_age_seconds"]["value"], 0)

    def test_storage_failure_does_not_advance_collection_deadline(self):
        original = self.history.append
        self.history.append = Mock(side_effect=OSError("synthetic-disk-failure"))
        with self.assertRaises(OSError):
            self.runtime.collect_tick({})
        self.history.append = original
        self.assertIsNotNone(self.runtime.collect_tick({}))
        self.assertEqual(len(self.history.pending(NOW)), 1)

    def test_clock_rollback_retains_future_evidence(self):
        self.wall = "2026-01-01T00:00:10Z"
        self.runtime.collect_tick({})
        self.wall, self.mono = "2026-01-01T00:00:09Z", 30
        self.runtime.collect_tick({})
        self.assertEqual(len(self.history.pending(self.wall)), 1)
        self.wall = "2026-01-01T00:00:10Z"
        self.assertEqual(len(self.history.pending(self.wall)), 2)

    def test_configuration_and_clock_errors(self):
        for kwargs in ({"interval_seconds": 0}, {"interval_seconds": 61}, {"interval_seconds": True},
                       {"ttl": 0}, {"interval_seconds": 30, "ttl": 20}):
            with self.assertRaises(PolicyError):
                CollectorRuntime(IDENTITY, self.history, self.transport, wall_clock=lambda: NOW,
                                 monotonic_clock=lambda: 0, **kwargs)
        with self.assertRaises(PolicyError):
            self.runtime.collect_tick({"arbitrary-command": b""})
        for invalid in (-1, float("inf"), float("nan"), True):
            self.mono = invalid
            with self.assertRaises(PolicyError):
                self.runtime.collect_tick({})
        self.mono, self.wall = 0, "synthetic-secret"
        with self.assertRaises(PolicyError):
            self.runtime.collect_tick({})
        with self.assertRaises(PolicyError):
            SourceFailure("synthetic-secret")
