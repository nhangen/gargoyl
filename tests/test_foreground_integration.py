"""Foreground composition with synthetic processes and real local mutual TLS."""

import hashlib
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ingestion_test_support import test_pki

from gargoyl.collector import collect
from gargoyl.collector_acquisition import BoundedAcquirer
from gargoyl.collector_history import EncryptedHistory, OutboundHTTPS
from gargoyl.collector_runtime import CollectorRuntime
from gargoyl.foreground import ForegroundConfig, run_configured
from gargoyl.ingestion import EvidenceStore, IngestionService, Principal
from gargoyl.ingestion_http import make_ingestion_server
from gargoyl.security import (
    CollectionIdentity,
    RetentionPolicy,
    SpoolCipher,
    TransportConfig,
)

HOST = "00000000-0000-4000-8000-000000000001"
STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
START = "2026-01-01T00:00:00Z"
COMPLETE = "2026-01-01T00:00:01Z"
NOW = "2026-01-01T00:00:02Z"


class StopAfterWait(threading.Event):
    """Stop after a complete synchronous foreground cycle, without a timer race."""

    def wait(self, timeout=None):
        self.set()
        return True


@unittest.skipUnless(os.name == "posix", "synthetic POSIX producer required")
class ForegroundIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.identity = CollectionIdentity(HOST)
        self.policy = RetentionPolicy()
        self.spool_cipher = SpoolCipher(self.identity, b"c" * 32)
        self.pki = test_pki(self.root)
        self.store = EvidenceStore(
            self.root / "receiver",
            {HOST: SpoolCipher(self.identity, b"r" * 32)},
            self.policy,
            NOW,
        )
        self.addCleanup(self.store.close)
        fields = collect(HOST, NOW, {})["fields"]
        principal = Principal(
            frozenset({HOST}),
            frozenset((name, field["source"]) for name, field in fields.items()),
        )
        service = IngestionService(
            self.store, {hashlib.sha256(self.pki["client"][2]).hexdigest(): principal}
        )
        self.delay = False
        self.accepted = threading.Event()
        owner = self

        class DelayedService:
            def accept(self, payload, certificate, *, now):
                if owner.delay:
                    time.sleep(0.35)
                result = service.accept(payload, certificate, now=now)
                owner.accepted.set()
                return result

        self.server = make_ingestion_server(
            DelayedService(),
            ca_file=self.pki["ca"],
            certificate_file=self.pki["server"][0],
            private_key_file=self.pki["server"][1],
            clock=lambda: NOW,
            timeout=1,
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()
        self.addCleanup(self.shutdown)
        self.executable = self.root / "synthetic-producer"
        fd = os.open(self.executable, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o700)
        with os.fdopen(fd, "w") as stream:
            stream.write(
                f"#!{sys.executable}\n"
                + """import os, sys, time
with open(os.environ["PID_RECEIPT"], "w") as receipt:
    receipt.write(str(os.getpid()))
if os.environ.get("MODE") == "hang" or sys.argv[1] == "doctor":
    time.sleep(30)
print("Status: ● Running — serving synthetic-private-label")
"""
            )

    def shutdown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()
        self.assertFalse(self.thread.is_alive())

    def sender(self, budget=1):
        return OutboundHTTPS(
            TransportConfig(
                f"https://localhost:{self.server.server_port}/v1/snapshots",
                self.pki["ca"],
                *self.pki["client"][:2],
            ),
            self.identity,
            total_timeout_seconds=budget,
        )

    def acquisition(self, *, wall_clock=lambda: START, mode="good"):
        return BoundedAcquirer(
            str(self.executable),
            environment={"MODE": mode, "PID_RECEIPT": str(self.root / "producer.pid")},
            cwd=str(self.root),
            wall_clock=wall_clock,
            monotonic_clock=time.monotonic,
            total_timeout_seconds=0.8,
            cleanup_grace_seconds=0.3,
        )

    def run_composed(
        self,
        acquisition,
        *,
        sources=(STATUS,),
        sender=None,
        stop=None,
        wall_clock=lambda: NOW,
        monotonic_clock=time.monotonic,
    ):
        return run_configured(
            ForegroundConfig(HOST, sources),
            identity=self.identity,
            cipher=self.spool_cipher,
            transport=sender or self.sender(),
            acquisition=acquisition,
            spool_directory=self.root / "collector",
            wall_clock=wall_clock,
            monotonic_clock=monotonic_clock,
            stop_event=stop if stop is not None else StopAfterWait(),
        )

    def history(self):
        history = EncryptedHistory(
            self.root / "collector", self.spool_cipher, self.policy, NOW
        )
        self.addCleanup(history.close)
        return history

    def assert_producer_reaped(self):
        pid = int((self.root / "producer.pid").read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_real_process_tls_and_observation_start_preserved(self):
        times = iter((START, COMPLETE))
        result = self.run_composed(self.acquisition(wall_clock=lambda: next(times)))
        self.assertEqual(
            (result.status, result.collections, result.deliveries), ("stopped", 1, 1)
        )
        evidence = self.store.snapshots(now=NOW)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["collected_at"], NOW)
        self.assertEqual(evidence[0]["fields"]["daemon_state"]["timestamp"], START)
        self.assertEqual(evidence[0]["fields"]["daemon_state"]["value"], "running")
        self.assertEqual(self.history().pending(NOW), [])
        self.assert_producer_reaped()
        for directory in (self.root / "collector", self.root / "receiver"):
            for path in directory.iterdir():
                raw = path.read_bytes()
                self.assertNotIn(b"synthetic-private-label", raw)
                self.assertNotIn(b'"daemon_state"', raw)

    def test_failed_source_unknown_independent_success_delivered(self):
        result = self.run_composed(self.acquisition(), sources=(STATUS, DOCTOR))
        self.assertEqual(
            (result.status, result.collections, result.deliveries), ("stopped", 1, 1)
        )
        fields = self.store.snapshots(now=NOW)[0]["fields"]
        self.assertEqual(fields["daemon_state"]["value"], "running")
        self.assertEqual(fields["doctor_state"]["state"], "unknown")
        self.assertEqual(fields["error_code"]["value"], "timeout")
        self.assert_producer_reaped()

    def test_clock_rollback_withholds_future_observation(self):
        times = iter(("2026-01-01T00:00:10Z", "2026-01-01T00:00:09Z"))
        result = self.run_composed(self.acquisition(wall_clock=lambda: next(times)))
        self.assertEqual(result.deliveries, 1)
        fields = self.store.snapshots(now=NOW)[0]["fields"]
        self.assertEqual(fields["daemon_state"]["state"], "unknown")
        self.assertIsNone(fields["daemon_state"]["value"])
        self.assertEqual(fields["error_code"]["value"], "invalid_state")
        self.assert_producer_reaped()

    def test_transport_timeout_retains_pending_and_replay_is_durable(self):
        self.delay = True
        result = self.run_composed(self.acquisition(), sender=self.sender(0.1))
        self.assertEqual(
            (result.status, result.collections, result.retries), ("stopped", 1, 1)
        )
        history = self.history()
        self.assertEqual(len(history.pending(NOW)), 1)
        self.assertTrue(self.accepted.wait(2))
        self.delay = False
        runtime = CollectorRuntime(
            self.identity,
            history,
            self.sender(),
            wall_clock=lambda: NOW,
            monotonic_clock=time.monotonic,
        )
        self.assertEqual(runtime.deliver_tick(), "sent")
        self.assertEqual(history.pending(NOW), [])
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)
        self.assert_producer_reaped()

    def test_stop_during_real_acquisition_reaps_without_persisting(self):
        stop = threading.Event()
        def cancel_after_start():
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                receipt = self.root / "producer.pid"
                if receipt.exists() and receipt.read_text():
                    break
                time.sleep(0.005)
            stop.set()

        timer = threading.Thread(target=cancel_after_start)
        timer.start()
        try:
            result = self.run_composed(self.acquisition(mode="hang"), stop=stop)
        finally:
            timer.join(timeout=3)
            self.assertFalse(timer.is_alive())
        self.assertEqual(
            (result.status, result.collections, result.deliveries), ("stopped", 0, 0)
        )
        self.assertEqual(self.store.snapshots(now=NOW), [])
        self.assertEqual(self.history().pending(NOW), [])
        self.assert_producer_reaped()

    def test_real_composition_skips_elapsed_scheduler_slots(self):
        # Only scheduler time is synthetic; process and transport deadlines use
        # real monotonic clocks. The first process completion represents an overrun.
        clock = [0.0]
        calls = []

        def observation_clock():
            calls.append(clock[0])
            if len(calls) == 2:
                clock[0] = 95.0
            return START

        class AdvancingStop(threading.Event):
            def wait(self, timeout=None):
                if len(calls) >= 4:
                    self.set()
                else:
                    clock[0] += timeout
                return self.is_set()

        result = self.run_composed(
            self.acquisition(wall_clock=observation_clock),
            stop=AdvancingStop(),
            monotonic_clock=lambda: clock[0],
        )
        self.assertEqual(calls[::2], [0.0, 120.0])
        self.assertEqual((result.status, result.collections), ("stopped", 2))
        self.assertEqual(self.history().pending(NOW), [])
        self.assert_producer_reaped()
