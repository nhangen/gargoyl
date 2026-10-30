"""Self-authored local subprocess fixtures, never an installed upstream command."""

import hashlib
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyl.collector_acquisition import AcquisitionResult, BoundedAcquirer
from gargoyl.collector_adapters import AdapterResult
from gargoyl.ingestion import EvidenceStore
from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import RepairPlan, canonical
from gargoyl.repair_host_adapter import StatusRefreshAdapter
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError

HOST = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"
NOW = "2026-01-01T00:00:00Z"


class StatusRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.producer = self.path / "synthetic-producer"
        self.write_producer("assert sys.argv[1:] == ['status']\nprint('Status: ○ Stopped')\n")
        self.wall = lambda: NOW
        self.acquire = BoundedAcquirer(str(self.producer), environment={}, cwd=str(self.path),
                                       wall_clock=self.wall, monotonic_clock=time.monotonic,
                                       total_timeout_seconds=1, cleanup_grace_seconds=.4)
        self.ciphers = {HOST: SpoolCipher(CollectionIdentity(HOST), os.urandom(32))}
        self.store = EvidenceStore(self.path / "evidence", self.ciphers, RetentionPolicy(), NOW)
        self.addCleanup(self.store.close)
        self.adapter = StatusRefreshAdapter(HOST, acquirer=self.acquire, store=self.store,
                                            wall_clock=self.wall, total_timeout_seconds=2)
        key = Ed25519PrivateKey.generate()
        manifest = canonical(dict(schema_version=1, runbook_id="status_refresh", version=1,
                                  operation="status_refresh", timeout_seconds=3))
        catalog = RunbookCatalog(trusted_keys={"test": key.public_key().public_bytes_raw()},
                                 allowed_versions=frozenset({("status_refresh", 1,
                                                             hashlib.sha256(manifest).hexdigest())}))
        book = catalog.verify_runbook(manifest, key.sign(SIGNING_CONTEXT + manifest), key_id="test")
        self.plan = catalog.plan(book, HOST, [], now=NOW)
        self.event = threading.Event()

    def write_producer(self, body):
        self.producer.write_text(f"#!{sys.executable}\nimport sys, time\n" + body)
        self.producer.chmod(0o700)

    def execute(self):
        return self.adapter.execute(self.plan, stop_event=self.event)

    def test_stopped_is_valid_durable_observation_not_health_success(self):
        self.assertEqual(self.execute().outcome, "succeeded")
        values = self.store.snapshots(now=NOW)
        self.assertEqual(values[0]["fields"]["daemon_state"]["value"], "stopped")
        self.assertEqual(values[0]["fields"]["daemon_state"]["timestamp"], NOW)
        reopened = EvidenceStore(self.path / "evidence", self.ciphers, RetentionPolicy(), NOW)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.snapshots(now=NOW), values)

    def test_running_and_observation_start_preserved(self):
        self.write_producer("print('Status: ● Running')\n")
        self.adapter._wall_clock = iter((NOW, "2026-01-01T00:00:01Z", "2026-01-01T00:00:02Z")).__next__
        self.assertEqual(self.execute().outcome, "succeeded")
        snapshot = self.store.snapshots(now="2026-01-01T00:00:02Z")[0]
        self.assertEqual(snapshot["collected_at"], "2026-01-01T00:00:01Z")
        self.assertEqual(snapshot["fields"]["daemon_state"]["timestamp"], NOW)

    def test_wrong_host_operation_or_budget_never_launches(self):
        for change in ({"target_host": OTHER}, {"blocked": True}):
            value = self.plan.as_dict()
            value.update(change)
            with patch.object(self.acquire, "acquire") as launch:
                with self.assertRaises(PolicyError):
                    self.adapter.execute(RepairPlan(canonical(value)), stop_event=self.event)
                launch.assert_not_called()
        with self.assertRaises(PolicyError):
            StatusRefreshAdapter(OTHER, acquirer=self.acquire, store=self.store, wall_clock=self.wall)
        for budget in (True, 10**1000, float("nan"), .5):
            with self.assertRaises(PolicyError):
                StatusRefreshAdapter(HOST, acquirer=self.acquire, store=self.store,
                                     wall_clock=self.wall, total_timeout_seconds=budget)

    def test_diagnostics_and_short_manifest_budget_never_launch(self):
        for operation, budget in (("diagnostics_capture", 3), ("status_refresh", 1)):
            value = self.plan.as_dict()
            value["runbook"]["manifest"].update(operation=operation, runbook_id=operation,
                                               timeout_seconds=budget)
            with patch.object(self.acquire, "acquire") as launch:
                with self.assertRaises(PolicyError):
                    self.adapter.execute(RepairPlan(canonical(value)), stop_event=self.event)
                launch.assert_not_called()

    def test_child_held_pipe_timeout_never_publishes(self):
        self.write_producer("import os\nif os.fork() == 0: time.sleep(10)\n"
                            "else: print('Status: ● Running', flush=True)\n")
        with patch.object(self.store, "accept") as accept:
            result = self.execute()
            self.assertEqual(result.outcome, "outcome_unknown")
            accept.assert_not_called()

    def test_malformed_nonzero_and_overflow_never_publish(self):
        for body in ("print('private malformed text')", "print('Status: ● Running'); sys.exit(1)",
                     "print('x'*70000)"):
            self.write_producer(body)
            with patch.object(self.store, "accept") as accept:
                self.assertEqual(self.execute().outcome, "failed")
                accept.assert_not_called()
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_timeout_never_publishes_partial_success(self):
        self.write_producer("print('Status: ● Running', flush=True); time.sleep(10)")
        with patch.object(self.store, "accept") as accept:
            result = self.execute()
            self.assertEqual(result.outcome, "outcome_unknown")
            self.assertIn(result.reason, {"deadline_exceeded", "cleanup_incomplete"})
            accept.assert_not_called()

    def test_precancel_never_launches(self):
        self.event.set()
        with patch.object(self.acquire, "acquire") as launch:
            self.assertEqual(self.execute().outcome, "cancelled")
            launch.assert_not_called()

    def test_postacquisition_cancel_never_publishes(self):
        acquire = self.acquire.acquire

        def cancel(*args, **kwargs):
            acquired = acquire(*args, **kwargs)
            self.event.set()
            return acquired

        with patch.object(self.acquire, "acquire", side_effect=cancel), patch.object(self.store, "accept") as accept:
            self.assertEqual(self.execute().reason, "cancelled")
            accept.assert_not_called()

    def test_incomplete_cleanup_disables_adapter(self):
        acquired = AcquisitionResult("darkbloom_status_text_v1", NOW, NOW,
                                     AdapterResult({}, ("unavailable",)), False)
        with patch.object(self.acquire, "acquire", return_value=acquired) as launch:
            result = self.execute()
            self.assertEqual(result.reason, "cleanup_incomplete")
            with self.assertRaises(PolicyError):
                self.execute()
            self.assertEqual(launch.call_count, 1)

    def test_deadline_before_publication(self):
        self.adapter._clock = iter((0., 0., 2.)).__next__
        with patch.object(self.store, "accept") as accept:
            self.assertEqual(self.execute().reason, "deadline_exceeded")
            accept.assert_not_called()

    def test_late_durable_acceptance_is_unknown_without_rollback(self):
        self.adapter._clock = iter((0., 0., 0., 3.)).__next__
        self.assertEqual(self.execute().reason, "deadline_exceeded")
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)

    def test_cancel_during_durable_acceptance_does_not_rollback(self):
        accept = self.store.accept

        def cancel(*args, **kwargs):
            accepted = accept(*args, **kwargs)
            self.event.set()
            return accepted

        with patch.object(self.store, "accept", side_effect=cancel):
            self.assertEqual(self.execute().reason, "cancelled")
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)

    def test_sqlite_failure_is_unknown_and_private(self):
        self.store._db.execute("PRAGMA query_only=ON")
        result = self.execute()
        self.assertEqual((result.outcome, result.reason), ("outcome_unknown", "audit_unavailable"))
        self.store._db.execute("PRAGMA query_only=OFF")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_wall_rollback_prevents_publication(self):
        self.adapter._wall_clock = iter((NOW, "2025-12-31T23:59:59Z")).__next__
        with patch.object(self.store, "accept") as accept:
            self.assertEqual(self.execute().reason, "clock_invalid")
            accept.assert_not_called()
