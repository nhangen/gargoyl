"""Synthetic doctor subprocess through durable evidence and authenticated runtime."""

import hashlib
import os
import threading
import unittest
from unittest.mock import patch

import test_repair_host_adapter as host_fixtures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_collector_adapters import DOCTOR_TEXT
from test_repair_host_adapter import HOST, NOW, OTHER

from gargoyl.collector_acquisition import AcquisitionResult
from gargoyl.collector_adapters import AdapterResult
from gargoyl.ingestion import EvidenceStore
from gargoyl.repair_audit import RepairAuditStore
from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import RepairConfirmation, RepairPlan, canonical
from gargoyl.repair_host_adapter import DiagnosticsCaptureAdapter
from gargoyl.repair_operator import (
    OperatorAuthorization,
    OperatorKey,
    OperatorPrincipal,
    OperatorRegistry,
    repair_intent_bytes,
)
from gargoyl.repair_runtime import RepairRuntime
from gargoyl.security import RetentionPolicy
from gargoyl.telemetry import PolicyError

FAILED = DOCTOR_TEXT.replace("✓ Enabled", "✗ DISABLED — provider cannot serve safely").replace(
    "Result: 8/8", "Result: 7/8").replace("All good! Start serving with: darkbloom serve",
    "Issues to fix:\n  1. synthetic-private-advice")
CLICK = "00000000-0000-4000-8000-000000000003"
AUDIENCE = "00000000-0000-4000-8000-000000000004"


class DiagnosticsCaptureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = host_fixtures.StatusRefreshTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.acquire, self.store = self.fixture.acquire, self.fixture.store
        self.write_report(FAILED)
        self.adapter = DiagnosticsCaptureAdapter(HOST, acquirer=self.acquire, store=self.store,
                                                  wall_clock=lambda: NOW, total_timeout_seconds=2)
        key = Ed25519PrivateKey.generate()
        manifest = canonical(dict(schema_version=1, runbook_id="diagnostics_capture", version=1,
                                  operation="diagnostics_capture", timeout_seconds=3))
        self.catalog = RunbookCatalog(trusted_keys={"test": key.public_key().public_bytes_raw()},
                                     allowed_versions=frozenset({("diagnostics_capture", 1,
                                                                 hashlib.sha256(manifest).hexdigest())}))
        book = self.catalog.verify_runbook(manifest, key.sign(SIGNING_CONTEXT + manifest), key_id="test")
        self.plan = self.catalog.plan(book, HOST, [], now=NOW)
        self.confirmation = RepairConfirmation(canonical(dict(
            schema_version=1, actor_id=OTHER, click_id=CLICK, target_host=HOST,
            runbook_id="diagnostics_capture", version=1, runbook_digest=book.digest,
            plan_digest=self.plan.digest, confirmed_at=NOW, expires_at="2026-01-01T00:01:00Z",
            impact_acknowledged=False)))
        self.event = threading.Event()

    def write_report(self, report, suffix=""):
        self.fixture.write_producer("assert sys.argv[1:] == ['doctor']\nprint(" + repr(report) + ")\n" + suffix)

    def execute(self):
        return self.adapter.execute(self.plan, stop_event=self.event)

    def runtime(self):
        key = Ed25519PrivateKey.generate()
        registry = OperatorRegistry({"operator": OperatorKey(key.public_key().public_bytes_raw(),
            OperatorPrincipal(OTHER, frozenset({(HOST, "diagnostics_capture")})))})
        proof = {"key_id": "operator", "signature": key.sign(repair_intent_bytes(AUDIENCE, self.confirmation))}
        authorization = OperatorAuthorization(proof, registry_provider=lambda: registry,
                                               audience=AUDIENCE, wall_clock=lambda: NOW)
        audit = RepairAuditStore(self.fixture.path / "audit", key=os.urandom(32))
        self.addCleanup(audit.close)
        runtime = RepairRuntime(catalog=self.catalog, audit=audit, authorization=authorization,
                                 evidence=lambda host: self.store.snapshots(now=NOW),
                                 wall_clock=lambda: NOW, adapter=self.adapter)
        return runtime, audit

    def test_complete_failed_checks_are_successful_capture_without_raw_advice(self):
        self.assertEqual(self.execute().outcome, "succeeded")
        snapshot = self.store.snapshots(now=NOW)[0]
        field = snapshot["fields"]["doctor_state"]
        self.assertEqual((field["value"], field["source"], field["timestamp"]), ("failed", "doctor", NOW))
        self.assertIsNone(snapshot["fields"]["daemon_state"]["value"])
        self.assertNotIn("synthetic-private", repr(snapshot))
        self.assertNotIn("System Integrity Protection", repr(snapshot))

    def test_complete_pass_and_incomplete_advice_footer_are_valid(self):
        for report, value in ((DOCTOR_TEXT, "passed"), (FAILED.split("  1.")[0], "failed")):
            self.write_report(report)
            self.assertEqual(self.execute().outcome, "succeeded")
            self.assertTrue(any(s["fields"]["doctor_state"]["value"] == value
                                for s in self.store.snapshots(now=NOW)))

    def test_missing_duplicate_inconsistent_and_failed_exit_do_not_publish(self):
        cases = [(FAILED.replace("Result: 7/8", "Result: 8/8"), ""),
                 (FAILED.replace("8. Coordinator connectivity.... ✓ Online (3 providers)\n", ""), ""),
                 (FAILED + "Result: 7/8 checks passed\n", ""), (FAILED, "sys.exit(1)\n")]
        for report, suffix in cases:
            self.write_report(report, suffix)
            with patch.object(self.store, "accept") as accept:
                self.assertEqual(self.execute().outcome, "failed")
                accept.assert_not_called()
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_timeout_after_complete_output_does_not_publish(self):
        self.write_report(FAILED, "sys.stdout.flush(); time.sleep(10)\n")
        with patch.object(self.store, "accept") as accept:
            self.assertEqual(self.execute().outcome, "outcome_unknown")
            accept.assert_not_called()

    def test_incomplete_cleanup_halts_and_cancellation_never_launches(self):
        self.event.set()
        with patch.object(self.acquire, "acquire") as launch:
            self.assertEqual(self.execute().outcome, "cancelled")
            launch.assert_not_called()
        self.event.clear()
        value = AcquisitionResult("darkbloom_doctor_text_v1", NOW, NOW,
                                  AdapterResult({}, ("unavailable",)), False)
        with patch.object(self.acquire, "acquire", return_value=value) as launch:
            self.assertEqual(self.execute().reason, "cleanup_incomplete")
            with self.assertRaises(PolicyError):
                self.execute()
            self.assertEqual(launch.call_count, 1)

    def test_wrong_host_and_status_plan_refuse_before_launch(self):
        value = self.plan.as_dict()
        value["target_host"] = OTHER
        for plan in (RepairPlan(canonical(value)), self.fixture.plan):
            with patch.object(self.acquire, "acquire") as launch:
                with self.assertRaises(PolicyError):
                    self.adapter.execute(plan, stop_event=self.event)
                launch.assert_not_called()

    def test_late_write_retains_failed_evidence_with_unknown_outcome(self):
        self.adapter._clock = iter((0., 0., 0., 3.)).__next__
        self.assertEqual(self.execute().reason, "deadline_exceeded")
        self.assertEqual(self.store.snapshots(now=NOW)[0]["fields"]["doctor_state"]["value"], "failed")

    def test_authenticated_runtime_durable_receipt_restart_and_no_repeat(self):
        runtime, audit = self.runtime()
        with patch.object(self.acquire, "acquire", wraps=self.acquire.acquire) as acquire:
            receipt = runtime.execute(self.plan, self.confirmation, stop_event=self.event).as_dict()
            self.assertEqual(receipt["outcome"], "succeeded")
            self.assertEqual(audit.lookup(CLICK).as_dict()["receipt"], receipt)
            self.assertEqual(runtime.execute(self.plan, self.confirmation,
                                            stop_event=self.event).as_dict()["outcome"], "blocked")
            self.assertEqual(acquire.call_count, 1)
        reopened = EvidenceStore(self.fixture.path / "evidence", self.fixture.ciphers, RetentionPolicy(), NOW)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.snapshots(now=NOW), self.store.snapshots(now=NOW))

    def test_actual_final_audit_failure_preserves_evidence_and_consumed_claim(self):
        runtime, audit = self.runtime()
        audit._db.execute("CREATE TRIGGER fail_terminal BEFORE UPDATE ON records "
                          "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        receipt = runtime.execute(self.plan, self.confirmation, stop_event=self.event).as_dict()
        self.assertEqual((receipt["outcome"], receipt["reason"]), ("outcome_unknown", "audit_unavailable"))
        self.assertEqual(audit.lookup(CLICK).as_dict()["state"], "started")
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)
