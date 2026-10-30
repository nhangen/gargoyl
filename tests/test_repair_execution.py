"""Synthetic authorization/operations only; never invokes a host command."""

import hashlib
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyl.repair_audit import AuditError, RepairAuditStore
from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import (
    OperationResult,
    RepairConfirmation,
    RepairReceipt,
    canonical,
)
from gargoyl.repair_runtime import RefusingAdapter, RepairRuntime
from gargoyl.telemetry import PolicyError

HOST = "00000000-0000-4000-8000-000000000001"
ACTOR = "00000000-0000-4000-8000-000000000002"
CLICK = "00000000-0000-4000-8000-000000000003"
NOW = "2026-01-01T00:00:00Z"


class SyntheticAuthorization:
    def authorize(self, plan, confirmation):
        if confirmation.as_dict()["actor_id"] != ACTOR:
            raise PermissionError("synthetic private error")


class SyntheticAdapter:
    supported_operations = frozenset({"status_refresh"})
    total_timeout_seconds = 1

    def __init__(self):
        self.calls = 0

    def execute(self, plan, *, stop_event):
        self.calls += 1
        return OperationResult("succeeded", "completed", True)


class RepairExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = os.urandom(32)
        self.store = RepairAuditStore(self.temp.name, key=self.key)
        self.addCleanup(self.store.close)
        key = Ed25519PrivateKey.generate()
        manifest = canonical(dict(schema_version=1, runbook_id="status_refresh", version=1,
                                  operation="status_refresh", timeout_seconds=5))
        digest = hashlib.sha256(manifest).hexdigest()
        self.catalog = RunbookCatalog(
            trusted_keys={"test": key.public_key().public_bytes_raw()},
            allowed_versions=frozenset({("status_refresh", 1, digest)}))
        book = self.catalog.verify_runbook(manifest, key.sign(SIGNING_CONTEXT + manifest), key_id="test")
        self.plan = self.catalog.plan(book, HOST, [], now=NOW)
        self.confirmation = RepairConfirmation(canonical(dict(
            schema_version=1, actor_id=ACTOR, click_id=CLICK, target_host=HOST,
            runbook_id="status_refresh", version=1, runbook_digest=digest,
            plan_digest=self.plan.digest, confirmed_at=NOW,
            expires_at="2026-01-01T00:01:00Z", impact_acknowledged=False)))
        self.adapter = SyntheticAdapter()
        self.runtime = RepairRuntime(catalog=self.catalog, audit=self.store,
                                     authorization=SyntheticAuthorization(), evidence=lambda host: [],
                                     wall_clock=lambda: NOW, adapter=self.adapter)

    def execute(self):
        return self.runtime.execute(self.plan, self.confirmation, stop_event=threading.Event())

    def test_success_and_replay_restart(self):
        result = self.execute()
        self.assertEqual(result.as_dict()["outcome"], "succeeded")
        self.assertEqual(self.execute().as_dict()["reason"], "already_claimed")
        self.store.close()
        reopened = RepairAuditStore(self.temp.name, key=self.key)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.lookup(CLICK).as_dict()["receipt"], result.as_dict())
        self.assertFalse(reopened.claim(self.plan, self.confirmation, now=NOW))
        self.assertEqual(self.adapter.calls, 1)
        self.assertNotIn(self.plan.payload, reopened._path.read_bytes())

    def test_concurrent_claims_across_connections(self):
        other = RepairAuditStore(self.temp.name, key=self.key)
        self.addCleanup(other.close)
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(store.claim, self.plan, self.confirmation, now=NOW)
                       for store in (self.store, other)]
            self.assertEqual(sorted(f.result() for f in futures), [False, True])

    def test_started_restart_remains_consumed(self):
        self.store.claim(self.plan, self.confirmation, now=NOW)
        self.store.close()
        self.runtime.audit = RepairAuditStore(self.temp.name, key=self.key)
        self.addCleanup(self.runtime.audit.close)
        self.assertEqual(self.runtime.audit.lookup(CLICK).as_dict()["state"], "started")
        self.assertEqual(self.execute().as_dict()["reason"], "already_claimed")
        self.assertEqual(self.adapter.calls, 0)

    def test_capacity_never_evicts(self):
        self.store._limit = 1
        self.execute()
        value = self.confirmation.as_dict()
        value["click_id"] = HOST
        with self.assertRaises(AuditError):
            self.store.claim(self.plan, RepairConfirmation(canonical(value)), now=NOW)
        self.assertIsNotNone(self.store.lookup(CLICK))

    def test_corruption_and_wrong_key_fail_closed(self):
        self.execute()
        with self.assertRaises(AuditError):
            RepairAuditStore(self.temp.name, key=os.urandom(32))
        self.store._db.execute("DELETE FROM records")
        with self.assertRaises(AuditError):
            self.store.lookup(CLICK)
        self.assertEqual(self.execute().as_dict()["reason"], "audit_unavailable")
        self.assertEqual(self.adapter.calls, 1)

    def test_commit_failure_prevents_execution(self):
        with patch.object(self.store, "_commit", side_effect=OSError("private path")):
            result = self.execute()
        self.assertEqual(result.as_dict()["reason"], "audit_unavailable")
        self.assertEqual(self.adapter.calls, 0)
        self.assertIsNone(self.store.lookup(CLICK))
        self.assertNotIn(b"private", result.payload)

    def test_finalize_failure_preserves_claim(self):
        with patch.object(self.store, "finalize", side_effect=OSError("private path")):
            result = self.execute()
        self.assertEqual(result.as_dict()["outcome"], "outcome_unknown")
        self.assertEqual(self.store.lookup(CLICK).as_dict()["state"], "started")
        self.assertEqual(self.execute().as_dict()["reason"], "already_claimed")

    def test_forged_terminal_and_conflicting_overwrite(self):
        result = self.execute()
        self.assertEqual(self.store.finalize(CLICK, result), self.store.lookup(CLICK))
        value = result.as_dict()
        value["actor_id"] = HOST
        with self.assertRaises(AuditError):
            self.store.finalize(CLICK, RepairReceipt(canonical(value)))
        value = result.as_dict()
        value.update(outcome="failed", reason="operation_failed")
        with self.assertRaises(AuditError):
            self.store.finalize(CLICK, RepairReceipt(canonical(value)))

    def test_wrong_host_and_boolean_authorization(self):
        value = self.confirmation.as_dict()
        value["target_host"] = ACTOR
        self.confirmation = RepairConfirmation(canonical(value))
        with self.assertRaises(PolicyError):
            self.execute()
        self.assertEqual(self.adapter.calls, 0)

    def test_default_refuses_and_authorization_is_separate(self):
        self.runtime.adapter = RefusingAdapter()
        self.assertEqual(self.execute().as_dict()["reason"], "operation_unavailable")
        self.runtime.adapter = self.adapter
        with patch.object(self.runtime.authorization, "authorize", return_value=True):
            self.assertEqual(self.execute().as_dict()["reason"], "authorization_denied")
        self.assertIsNone(self.store.lookup(CLICK))

    def test_interrupt_is_unknown(self):
        with patch.object(self.adapter, "execute", side_effect=KeyboardInterrupt()):
            result = self.execute()
        self.assertEqual(result.as_dict()["reason"], "interrupted")
        self.assertEqual(result.as_dict()["outcome"], "outcome_unknown")

    def test_exception_is_private_and_unknown(self):
        with patch.object(self.adapter, "execute", side_effect=RuntimeError("private output")):
            result = self.execute()
        self.assertEqual(result.as_dict()["outcome"], "outcome_unknown")
        self.assertNotIn(b"private", result.payload)

    def test_invalid_result_is_unknown(self):
        with patch.object(self.adapter, "execute", return_value=True):
            self.assertEqual(self.execute().as_dict()["reason"], "invalid_result")

    def test_incompatible_adapter_outcome_becomes_unknown(self):
        with patch.object(self.adapter, "execute", return_value=OperationResult(
                "failed", "clock_invalid", True)):
            result = self.execute().as_dict()
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(result["reason"], "invalid_result")
        self.assertEqual(self.store.lookup(CLICK).as_dict()["receipt"], result)

    def test_cancellation_before_claim(self):
        event = threading.Event()
        event.set()
        result = self.runtime.execute(self.plan, self.confirmation, stop_event=event)
        self.assertEqual(result.as_dict()["reason"], "cancelled")
        self.assertIsNone(self.store.lookup(CLICK))

    def test_incomplete_cleanup_is_unknown(self):
        with patch.object(self.adapter, "execute", return_value=OperationResult(
                "outcome_unknown", "cleanup_incomplete", False)):
            result = self.execute().as_dict()
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertFalse(result["cleanup_complete"])

    def test_changed_preflight_prevents_claim(self):
        with patch.object(self.runtime, "evidence", side_effect=ValueError("private")):
            self.assertEqual(self.execute().as_dict()["reason"], "plan_changed")
        self.assertEqual(self.adapter.calls, 0)
        self.assertIsNone(self.store.lookup(CLICK))

    def test_deadline_and_clock_rollback(self):
        self.runtime.monotonic_clock = iter((1.0, 3.0)).__next__
        result = self.execute()
        self.assertEqual(result.as_dict()["reason"], "deadline_exceeded")
        self.assertEqual(result.as_dict()["outcome"], "outcome_unknown")

    def test_clock_rollback_after_operation(self):
        self.runtime.wall_clock = iter((NOW, NOW, NOW, "2025-12-31T23:59:59Z")).__next__
        result = self.execute().as_dict()
        self.assertEqual(result["reason"], "clock_invalid")
        self.assertEqual(result["finished_at"], NOW)
