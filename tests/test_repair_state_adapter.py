"""Only temporary owner-local JSON, ephemeral trust, and encrypted test stores."""

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_collector_state_file import EPOCH, HOST, NOW, fixture

from gargoyl.collector_adapters import AdapterResult
from gargoyl.collector_state_file import DaemonStateResult, read_daemon_state
from gargoyl.ingestion import EvidenceStore
from gargoyl.repair_audit import RepairAuditStore
from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import RepairConfirmation, RepairPlan, canonical
from gargoyl.repair_operator import (
    OperatorAuthorization,
    OperatorKey,
    OperatorPrincipal,
    OperatorRegistry,
    repair_intent_bytes,
)
from gargoyl.repair_runtime import RepairRuntime
from gargoyl.repair_state_adapter import DaemonStateRefreshAdapter
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError

ACTOR = "00000000-0000-4000-8000-000000000002"
CLICK = "00000000-0000-4000-8000-000000000003"
AUDIENCE = "00000000-0000-4000-8000-000000000004"
END = "2026-01-01T00:01:00Z"
BEFORE = "2025-12-31T23:59:59Z"
READ = "gargoyl.repair_state_adapter.read_daemon_state"


class StateRefreshTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / "state.json"
        self.write(fixture())
        self.ciphers = {HOST: SpoolCipher(CollectionIdentity(HOST), os.urandom(32))}
        self.store = EvidenceStore(
            self.root / "evidence", self.ciphers, RetentionPolicy(), NOW
        )
        self.addCleanup(self.store.close)
        self.adapter = DaemonStateRefreshAdapter(
            HOST,
            source_path=str(self.source),
            expected_owner_uid=os.getuid(),
            store=self.store,
            wall_clock=lambda: NOW,
            total_timeout_seconds=2,
        )
        key = Ed25519PrivateKey.generate()
        manifest = canonical(
            dict(
                schema_version=1,
                runbook_id="status_refresh",
                version=1,
                operation="status_refresh",
                timeout_seconds=3,
            )
        )
        self.catalog = RunbookCatalog(
            trusted_keys={"test": key.public_key().public_bytes_raw()},
            allowed_versions=frozenset(
                {("status_refresh", 1, hashlib.sha256(manifest).hexdigest())}
            ),
        )
        self.book = self.catalog.verify_runbook(
            manifest, key.sign(SIGNING_CONTEXT + manifest), key_id="test"
        )
        self.plan = self.catalog.plan(self.book, HOST, [], now=NOW)
        self.confirmation = RepairConfirmation(
            canonical(
                dict(
                    schema_version=1,
                    actor_id=ACTOR,
                    click_id=CLICK,
                    target_host=HOST,
                    runbook_id="status_refresh",
                    version=1,
                    runbook_digest=self.book.digest,
                    plan_digest=self.plan.digest,
                    confirmed_at=NOW,
                    expires_at=END,
                    impact_acknowledged=False,
                )
            )
        )
        self.event = threading.Event()

    def write(self, data):
        self.source.write_text(json.dumps(data))
        self.source.chmod(0o600)

    def execute(self):
        return self.adapter.execute(self.plan, stop_event=self.event)

    def runtime(self, *, granted=True):
        key = Ed25519PrivateKey.generate()
        grants = frozenset({(HOST, "status_refresh")}) if granted else frozenset()
        self.registry = OperatorRegistry(
            {
                "operator": OperatorKey(
                    key.public_key().public_bytes_raw(),
                    OperatorPrincipal(ACTOR, grants),
                )
            }
        )
        proof = dict(
            key_id="operator",
            signature=key.sign(repair_intent_bytes(AUDIENCE, self.confirmation)),
        )
        authorization = OperatorAuthorization(
            proof,
            registry_provider=lambda: self.registry,
            audience=AUDIENCE,
            wall_clock=lambda: NOW,
        )
        audit = RepairAuditStore(self.root / "audit", key=os.urandom(32))
        self.addCleanup(audit.close)
        runtime = RepairRuntime(
            catalog=self.catalog,
            audit=audit,
            authorization=authorization,
            evidence=lambda host: [],
            wall_clock=lambda: NOW,
            adapter=self.adapter,
        )
        return runtime, audit

    def test_real_file_to_durable_evidence_preserves_source_and_privacy(self):
        data = fixture()
        data["written_at"] = EPOCH - 1
        self.write(data)
        original = self.source.read_bytes()
        with patch("subprocess.Popen") as process, patch("socket.socket") as network:
            self.assertEqual(self.execute().outcome, "succeeded")
        process.assert_not_called()
        network.assert_not_called()
        self.assertEqual(self.source.read_bytes(), original)
        records = self.store.snapshots(now=NOW)
        field = records[0]["fields"]["requests_total"]
        self.assertEqual((field["value"], field["timestamp"]), (3, BEFORE))
        self.assertIsNone(records[0]["fields"]["daemon_state"]["value"])
        self.assertNotIn("synthetic-private", repr(records))
        reopened = EvidenceStore(
            self.root / "evidence", self.ciphers, RetentionPolicy(), NOW
        )
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.snapshots(now=NOW), records)
        self.assertNotIn(
            b"synthetic-private", (self.root / "evidence/evidence.sqlite3").read_bytes()
        )

    def test_missing_malformed_empty_stale_future_never_publish(self):
        cases = [
            None,
            "{private-malformed",
            dict(fixture(), warm_models=[], stats={}),
            dict(fixture(), written_at=EPOCH - 61),
            dict(fixture(), written_at=EPOCH + 1),
        ]
        for data in cases:
            with self.subTest(data=type(data).__name__):
                if self.source.exists():
                    self.source.unlink()
                if isinstance(data, dict):
                    self.write(data)
                elif isinstance(data, str):
                    self.source.write_text(data)
                with patch.object(self.store, "accept") as accept:
                    self.assertEqual(self.execute().outcome, "failed")
                accept.assert_not_called()
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_source_protection_failures_never_publish(self):
        self.root.chmod(0o755)
        self.assertEqual(self.execute().outcome, "failed")
        self.root.chmod(0o700)
        self.adapter._uid = os.getuid() + 1
        self.assertEqual(self.execute().outcome, "failed")
        self.adapter._uid = os.getuid()
        target = self.root / "other.json"
        self.source.rename(target)
        self.source.symlink_to(target)
        self.assertEqual(self.execute().outcome, "failed")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_wrong_scope_operation_blocked_plan_or_budget_never_reads(self):
        for host, operation, budget, blocked in [
            (ACTOR, "status_refresh", 3, False),
            (HOST, "diagnostics_capture", 3, False),
            (HOST, "drained_provider_restart", 3, True),
            (HOST, "status_refresh", 1, False),
            (HOST, "status_refresh", 3, True),
        ]:
            data = self.plan.as_dict()
            data.update(target_host=host, blocked=blocked)
            data["runbook"]["manifest"].update(
                operation=operation, runbook_id=operation, timeout_seconds=budget
            )
            with patch(READ) as read:
                with self.assertRaises(PolicyError):
                    self.adapter.execute(
                        RepairPlan(canonical(data)), stop_event=self.event
                    )
                read.assert_not_called()

    def test_disruptive_signed_plans_remain_blocked_and_never_read(self):
        key = Ed25519PrivateKey.generate()
        for operation in (
            "drained_provider_restart",
            "model_load_retry",
            "stale_state_reconciliation",
        ):
            manifest = canonical(
                dict(
                    schema_version=1,
                    runbook_id=operation,
                    version=1,
                    operation=operation,
                    timeout_seconds=3,
                )
            )
            catalog = RunbookCatalog(
                trusted_keys={"test": key.public_key().public_bytes_raw()},
                allowed_versions=frozenset(
                    {(operation, 1, hashlib.sha256(manifest).hexdigest())}
                ),
            )
            book = catalog.verify_runbook(
                manifest, key.sign(SIGNING_CONTEXT + manifest), key_id="test"
            )
            plan = catalog.plan(book, HOST, [], now=NOW)
            self.assertTrue(plan.as_dict()["blocked"])
            with patch(READ) as read:
                with self.assertRaises(PolicyError):
                    self.adapter.execute(plan, stop_event=self.event)
                read.assert_not_called()

    def test_reader_projection_binding_revalidated_before_publication(self):
        state = read_daemon_state(
            str(self.source), expected_owner_uid=os.getuid(), now=NOW
        )
        for change in (
            {"freshness_seconds": 61},
            {"timestamp": BEFORE},
            {"source": "console"},
        ):
            readings = json.loads(json.dumps(state.result.readings))
            readings["requests_total"].update(change)
            altered = DaemonStateResult(NOW, AdapterResult(readings, ()))
            with (
                patch(READ, return_value=altered),
                patch.object(self.store, "accept") as accept,
            ):
                self.assertEqual(self.execute().reason, "invalid_result")
                accept.assert_not_called()

    def test_invalid_constructor_never_reads_or_generates_capabilities(self):
        defaults = dict(
            target_host=HOST,
            source_path=str(self.source),
            expected_owner_uid=os.getuid(),
            store=self.store,
            wall_clock=lambda: NOW,
        )
        for change in (
            dict(source_path="relative"),
            dict(expected_owner_uid=2**32 - 1),
            dict(target_host=ACTOR),
            dict(total_timeout_seconds=True),
            dict(total_timeout_seconds=float("nan")),
            dict(total_timeout_seconds=31),
        ):
            with patch(READ) as read:
                with self.assertRaises(PolicyError):
                    DaemonStateRefreshAdapter(**dict(defaults, **change))
                read.assert_not_called()

    def test_precancel_and_cancel_after_read_do_not_publish(self):
        self.event.set()
        with patch(READ) as read:
            self.assertEqual(self.execute().outcome, "cancelled")
            read.assert_not_called()
        self.event.clear()

        def cancel(*args, **kwargs):
            state = read_daemon_state(*args, **kwargs)
            self.event.set()
            return state

        with (
            patch(READ, side_effect=cancel),
            patch.object(self.store, "accept") as accept,
        ):
            self.assertEqual(self.execute().outcome, "cancelled")
            accept.assert_not_called()

    def test_elapsed_budget_before_publication_never_accepts(self):
        self.adapter._clock = iter((0, 3)).__next__
        with patch.object(self.store, "accept") as accept:
            self.assertEqual(self.execute().reason, "deadline_exceeded")
            accept.assert_not_called()

    def test_real_elapsed_guard_works_with_frozen_injected_clock(self):
        self.adapter._clock = lambda: 0
        with (
            patch("gargoyl.repair_state_adapter.time.monotonic", side_effect=(0, 3)),
            patch.object(self.store, "accept") as accept,
        ):
            self.assertEqual(self.execute().reason, "deadline_exceeded")
            accept.assert_not_called()

    def test_source_expiring_during_read_or_wall_rollback_never_publish(self):
        self.write(dict(fixture(), written_at=EPOCH - 59))
        self.adapter._wall_clock = iter((NOW, "2026-01-01T00:00:02Z")).__next__
        self.assertEqual(self.execute().outcome, "failed")
        self.adapter._wall_clock = iter((NOW, BEFORE)).__next__
        self.assertEqual(self.execute().reason, "clock_invalid")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_late_durable_publication_is_unknown_without_rollback(self):
        self.adapter._clock = iter((0, 0, 0, 3)).__next__
        result = self.execute()
        self.assertEqual(
            (result.outcome, result.reason), ("outcome_unknown", "deadline_exceeded")
        )
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)

    def test_cancel_during_acceptance_preserves_uncertain_durable_result(self):
        original = self.store.accept

        def cancel(*args, **kwargs):
            accepted = original(*args, **kwargs)
            self.event.set()
            return accepted

        with patch.object(self.store, "accept", side_effect=cancel):
            result = self.execute()
        self.assertEqual(
            (result.outcome, result.reason), ("outcome_unknown", "cancelled")
        )
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)

    def test_expiration_during_acceptance_retains_record_without_fresh_success(self):
        self.write(dict(fixture(), written_at=EPOCH - 59))
        self.adapter._wall_clock = iter((NOW, NOW, "2026-01-01T00:00:02Z")).__next__
        result = self.execute()
        self.assertEqual(
            (result.outcome, result.reason), ("outcome_unknown", "invalid_result")
        )
        records = self.store.snapshots(now="2026-01-01T00:00:02Z")
        self.assertEqual(len(records), 1)
        self.assertEqual(
            records[0]["fields"]["requests_total"]["timestamp"], "2025-12-31T23:59:01Z"
        )

    def test_real_clock_source_expires_during_sub_budget_commit_delay(self):
        now = datetime.now(timezone.utc).timestamp()
        self.write(dict(fixture(), written_at=now - 59.2, started_at=now - 100))
        self.adapter._wall_clock = lambda: datetime.now(timezone.utc).isoformat()
        accept = self.store.accept

        def delayed(*args, **kwargs):
            time.sleep(1.2)
            return accept(*args, **kwargs)

        with patch.object(self.store, "accept", side_effect=delayed):
            result = self.execute()
        self.assertEqual(result.outcome, "outcome_unknown")
        self.assertIn(result.reason, {"invalid_result", "deadline_exceeded"})
        records = self.store.snapshots(now=datetime.now(timezone.utc).isoformat())
        self.assertEqual(len(records), 1)

    def test_storage_failure_or_false_acceptance_never_claims_success(self):
        self.store._db.execute("PRAGMA query_only=ON")
        self.assertEqual(self.execute().reason, "audit_unavailable")
        self.store._db.execute("PRAGMA query_only=OFF")
        with patch.object(self.store, "accept", return_value=False):
            self.assertEqual(self.execute().reason, "audit_unavailable")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_monotonic_rollback_and_interruption_fail_closed(self):
        self.adapter._clock = iter((2, 1)).__next__
        self.assertEqual(self.execute().reason, "invalid_result")
        self.adapter._clock = lambda: 0
        with patch(READ, side_effect=KeyboardInterrupt):
            self.assertEqual(self.execute().reason, "interrupted")
        self.assertEqual(self.store.snapshots(now=NOW), [])

    def test_signed_runtime_claims_before_read_and_persists_receipt_and_replay_guard(
        self,
    ):
        runtime, audit = self.runtime()

        def verify_claim(*args, **kwargs):
            self.assertEqual(audit.lookup(CLICK).as_dict()["state"], "started")
            return read_daemon_state(*args, **kwargs)

        with patch(READ, side_effect=verify_claim) as read:
            receipt = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(receipt.as_dict()["outcome"], "succeeded")
            replay = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(replay.as_dict()["reason"], "already_claimed")
            self.assertEqual(read.call_count, 1)
        self.assertEqual(audit.lookup(CLICK).as_dict()["receipt"], receipt.as_dict())
        self.assertNotIn("synthetic-private", repr(receipt.as_dict()))

    def test_authorization_denial_and_audit_failure_prevent_source_read(self):
        runtime, audit = self.runtime(granted=False)
        with patch(READ) as read:
            receipt = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(receipt.as_dict()["reason"], "authorization_denied")
            read.assert_not_called()
        runtime.authorization = self.runtime_authorization_granted()
        with (
            patch.object(audit, "claim", side_effect=OSError("synthetic-private")),
            patch(READ) as read,
        ):
            receipt = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(receipt.as_dict()["reason"], "audit_unavailable")
            read.assert_not_called()

    def runtime_authorization_granted(self):
        key = Ed25519PrivateKey.generate()
        self.registry = OperatorRegistry(
            {
                "operator": OperatorKey(
                    key.public_key().public_bytes_raw(),
                    OperatorPrincipal(ACTOR, frozenset({(HOST, "status_refresh")})),
                )
            }
        )
        return OperatorAuthorization(
            dict(
                key_id="operator",
                signature=key.sign(repair_intent_bytes(AUDIENCE, self.confirmation)),
            ),
            registry_provider=lambda: self.registry,
            audience=AUDIENCE,
            wall_clock=lambda: NOW,
        )

    def test_revocation_during_claim_prevents_read_and_consumes_intent(self):
        runtime, audit = self.runtime()
        claim = audit.claim

        def revoke(*args, **kwargs):
            result = claim(*args, **kwargs)
            self.registry = OperatorRegistry(
                {
                    "operator": OperatorKey(
                        Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                        OperatorPrincipal(ACTOR),
                    )
                }
            )
            return result

        with patch.object(audit, "claim", side_effect=revoke), patch(READ) as read:
            receipt = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(receipt.as_dict()["reason"], "authorization_denied")
            read.assert_not_called()
        self.assertEqual(audit.lookup(CLICK).as_dict()["state"], "finished")
        self.assertFalse(audit.claim(self.plan, self.confirmation, now=NOW))

    def test_finalize_failure_retains_durable_evidence_and_consumed_claim(self):
        runtime, audit = self.runtime()
        with (
            patch.object(audit, "finalize", side_effect=OSError("synthetic-private")),
            patch(READ, wraps=read_daemon_state) as read,
        ):
            receipt = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(receipt.as_dict()["reason"], "audit_unavailable")
            self.assertEqual(receipt.as_dict()["outcome"], "outcome_unknown")
            replay = runtime.execute(
                self.plan, self.confirmation, stop_event=self.event
            )
            self.assertEqual(replay.as_dict()["reason"], "already_claimed")
            self.assertEqual(read.call_count, 1)
        self.assertEqual(audit.lookup(CLICK).as_dict()["state"], "started")
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)
