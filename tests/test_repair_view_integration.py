"""Real encrypted audit/runtime composition with test-only authorization/adapters."""
import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyl.collector import collect
from gargoyl.repair_audit import RepairAuditStore
from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import OperationResult, RepairConfirmation, canonical
from gargoyl.repair_runtime import RepairRuntime
from gargoyl.repair_view import render_audit_entry, render_preview, render_receipt
from gargoyl.telemetry import PolicyError

HOST = '00000000-0000-4000-8000-000000000001'
ACTOR = '00000000-0000-4000-8000-000000000002'
CLICK = '00000000-0000-4000-8000-000000000003'
NOW = '2026-01-01T00:00:00Z'
END = '2026-01-01T00:01:00Z'


class SyntheticAuthority:
    def authorize(self, plan, confirmation):
        value = confirmation.as_dict()
        if (value['actor_id'], value['target_host'], value['runbook_id']) != (ACTOR, HOST, 'status_refresh'):
            raise PermissionError('synthetic-private-marker')


class RecordingSyntheticAdapter:
    supported_operations = frozenset({'status_refresh'})
    total_timeout_seconds = 1

    def __init__(self, test):
        self.test = test
        self.calls = 0
        self.result = OperationResult('succeeded', 'completed', True)

    def execute(self, plan, *, stop_event):
        self.calls += 1
        # Verify the real claim is readable before any synthetic operation occurs.
        self.test.assertEqual(self.test.store.lookup(CLICK).as_dict()['state'], 'started')
        return self.result


class RepairViewIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = os.urandom(32)
        self.store = RepairAuditStore(self.temp.name, key=self.key)
        self.addCleanup(lambda: self.store.close())
        signer = Ed25519PrivateKey.generate()
        manifest = canonical(dict(schema_version=1, runbook_id='status_refresh', version=1,
                                  operation='status_refresh', timeout_seconds=5))
        digest = hashlib.sha256(manifest).hexdigest()
        self.catalog = RunbookCatalog(trusted_keys={'test': signer.public_key().public_bytes_raw()},
                                     allowed_versions=frozenset({('status_refresh', 1, digest)}))
        book = self.catalog.verify_runbook(manifest, signer.sign(SIGNING_CONTEXT + manifest), key_id='test')
        self.plan = self.catalog.plan(book, HOST, [], now=NOW)
        self.confirmation = RepairConfirmation(canonical(dict(schema_version=1, actor_id=ACTOR,
            click_id=CLICK, target_host=HOST, runbook_id='status_refresh', version=1,
            runbook_digest=digest, plan_digest=self.plan.digest, confirmed_at=NOW,
            expires_at=END, impact_acknowledged=False)))
        self.clock = NOW
        self.adapter = RecordingSyntheticAdapter(self)
        self.runtime = RepairRuntime(catalog=self.catalog, audit=self.store,
            authorization=SyntheticAuthority(), evidence=lambda host: [], wall_clock=lambda: self.clock,
            adapter=self.adapter)

    def execute(self):
        return self.runtime.execute(self.plan, self.confirmation, stop_event=threading.Event())

    def restart(self):
        self.store.close()
        self.store = RepairAuditStore(self.temp.name, key=self.key)
        self.runtime.audit = self.store

    def test_authorized_synthetic_execution_durable_receipt_and_replay(self):
        preview = render_preview(self.plan, self.catalog, now=NOW, confirmation=self.confirmation)
        self.assertIn('Intent binding valid as data only', preview)
        receipt = self.execute()
        self.assertIn('<dd>succeeded</dd>', render_receipt(receipt))
        self.assertIn('does not independently verify execution', render_receipt(receipt))
        self.restart()
        page = render_audit_entry(self.store.lookup(CLICK))
        for marker in (ACTOR, CLICK, HOST, self.plan.digest, 'Reported terminal result', '<dd>succeeded</dd>'):
            self.assertIn(marker, page)
        replay = render_receipt(self.execute())
        self.assertIn('already_claimed', replay)
        self.assertIn('grants no retry permission', replay)
        self.assertEqual(self.adapter.calls, 1)
        for path in Path(self.temp.name).iterdir():
            self.assertNotIn(b'"preflight"', path.read_bytes())
            self.assertNotIn(b'"confirmation"', path.read_bytes())

    def test_started_claim_restart_stays_unknown_without_execution(self):
        self.assertTrue(self.store.claim(self.plan, self.confirmation, now=NOW))
        self.restart()
        page = render_audit_entry(self.store.lookup(CLICK))
        self.assertIn('recovery_required', page)
        self.assertIn('No terminal receipt', page)
        self.assertNotIn('<dd>succeeded</dd>', page)
        self.assertIn('already_claimed', render_receipt(self.execute()))
        self.assertEqual(self.adapter.calls, 0)
        self.assertEqual(self.store.lookup(CLICK).as_dict()['state'], 'started')

    def test_denied_expired_and_wrong_bindings_never_become_success(self):
        original = self.confirmation
        self.confirmation = RepairConfirmation(canonical(dict(original.as_dict(), actor_id=HOST)))
        denied = render_receipt(self.execute())
        self.assertIn('authorization_denied', denied)
        self.assertNotIn('synthetic-private-marker', denied)
        self.assertIsNone(self.store.lookup(CLICK))
        for update in ({'target_host': ACTOR}, {'plan_digest': '0'*64}, {'version': 2}):
            self.confirmation = RepairConfirmation(canonical(dict(original.as_dict(), **update)))
            with self.assertRaises(PolicyError):
                self.execute()
            self.assertIn('Repair data unavailable', render_preview(
                self.plan, self.catalog, now=NOW, confirmation=self.confirmation))
        self.confirmation = original
        self.clock = END
        with self.assertRaises(PolicyError):
            self.execute()
        self.assertIn('Repair data unavailable', render_preview(self.plan, self.catalog, now=END))
        self.assertIsNone(self.store.lookup(CLICK))
        self.assertEqual(self.adapter.calls, 0)

    def test_actual_finalize_failure_preserves_unknown_claim_and_no_retry(self):
        with closing(sqlite3.connect(Path(self.temp.name) / 'repair-audit.sqlite3')) as connection, connection:
            connection.execute("CREATE TRIGGER deny_finalize BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT, 'synthetic-private-marker'); END")
        result = self.execute()
        page = render_receipt(result)
        self.assertIn('audit_unavailable', page)
        self.assertIn('Outcome unknown', page)
        self.assertNotIn('synthetic-private-marker', page)
        self.restart()
        self.assertIn('recovery_required', render_audit_entry(self.store.lookup(CLICK)))
        self.assertIn('already_claimed', render_receipt(self.execute()))
        self.assertEqual(self.adapter.calls, 1)

    def test_expiry_during_real_claim_renders_consumed_refusal(self):
        original_claim = self.store.claim

        def delayed_claim(*args, **kwargs):
            claimed = original_claim(*args, **kwargs)
            self.clock = END
            return claimed

        with patch.object(self.store, 'claim', side_effect=delayed_claim):
            receipt = self.execute()
        page = render_receipt(receipt)
        self.assertIn('<dd>blocked</dd>', page)
        self.assertIn('confirmation_expired', page)
        self.assertIn('grants no retry permission', page)
        self.assertNotIn('<dd>succeeded</dd>', page)
        self.assertEqual(self.adapter.calls, 0)
        self.restart()
        entry = self.store.lookup(CLICK)
        self.assertEqual(entry.as_dict()['receipt'], receipt.as_dict())
        self.assertIn('confirmation_expired', render_audit_entry(entry))
        self.assertFalse(self.store.claim(self.plan, self.confirmation, now=NOW))
        with self.assertRaises(PolicyError):
            self.execute()
        self.assertEqual(self.adapter.calls, 0)

    def test_changed_valid_evidence_after_claim_renders_refusal(self):
        calls = []
        changed = collect(HOST, NOW, {})

        def evidence(host):
            self.assertEqual(host, HOST)
            calls.append(host)
            return [] if len(calls) == 1 else [changed]

        self.runtime.evidence = evidence
        receipt = self.execute()
        page = render_receipt(receipt)
        self.assertIn('<dd>blocked</dd>', page)
        self.assertIn('plan_changed', page)
        self.assertIn('grants no retry permission', page)
        self.assertEqual(self.adapter.calls, 0)
        self.assertEqual(self.store.lookup(CLICK).as_dict()['receipt'], receipt.as_dict())
        self.assertIn('plan_changed', render_audit_entry(self.store.lookup(CLICK)))
        self.runtime.evidence = lambda host: []
        self.assertIn('already_claimed', render_receipt(self.execute()))
        self.assertEqual(self.adapter.calls, 0)

    def test_failed_operation_receipt_never_implies_retry_permission(self):
        self.adapter.result = OperationResult('failed', 'operation_failed', True)
        page = render_receipt(self.execute())
        self.assertIn('operation_failed', page)
        self.assertIn('grants no retry permission', page)
        self.assertNotIn('<dd>succeeded</dd>', page)
        self.assertIn('already_claimed', render_receipt(self.execute()))
        self.assertEqual(self.adapter.calls, 1)
