"""Signed reads and real encrypted stores; only a self-authored subprocess runs."""

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_repair_catalog as fixtures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_repair_catalog import ACTOR, CLICK, END, HOST, NOW
from test_telemetry import snapshot

from gargoyl.collector_acquisition import BoundedAcquirer
from gargoyl.ingestion import EvidenceStore
from gargoyl.operator_report import UNAVAILABLE, render_operator_report
from gargoyl.repair_audit import RepairAuditStore
from gargoyl.repair_host_adapter import StatusRefreshAdapter
from gargoyl.repair_operator import (
    OperatorAuthorization,
    OperatorKey,
    OperatorPrincipal,
    OperatorReadAuthorization,
    OperatorRegistry,
    read_intent_bytes,
    repair_intent_bytes,
)
from gargoyl.repair_runtime import RepairRuntime
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import encode_snapshot

OTHER = '00000000-0000-4000-8000-000000000099'
AUDIENCE = '00000000-0000-4000-8000-000000000098'


class OperatorReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.now = NOW
        self.key = Ed25519PrivateKey.generate()
        self.audit_key = os.urandom(32)
        self.ciphers = {host: SpoolCipher(CollectionIdentity(host), os.urandom(32))
                        for host in (HOST, OTHER)}
        self.open_stores()
        self.grants()
        fixture = fixtures.RepairCatalogTests()
        fixture.setUp()
        self.catalog, self.plan = fixture.catalog, fixture.plan
        self.confirmation = fixture.confirmation()
        producer = self.path / 'synthetic-status'
        producer.write_text(f'#!{sys.executable}\nimport sys\n'
                            "assert sys.argv[1:] == ['status']\nprint('Status: ○ Stopped')\n")
        producer.chmod(0o700)
        self.acquire = BoundedAcquirer(str(producer), environment={}, cwd=str(self.path),
            wall_clock=lambda: self.now, monotonic_clock=time.monotonic,
            total_timeout_seconds=1, cleanup_grace_seconds=.4)

    def open_stores(self):
        self.store = EvidenceStore(self.path / 'evidence', self.ciphers, RetentionPolicy(), NOW)
        self.audit = RepairAuditStore(self.path / 'audit', key=self.audit_key)
        self.addCleanup(self.store.close)
        self.addCleanup(self.audit.close)

    def grants(self, evidence=(HOST,), audit=(HOST,)):
        principal = OperatorPrincipal(ACTOR, frozenset({(HOST, 'status_refresh')}),
                                      frozenset(evidence), frozenset(audit))
        self.registry = OperatorRegistry({'test': OperatorKey(self.key.public_key().public_bytes_raw(), principal)})

    def authorization(self, *, audience=AUDIENCE, signing_key=None):
        request = dict(schema_version=1, actor_id=ACTOR, request_id=OTHER,
                       issued_at=NOW, expires_at=END)
        proof = {'key_id': 'test', 'signature': (signing_key or self.key).sign(read_intent_bytes(AUDIENCE, request))}
        return OperatorReadAuthorization(request, proof, registry_provider=lambda: self.registry,
                                         audience=audience, wall_clock=lambda: self.now)

    def report(self, **overrides):
        args = dict(authorization=self.authorization(), evidence_reader=self.store,
                    audit_reader=self.audit, expected_hosts=[HOST, OTHER], audit_ids=[CLICK], now=self.now)
        args.update(overrides)
        return render_operator_report(**args)

    def execute(self):
        proof = {'key_id': 'test', 'signature': self.key.sign(repair_intent_bytes(AUDIENCE, self.confirmation))}
        auth = OperatorAuthorization(proof, registry_provider=lambda: self.registry,
                                     audience=AUDIENCE, wall_clock=lambda: self.now)
        adapter = StatusRefreshAdapter(HOST, acquirer=self.acquire, store=self.store,
                                      wall_clock=lambda: self.now, total_timeout_seconds=2)
        runtime = RepairRuntime(catalog=self.catalog, audit=self.audit, authorization=auth,
            evidence=lambda host: [], wall_clock=lambda: self.now, adapter=adapter)
        return runtime.execute(self.plan, self.confirmation, stop_event=threading.Event()).as_dict()

    def test_signed_runtime_adapter_store_restart_report(self):
        self.assertEqual(self.execute()['outcome'], 'succeeded')
        self.store.close()
        self.audit.close()
        self.open_stores()
        page = self.report()
        for expected in (HOST, CLICK, 'stopped', 'Reported outcome', 'succeeded', 'no permission to execute or retry'):
            self.assertIn(expected, page)
        self.assertNotIn(OTHER, page)
        for control in ('<form', '<button', '<input', '<script', 'onclick='):
            self.assertNotIn(control, page)
        self.assertEqual(self.execute()['reason'], 'already_claimed')

    def test_finalize_failure_preserves_evidence_and_consumed_claim_after_restart(self):
        with patch.object(self.audit, 'finalize', side_effect=RuntimeError('private-marker')):
            result = self.execute()
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.store.close()
        self.audit.close()
        self.open_stores()
        page = self.report()
        for expected in ('stopped', 'Recorded claim: started', 'recovery_required', 'Do not automatically retry'):
            self.assertIn(expected, page)
        self.assertNotIn('private-marker', page)
        with patch.object(self.acquire, 'acquire') as acquire:
            self.assertEqual(self.execute()['reason'], 'already_claimed')
            acquire.assert_not_called()
        self.assertEqual(len(self.store.snapshots(now=NOW)), 1)

    def test_separate_grants_and_missing_denied_audits_are_identical(self):
        self.execute()
        extra = snapshot()
        extra['host_id'] = OTHER
        self.store.accept(extra, now=NOW)
        self.grants(evidence=(OTHER,), audit=())
        denied = self.report()
        missing = self.report(audit_ids=[OTHER])
        self.assertEqual(denied, missing)
        self.assertNotIn(HOST, denied)
        self.assertNotIn(CLICK, denied)
        self.assertIn(OTHER, denied)
        self.assertIn('missing_collector_heartbeat', denied)
        self.grants(evidence=(), audit=(HOST,))
        audit_only = self.report()
        self.assertIn(CLICK, audit_only)
        self.assertNotIn(OTHER, audit_only)
        self.assertNotIn('missing_collector_heartbeat', audit_only)

    def test_signature_audience_expiry_and_changed_scope_fail_closed(self):
        for auth in (self.authorization(signing_key=Ed25519PrivateKey.generate()),
                     self.authorization(audience=OTHER)):
            with patch.object(self.store, 'snapshots') as read:
                self.assertEqual(self.report(authorization=auth), UNAVAILABLE)
                read.assert_not_called()
        self.now = END
        self.assertEqual(self.report(), UNAVAILABLE)
        self.now = NOW
        original = self.store.snapshots
        def revoke(**kwargs):
            values = original(**kwargs)
            self.grants(evidence=(), audit=())
            return values
        with patch.object(self.store, 'snapshots', side_effect=revoke):
            self.assertEqual(self.report(), UNAVAILABLE)

    def test_denied_and_missing_audits_have_identical_cap_edge_behavior(self):
        self.execute()
        self.grants(audit=())
        size = sum(len(encode_snapshot(value)) for value in self.store.snapshots(now=NOW))
        with patch('gargoyl.operator_report.MAX_INPUT_BYTES', size):
            missing = self.report(audit_ids=[OTHER])
            denied = self.report(audit_ids=[CLICK])
            self.assertNotEqual(missing, UNAVAILABLE)
            self.assertEqual(denied, missing)
            self.grants()
            self.assertEqual(self.report(audit_ids=[CLICK]), UNAVAILABLE)

    def test_expiry_during_read_and_failed_reads_never_return_partial_report(self):
        original = self.store.snapshots
        def expire(**kwargs):
            values = original(**kwargs)
            self.now = END
            return values
        with patch.object(self.store, 'snapshots', side_effect=expire):
            self.assertEqual(self.report(), UNAVAILABLE)
        self.now = NOW
        for reader, method in ((self.store, 'snapshots'), (self.audit, 'lookup')):
            with patch.object(reader, method, side_effect=RuntimeError('private-marker')):
                self.assertEqual(self.report(), UNAVAILABLE)

    def test_missing_stale_conflicting_and_future_evidence(self):
        self.assertIn('missing', self.report())
        first = snapshot()
        self.store.accept(first, now=NOW)
        conflict = snapshot()
        conflict['fields']['daemon_state']['value'] = 'stopped'
        self.store.accept(conflict, now=NOW)
        page = self.report()
        self.assertIn('running', page)
        self.assertIn('stopped', page)
        self.assertIn('conflict', page)
        self.assertIn('stale', self.report(now='2026-01-01T00:02:00Z'))
        self.assertIn('unknown', self.report(now='2025-12-31T23:59:59Z'))

    def test_snapshot_and_byte_caps_and_malformed_audit(self):
        with patch.object(self.store, 'snapshots', return_value=[snapshot()] * 257):
            self.assertEqual(self.report(), UNAVAILABLE)
        size = len(encode_snapshot(snapshot()))
        with patch('gargoyl.operator_report.MAX_INPUT_BYTES', size):
            with patch.object(self.store, 'snapshots', return_value=[snapshot()]):
                self.assertNotEqual(self.report(), UNAVAILABLE)
            with patch.object(self.store, 'snapshots', return_value=[snapshot(), snapshot()]):
                self.assertEqual(self.report(), UNAVAILABLE)
        with patch.object(self.audit, 'lookup', return_value=object()):
            self.assertEqual(self.report(), UNAVAILABLE)

    def test_real_ciphertext_corruption_discards_all_results(self):
        self.execute()
        for database, table in ((self.store._db, 'evidence'), (self.audit._db, 'records')):
            with self.subTest(table=table):
                original = database.execute(f'SELECT payload FROM {table}').fetchone()[0]
                database.execute(f'UPDATE {table} SET payload=?', (b'private-marker',))
                database.commit()
                self.assertEqual(self.report(), UNAVAILABLE)
                database.execute(f'UPDATE {table} SET payload=?', (original,))
                database.commit()
                self.assertNotEqual(self.report(), UNAVAILABLE)

    def test_audit_lookup_binding_and_malformed_snapshot_fail_closed(self):
        self.execute()
        entry = self.audit.lookup(CLICK)
        with patch.object(self.audit, 'lookup', return_value=entry):
            self.assertEqual(self.report(audit_ids=[OTHER]), UNAVAILABLE)
        malformed = snapshot()
        malformed['host_id'] = '<script>private-marker</script>'
        with patch.object(self.store, 'snapshots', return_value=[malformed]):
            self.assertEqual(self.report(), UNAVAILABLE)
