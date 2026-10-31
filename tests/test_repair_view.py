import hashlib
import re
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_telemetry import snapshot

from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import (
    RUNBOOK_IDS,
    RepairAuditEntry,
    RepairConfirmation,
    RepairPlan,
    RepairReceipt,
    canonical,
    manifest_bytes,
)
from gargoyl.repair_view import render_audit_entry, render_preview, render_receipt

HOST = '00000000-0000-4000-8000-000000000001'
ACTOR = '00000000-0000-4000-8000-000000000002'
CLICK = '00000000-0000-4000-8000-000000000003'
NOW = '2026-01-01T00:00:00Z'
LATER = '2026-01-01T00:00:30Z'
END = '2026-01-01T00:01:00Z'


class RepairViewTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.catalog, self.book, self.plan = self.fixture()

    def fixture(self, operation='status_refresh', evidence=None, version=1):
        manifest = {'schema_version': 1, 'runbook_id': operation, 'version': version,
                    'operation': operation, 'timeout_seconds': 5}
        payload = manifest_bytes(manifest)
        catalog = RunbookCatalog(trusted_keys={'test': self.key.public_key().public_bytes_raw()},
                                 allowed_versions=frozenset({(operation, version, hashlib.sha256(payload).hexdigest())}))
        book = catalog.verify_runbook(payload, self.key.sign(SIGNING_CONTEXT + payload), key_id='test')
        return catalog, book, catalog.plan(book, HOST, evidence or [], now=NOW)

    def confirmation(self):
        return RepairConfirmation(canonical(dict(schema_version=1, actor_id=ACTOR, click_id=CLICK,
            target_host=HOST, runbook_id='status_refresh', version=1, runbook_digest=self.book.digest,
            plan_digest=self.plan.digest, confirmed_at=NOW, expires_at=END, impact_acknowledged=False)))

    def receipt(self, outcome='succeeded', reason='completed', cleanup=True):
        return RepairReceipt(canonical(dict(schema_version=1, actor_id=ACTOR, click_id=CLICK,
            target_host=HOST, runbook_id='status_refresh', version=1, runbook_digest=self.book.digest,
            plan_digest=self.plan.digest, preflight=self.plan.as_dict(), started_at=NOW, finished_at=LATER,
            stage='completion', outcome=outcome, reason=reason, cleanup_complete=cleanup)))

    def entry(self, receipt=None):
        return RepairAuditEntry(canonical(dict(schema_version=1, state='finished' if receipt else 'started',
            plan=self.plan.as_dict(), confirmation=self.confirmation().as_dict(), started_at=NOW,
            receipt=receipt.as_dict() if receipt else None)))

    def assert_read_only(self, page):
        for tag in ('<form', '<button', '<input', '<script', 'onclick='):
            self.assertNotIn(tag, page)
        # The shared presentation shell permits only navigation within this
        # document, never a repair route, external resource or action link.
        self.assertEqual(set(re.findall(r'href="([^"]*)"', page)), {'#main'})
        self.assertIn('id="main"', page)

    def test_exact_bindings_and_intent_are_not_authorization(self):
        page = render_preview(self.plan, self.catalog, now=NOW, confirmation=self.confirmation())
        for value in (HOST, ACTOR, CLICK, self.book.digest, self.plan.digest, NOW, END,
                      'Intent binding valid as data only', 'permission remain unverified'):
            self.assertIn(value, page)
        self.assert_read_only(page)

    def test_all_runbooks_keep_missing_safety_prerequisites_blocked(self):
        for name in RUNBOOK_IDS:
            catalog, _, plan = self.fixture(name, [snapshot()])
            page = render_preview(plan, catalog, now=NOW)
            self.assert_read_only(page)
            if name in {'status_refresh', 'diagnostics_capture'}:
                self.assertIn('Preview only', page)
            else:
                self.assertIn('Blocked: preconditions_blocked', page)
                for check in plan.as_dict()['checks'][2:]:
                    self.assertIn(check['check_id'], page)
            self.assertIn('No confirmation supplied', page)

    def test_current_freshness_does_not_relabel_original_evidence(self):
        evidence = snapshot()
        evidence['fields']['daemon_state']['freshness_seconds'] = 10
        catalog, _, plan = self.fixture(evidence=[evidence])
        page = render_preview(plan, catalog, now=LATER)
        original, current = page.split('<h2>Current evidence assessment</h2>')
        self.assertIn('<td>evidence_fresh</td><td>passed</td>', original)
        self.assertIn('<td>evidence_fresh</td><td>unknown</td>', current)
        self.assertIn(NOW, original)
        self.assertIn(plan.digest, original)
        self.assertIn(LATER, current)

    def test_unknown_future_and_conflicting_evidence_stays_unknown(self):
        first = snapshot()
        conflict = snapshot()
        conflict['fields']['daemon_state']['value'] = 'stopped'
        future = snapshot()
        future['collected_at'] = END
        unknown = snapshot()
        unknown['fields']['daemon_state'].update(state='unknown', value=None)
        for evidence in ([], [first, conflict], [future], [unknown]):
            catalog, _, plan = self.fixture(evidence=evidence)
            page = render_preview(plan, catalog, now=NOW)
            self.assertIn('<td>evidence_fresh</td><td>unknown</td>', page)
            self.assertIn('never supplies authorization', page)

    def test_forged_plan_signature_checks_and_expired_preview_fail_closed(self):
        for field in ('signature', 'checks'):
            data = self.plan.as_dict()
            if field == 'signature':
                data['runbook']['signature'] = '0' * 128
            else:
                data['checks'][0]['state'] = 'blocked'
            page = render_preview(RepairPlan(canonical(data)), self.catalog, now=NOW)
            self.assertIn('Repair data unavailable', page)
            self.assertNotIn(self.plan.digest, page)
        for invalid in (object(), object.__new__(RepairPlan)):
            self.assertIn('Repair data unavailable', render_preview(invalid, self.catalog, now=NOW))
        self.assertIn('Repair data unavailable', render_preview(self.plan, self.catalog, now=END))

    def test_mismatched_confirmation_never_shows_valid_binding(self):
        for update in ({'target_host': ACTOR}, {'version': 2}, {'runbook_digest': '0'*64},
                       {'plan_digest': '0'*64}, {'runbook_id': 'diagnostics_capture'},
                       {'expires_at': '2026-01-01T00:00:01Z'}):
            confirmation = RepairConfirmation(canonical(dict(self.confirmation().as_dict(), **update)))
            page = render_preview(self.plan, self.catalog, now=LATER, confirmation=confirmation)
            self.assertIn('Repair data unavailable', page)
            self.assertNotIn('Intent binding valid', page)

    def test_historical_receipt_survives_catalog_revocation_and_expiry(self):
        replacement, _, _ = self.fixture(version=2)
        self.assertIn('Repair data unavailable', render_preview(self.plan, replacement, now=NOW))
        self.assertIn('Repair data unavailable', render_preview(self.plan, self.catalog, now=END))
        page = render_receipt(self.receipt())
        self.assertIn('Reported outcome', page)
        self.assertIn('succeeded', page)
        self.assertIn('does not independently verify execution', page)
        self.assertIn('historical claims', page)
        self.assert_read_only(page)

    def test_claim_absence_uncertainty_failure_and_clock_invalid(self):
        self.assertIn('Outcome unknown', render_audit_entry(None))
        started = render_audit_entry(self.entry())
        self.assertIn('recovery_required', started)
        self.assertIn('Do not automatically retry', started)
        self.assertNotIn('Reported terminal result', started)
        for outcome, reason, cleanup in (('failed', 'operation_failed', True),
                                        ('cancelled', 'cancelled', True),
                                        ('outcome_unknown', 'cleanup_incomplete', False),
                                        ('outcome_unknown', 'clock_invalid', True)):
            page = render_audit_entry(self.entry(self.receipt(outcome, reason, cleanup)))
            self.assertIn(outcome, page)
            self.assertIn(reason, page)
            self.assert_read_only(page)
            if reason == 'clock_invalid':
                self.assertIn('not a trustworthy completion time', page)

    def test_malformed_historical_data_and_exception_text_never_escape(self):
        for cls, render in ((RepairReceipt, render_receipt), (RepairAuditEntry, render_audit_entry)):
            forged = object.__new__(cls)
            object.__setattr__(forged, 'payload', b'{"raw_output":"<script>synthetic-secret</script>"}')
            page = render(forged)
            self.assertIn('Repair data unavailable', page)
            self.assertNotIn('synthetic-secret', page)
            self.assertNotIn('<script>', page)
        with patch.object(RunbookCatalog, 'validate_plan', side_effect=RuntimeError('synthetic-secret')):
            self.assertNotIn('synthetic-secret', render_preview(self.plan, self.catalog, now=NOW))
