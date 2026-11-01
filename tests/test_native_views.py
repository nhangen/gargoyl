import unittest
from unittest.mock import patch

from test_dashboard import HOST, NOW, snapshot
from test_manual_restart import TARGET

from gargoyl.gui_runtime import native_view
from gargoyl.native_views import VIEWS, render_view


class NativeViewTests(unittest.TestCase):
    def evidence(self):
        return dict(evaluated_at=NOW, snapshots=[snapshot()])

    def test_full_admin_inventory_has_only_read_only_navigation(self):
        page = render_view('tools', self.evidence(), None, now=NOW)
        for label in ('Operator tools', 'Health, model and connection', 'Export diagnostics',
                      'Manual provider restart', 'Mac confirmation required', 'Not available in this app'):
            self.assertIn(label, page)
        for view in VIEWS:
            self.assertIn('gargoyl-view://' + view + '/', page)
        for forbidden in ('<form', '<script', '/s/', 'token=', 'terminal', 'href="http'):
            self.assertNotIn(forbidden, page)

    def test_missing_monitor_never_retains_a_healthy_view_and_operation_is_independent(self):
        for view in VIEWS:
            page = render_view(view, None, None, now=NOW)
            self.assertIn('Direct local observations unavailable' if view == 'fleet' else 'Monitor evidence unavailable', page)
            self.assertIn('unknown', page)
        with patch('gargoyl.gui_runtime.export_evidence', side_effect=OSError), patch(
            'gargoyl.gui_runtime.read_operation', return_value=None
        ) as read, patch('gargoyl.gui_runtime.owner_home', return_value=__import__('pathlib').Path('/owner')):
            self.assertIn('No manual operation recorded', native_view('view-operation')['html'])
            read.assert_called_once_with('/owner/.gargoyl-manual-restart')

    def test_journal_is_not_read_for_other_views_and_invalid_view_cannot_acquire(self):
        with patch('gargoyl.gui_runtime.export_evidence', return_value=self.evidence()) as export, patch(
            'gargoyl.gui_runtime.read_operation', side_effect=AssertionError('private read')
        ):
            for view in ('tools', 'evidence', 'history', 'details'):
                self.assertEqual(native_view('view-' + view)['view'], view)
            calls = export.call_count
            with self.assertRaises(ValueError):
                native_view('view-restart')
            self.assertEqual(export.call_count, calls)

    def test_stale_and_future_evidence_are_not_current_health(self):
        page = render_view('evidence', self.evidence(), None, now='2026-01-02T00:00:00Z')
        self.assertIn('stale (reported: observed)', page)
        self.assertIn('Protocol confidence: <strong>unknown', page)
        data = dict(evaluated_at=NOW, snapshots=[snapshot('requests_total', 0, source='daemon')])
        page = render_view('history', data, None, now='2025-12-31T00:00:00Z')
        self.assertIn('<td>unknown</td>', page)
        self.assertIn('Zero traffic alone is not failure', page)
        self.assertNotIn('>failure<', page)

    def test_rejects_cross_host_oversized_and_injected_evidence(self):
        for mutate in (lambda d: d['snapshots'].append(dict(snapshot(), host_id='00000000-0000-4000-8000-000000000002')),
                       lambda d: d.update(snapshots=[snapshot()] * 65),
                       lambda d: d['snapshots'][0]['fields']['daemon_state'].update(value='<script>')):
            data = self.evidence()
            mutate(data)
            with self.assertRaises(ValueError):
                render_view('evidence', data, None, now=NOW)

    def test_log_counts_are_not_presented_as_current_when_stale_or_future(self):
        data = self.evidence()
        data['coordinator_log_report'] = dict(state='observed', reason='visible_records_only',
            observed_at=NOW, freshness_seconds=45, window_start=NOW, window_end=NOW,
            count=10, redacted_count=2, latest_event_at=NOW)
        for now in ('2026-01-02T00:00:00Z', '2025-12-31T00:00:00Z'):
            page = render_view('evidence', data, None, now=now)
            self.assertIn('Current counts and recency are unknown', page)
            self.assertNotIn('Visible records: 10', page)
        self.assertIn('Visible records: 10', render_view('evidence', data, None, now=NOW))

    def test_shared_journal_states_are_truthful_and_never_offer_clear_or_retry(self):
        # Use actual journal schema/UUID timestamp requirements from backend fixtures.
        import tempfile
        from pathlib import Path

        from gargoyl.manual_restart import ManualJournal, run_restart
        with tempfile.TemporaryDirectory() as directory:
            with ManualJournal(str(Path(directory).resolve() / 'journal')) as journal:
                from test_manual_restart import REPLACEMENT
                observations = iter((TARGET, REPLACEMENT))
                record = run_restart(journal, TARGET, inspect_target=lambda: next(observations),
                                     invoke=lambda: 0, confirm=lambda _: True, progress=lambda _: None)
        for state, reason in [('intent', 'invocation_not_confirmed'), ('unknown', 'completion_unverified'),
                              ('completed', 'cli_success_and_replacement_observed')]:
            data = dict(record, state=state, reason=reason)
            page = render_view('operation', None, data, now=NOW)
            self.assertIn('Verified replacement observed' if state == 'completed' else 'Unresolved — native retry blocked', page)
            self.assertNotIn('<form', page)
        data = dict(record, state='reconciled', reason='reconciled_read_only',
                    reconciled_at=record['finished_at'], observation='provider_unobservable')
        self.assertIn('Unresolved — native retry blocked', render_view('operation', None, data, now=NOW))
        page = render_view('operation', None, None, journal_available=False, now=NOW)
        self.assertIn('Operation record unavailable', page)
        self.assertNotIn('No manual operation recorded', page)

    def test_native_restart_refuses_all_unresolved_and_reconciled_states_before_preflight(self):
        from unittest.mock import Mock

        from gargoyl.gui_runtime import graphical_restart
        for state in ('intent', 'unknown', 'reconciled'):
            journal = Mock()
            journal.read.return_value = dict(state=state)
            preflight = Mock()
            invoke = Mock()
            with self.assertRaises(ValueError):
                graphical_restart(journal=journal, preflight=preflight,
                    inspect_target=Mock(), invoke=invoke, receive=Mock(), owner=lambda: True)
            preflight.assert_not_called()
            invoke.assert_not_called()

    def test_native_fragment_links_are_absolute_for_opaque_about_blank_document(self):
        for view in VIEWS:
            page = render_view(view, self.evidence(), None, now=NOW)
            self.assertNotIn('href="#', page)
            self.assertIn('href="about:blank#main"', page)
        page = render_view('evidence', self.evidence(), None, now=NOW)
        self.assertIn('href="about:blank#fleet-overview"', page)
        self.assertIn('href="about:blank#host-' + HOST, page)

    def test_default_public_dashboard_does_not_gain_private_views(self):
        from gargoyl.dashboard import render_dashboard
        page = render_dashboard([snapshot()], [HOST], NOW)
        self.assertNotIn('gargoyl-view:', page)
        self.assertNotIn('Native operator console', page)
