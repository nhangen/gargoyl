import copy
import subprocess
import sys
import unittest
from itertools import permutations

from gargoyl.dashboard import build_dashboard, render_dashboard
from gargoyl.telemetry import PolicyError

HOST = '00000000-0000-4000-8000-000000000001'
NOW = '2026-01-01T00:00:00Z'


def snapshot(metric='daemon_state', value='running', source='daemon', state='observed', at=NOW, ttl=300):
    return {'schema_version': 1, 'host_id': HOST, 'collected_at': at,
            'fields': {metric: {'value': value, 'source': source, 'timestamp': at,
                              'freshness_seconds': ttl, 'state': state, 'sensitivity': 'safe'}}}


def project(data, now=NOW):
    return build_dashboard(data, [HOST], now)['hosts'][0]


class DashboardTests(unittest.TestCase):
    def test_missing_host_and_fields_are_unknown(self):
        host = project([])
        self.assertIn('missing_collector_heartbeat', host['incidents'])
        self.assertTrue(all(c['state'] == 'unknown' for c in host['comparisons']))
        page = render_dashboard([], [HOST], NOW)
        self.assertIn('No report', page)
        self.assertIn('unknown', page)

    def test_mismatch_immediate_and_at_five_minutes(self):
        data = [snapshot(), snapshot(value='stopped', source='coordinator')]
        for now in (NOW, '2026-01-01T00:05:00Z'):
            host = project(data, now)
            self.assertEqual(host['comparisons'][0]['state'], 'mismatch')
            self.assertEqual(len(host['comparisons'][0]['evidence']), 2)
        self.assertEqual(project(data, '2026-01-01T00:05:01Z')['comparisons'][0]['state'], 'unknown')

    def test_unavailable_ancillary_sources_do_not_hide_mismatch(self):
        for source in ('doctor', 'launchd', 'host', 'collector'):
            for state in ('stale', 'unknown', 'blocked'):
                with self.subTest(source=source, state=state):
                    ancillary = snapshot(source=source, state=state,
                                         value='running' if state == 'stale' else None)
                    data = [snapshot(), snapshot(value='stopped', source='coordinator'), ancillary]
                    host = project(data)
                    self.assertEqual(host['comparisons'][0]['state'], 'mismatch')
                    self.assertIn('daemon_state_mismatch', host['incidents'])
                    self.assertIn('daemon_state: mismatch', render_dashboard(data, [HOST], NOW))
                    data[1] = snapshot(source='coordinator')
                    self.assertEqual(project(data)['comparisons'][0]['state'], 'unknown')
        data = [snapshot(), snapshot(source='doctor'), snapshot(value='stopped', source='host'),
                snapshot(source='coordinator')]
        self.assertEqual(project(data)['comparisons'][0]['state'], 'mismatch')
        self.assertEqual(project([snapshot(), snapshot(source='coordinator')])['comparisons'][0]['state'], 'agreement')

    def test_mismatch_with_future_or_conflicting_auxiliary_for_all_metrics(self):
        metrics = [('daemon_state', 'running', 'stopped'),
                   ('routing_eligible', 'eligible', 'ineligible'),
                   ('attestation_state', 'valid', 'expired'),
                   ('model_state', 'resident', 'absent')]
        for metric, local_value, remote_value in metrics:
            pair = [snapshot(metric, local_value, 'daemon'),
                    snapshot(metric, remote_value, 'coordinator')]
            future = snapshot(metric, local_value, 'doctor', at='2026-01-01T00:01:00Z')
            conflict = [snapshot(metric, local_value, 'doctor'),
                        snapshot(metric, remote_value, 'doctor')]
            for kind, auxiliary in [('future', [future]), ('conflict', conflict)]:
                for data in permutations(pair + auxiliary):
                    with self.subTest(metric=metric, auxiliary=kind, sources=[d['fields'][metric]['source'] for d in data]):
                        host = project(data)
                        comparison = next(c for c in host['comparisons'] if c['metric'] == metric)
                        self.assertEqual(comparison['state'], 'mismatch')
                        self.assertIn(metric + '_mismatch', host['incidents'])

    def test_conflicting_original_evidence_is_rendered(self):
        first = snapshot()
        second = snapshot(value='stopped', state='stale', ttl=120)
        first['collected_at'] = '2026-01-01T00:00:01Z'
        second['collected_at'] = '2026-01-01T00:00:02Z'
        now = '2026-01-01T00:00:03Z'
        for data in ([first, second], [second, first]):
            host = project(data, now)
            self.assertEqual(host['latest']['daemon_state'][0]['state'], 'unknown')
            self.assertIsNone(host['latest']['daemon_state'][0]['value'])
            page = render_dashboard(data, [HOST], now)
            conflict = page.split('<details open>')[1].split('</details>')[0]
            self.assertIn('unknown — conflicting observations', conflict)
            self.assertIn('No report is selected as authoritative', conflict)
            self.assertIn('observed (reported: observed)', conflict)
            self.assertIn('stale (reported: stale)', conflict)
            self.assertIn('TTL 300s', conflict)
            self.assertIn('TTL 120s', conflict)
            for value, collected in [('running', first['collected_at']), ('stopped', second['collected_at'])]:
                self.assertIn(f'<td>{value}</td><td>daemon</td><td>{NOW}</td><td>{collected}', conflict)
        # A conflicting local source cannot claim agreement with the coordinator.
        self.assertEqual(project([first, second, snapshot(source='coordinator')], now)['comparisons'][0]['state'], 'unknown')

    def test_states_and_future_collection(self):
        for state in ('unknown', 'blocked'):
            self.assertEqual(project([snapshot(value=None, state=state)])['latest']['daemon_state'][0]['state'], state)
        data = snapshot()
        self.assertEqual(project([data], '2026-01-01T00:05:01Z')['latest']['daemon_state'][0]['state'], 'stale')
        data['collected_at'] = '2026-01-01T00:01:00Z'
        self.assertEqual(project([data])['latest']['daemon_state'][0]['state'], 'unknown')

    def test_heartbeat_value_and_elapsed_time_both_count(self):
        data = [snapshot('heartbeat_age_seconds', 290, 'collector')]
        self.assertNotIn('collector_heartbeat_not_current', project(data)['incidents'])
        self.assertIn('collector_heartbeat_not_current', project(data, '2026-01-01T00:00:11Z')['incidents'])
        self.assertIn('collector_heartbeat_not_current', project([snapshot('heartbeat_age_seconds', None, 'collector', 'blocked')])['incidents'])

    def test_out_of_order_and_conflicting_reports(self):
        old = snapshot(value='stopped')
        new = snapshot(at='2026-01-01T00:01:00Z')
        for data in ([old,new], [new,old]):
            self.assertEqual(project(data, '2026-01-01T00:01:00Z')['latest']['daemon_state'][0]['value'], 'running')
        conflicting = [snapshot(), snapshot(value='stopped')]
        self.assertEqual(project(conflicting)['latest']['daemon_state'][0]['state'], 'unknown')

    def test_conflict_evidence_rejects_html_injection(self):
        for key in ('value', 'source', 'timestamp', 'state', 'freshness_seconds'):
            data = snapshot(value='stopped')
            data['fields']['daemon_state'][key] = '<script>alert("synthetic")</script>'
            with self.subTest(key=key), self.assertRaises(PolicyError):
                render_dashboard([snapshot(), data], [HOST], NOW)
        with self.assertRaises(PolicyError):
            render_dashboard([snapshot()], [HOST], '<script>synthetic</script>')

    def test_usage_and_earnings_remain_distinct(self):
        data = [snapshot('requests_total', 42), snapshot('tokens_total', 100),
                snapshot('confirmed_paid_microunits', 7, 'console')]
        page = render_dashboard(data, [HOST], NOW)
        self.assertIn('Local request / token history', page)
        self.assertIn('currency and independent payment verification are not established', page)
        self.assertNotIn('confirmed_paid_microunits', page.split('Local request / token history')[1].split('Console-reported')[0])
        self.assertEqual(project(data[:2])['latest']['confirmed_paid_microunits'], [])

    def test_complete_validation_before_render_and_no_mutation(self):
        data = snapshot()
        original = copy.deepcopy(data)
        render_dashboard([data], [HOST], NOW)
        self.assertEqual(data, original)
        data['fields']['prompt'] = 'synthetic-secret-marker'
        with self.assertRaises(PolicyError):
            render_dashboard([data], [HOST], NOW)

    def test_ui_has_all_required_evidence_and_provenance(self):
        page = render_dashboard([snapshot(), snapshot('error_code','timeout','doctor')], [HOST], NOW)
        for text in ('routing_eligible', 'attestation_state', 'model_state', 'memory_headroom_bytes',
                     'competing_runtimes', 'Source timestamp', 'Collection / freshness', 'timeout', NOW):
            self.assertIn(text, page)
        self.assertNotIn('<button', page)

    def test_degraded_host_evidence_is_not_hidden(self):
        cases = [('attestation_state', 'expired', 'doctor'),
                 ('memory_headroom_bytes', 0, 'host'),
                 ('competing_runtimes', 2, 'host'),
                 ('model_state', 'failed', 'daemon'),
                 ('routing_eligible', 'ineligible', 'coordinator')]
        data = [snapshot(metric, value, source) for metric, value, source in cases]
        host = project(data)
        for metric, value, source in cases:
            self.assertEqual(host['latest'][metric][0]['value'], value)
            self.assertEqual(host['latest'][metric][0]['source'], source)
        page = render_dashboard(data, [HOST], NOW)
        for text in ('expired', 'failed', 'ineligible'):
            self.assertIn(text, page)

    def test_cli_empty_fleet_and_invalid_clock(self):
        command = [sys.executable, '-m', 'gargoyl.dashboard', '--host', HOST, '--now']
        good = subprocess.run(command + [NOW], capture_output=True, text=True)
        self.assertEqual(good.returncode, 0)
        self.assertIn('missing_collector_heartbeat', good.stdout)
        for clock in ('invalid', ''):
            bad = subprocess.run(command + [clock], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, '')
