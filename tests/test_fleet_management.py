"""Management views consume existing evidence only; no enrollment or lifecycle."""
import copy
import unittest

from test_dashboard import HOST, snapshot
from test_fleet_state import NOW, response

from gargoyl.fleet_management import management_projection
from gargoyl.fleet_state import normalize_inventory, provider_key
from gargoyl.native_views import render_view


class ManagementTests(unittest.TestCase):
    def setUp(self):
        raw = response()
        second = copy.deepcopy(raw['providers'][0])
        second['id'] = 'second-provider-test-only'
        second['se_public_key'] = 'second-public-identity'
        raw['providers'].append(second)
        raw['total_count'] = 2
        self.inventory = normalize_inventory(raw, NOW)
        self.local = dict(identity_digest=provider_key('fixture-public-key'), observed_at=NOW)
        self.evidence = dict(evaluated_at=NOW, snapshots=[snapshot(source='host', at=NOW)])

    def project(self, **kwargs):
        return management_projection(kwargs.get('inventory', self.inventory),
                                     kwargs.get('local', self.local),
                                     kwargs.get('evidence', self.evidence),
                                     kwargs.get('now', NOW), HOST)

    def page(self, **kwargs):
        return render_view('management', kwargs.get('evidence', self.evidence), None,
                           inventory=kwargs.get('inventory', self.inventory),
                           local=kwargs.get('local', self.local), now=kwargs.get('now', NOW),
                           aliases=kwargs.get('aliases', {}))

    def test_only_fresh_unique_identity_receives_direct_history_and_native_review(self):
        rows = self.project()['rows']
        self.assertEqual((rows[0]['collection'], rows[0]['process_state'], rows[0]['history_samples'],
                          rows[0]['manual_restart']), ('local_associated', 'observed', 1, 'native_review'))
        self.assertEqual((rows[1]['collection'], rows[1]['history_samples'], rows[1]['manual_restart']),
                         ('inventory_only', None, 'unavailable'))
        page = self.page()
        self.assertIn('No direct', page.replace('no verified direct', 'No direct'))
        self.assertIn('no remote history', page)
        self.assertIn('Fresh preflight may refuse', page)
        self.assertIn('no provider control', page)
        self.assertNotIn('must-never-persist', page)
        for forbidden in ('<form', '<script', 'gargoyl-action:', 'token='):
            self.assertNotIn(forbidden, page)

    def test_names_and_aliases_never_supply_association_or_action_authority(self):
        page = self.page(local=None, aliases={'second-provider-test-only':'MBP-2026.local'})
        self.assertIn('MBP-2026.local', page)
        self.assertNotIn('identity matched', page)
        self.assertNotIn('Open local history', page)
        self.assertNotIn('native_review', page)

    def test_stale_disconnected_future_missing_and_ambiguous_identity_fail_closed(self):
        disconnected = copy.deepcopy(self.inventory)
        disconnected['connection'] = 'disconnected'
        partial = copy.deepcopy(self.inventory)
        partial['partial'] = True
        duplicate = copy.deepcopy(self.inventory)
        duplicate['providers'][1]['identity_digest'] = duplicate['providers'][0]['identity_digest']
        for changes in ({'local':None}, {'inventory':disconnected}, {'inventory':partial}, {'inventory':duplicate},
                        {'now':'2026-11-01T00:03:00Z'}, {'now':'2026-10-31T23:59:00Z'}):
            with self.subTest(changes=changes):
                rows = self.project(**changes)['rows']
                self.assertTrue(all(row['manual_restart']=='unavailable' for row in rows))
                self.assertTrue(all(row['history_samples'] is None for row in rows))
        page = self.page(inventory=None)
        self.assertIn('coverage is unknown, not an empty fleet', page)
        self.assertNotIn('second-provider-test-only', page)

    def test_account_report_is_not_direct_process_evidence(self):
        self.evidence['snapshots'][0]['fields']['daemon_state']['source'] = 'daemon'
        self.assertEqual(self.project()['rows'][0]['process_state'], 'unknown')
        self.evidence['snapshots'][0]['fields']['daemon_state'].update(source='host', state='blocked', value=None)
        self.assertEqual(self.project()['rows'][0]['process_state'], 'blocked')
        self.assertIn('blocked', self.page())

    def test_cross_host_oversized_and_invalid_snapshots_are_refused(self):
        wrong = copy.deepcopy(self.evidence)
        wrong['snapshots'][0]['host_id'] = '00000000-0000-4000-8000-000000000002'
        for evidence in (wrong, dict(evaluated_at=NOW, snapshots=self.evidence['snapshots']*65)):
            with self.assertRaises(ValueError):
                self.project(evidence=evidence)
        empty = self.project(evidence=None)['rows'][0]
        self.assertIsNone(empty['history_samples'])
        self.assertEqual(empty['process_state'], 'unknown')

    def test_untrusted_labels_are_escaped_and_persistence_is_not_claimed(self):
        self.inventory['providers'][0]['name'] = '<script>host</script>'
        page = self.page()
        self.assertIn('&lt;script&gt;host&lt;/script&gt;', page)
        self.assertNotIn('<script>', page)
        self.assertIn('Durable encrypted history is not activated', page)
        self.assertIn('No history key is created', page)


class HistoryWorkflowTests(unittest.TestCase):
    def sample(self, at, requests, tokens):
        value = snapshot(metric='requests_total', value=requests, source='daemon', at=at, ttl=60)
        value['fields']['tokens_total'] = dict(value['fields']['requests_total'], value=tokens)
        value['fields']['error_code'] = dict(value['fields']['requests_total'], value='none', source='collector')
        return value

    def test_history_shows_real_bounded_changes_and_latest_observations_first(self):
        first = self.sample('2026-11-01T00:00:00Z', 100, 200)
        last = self.sample('2026-11-01T00:00:05Z', 103, 230)
        page = render_view('history', dict(evaluated_at=NOW, snapshots=[first,last]), None,
                           now='2026-11-01T00:00:06Z')
        self.assertIn('3 requests · 30 tokens across 5.0 seconds', page)
        self.assertIn('2 of at most 64 samples', page)
        table = page.split('<tbody>',1)[1]
        self.assertLess(table.index(last['collected_at']), table.index(first['collected_at']))
        self.assertIn('Zero traffic alone is not failure', page)

    def test_resets_staleness_sparse_and_future_collection_never_fabricate_delta(self):
        first = self.sample('2026-11-01T00:00:00Z',100,200)
        last = self.sample('2026-11-01T00:00:05Z',101,220)
        reset = copy.deepcopy(last)
        reset['fields']['requests_total']['value']=1
        future = copy.deepcopy(last)
        future['collected_at']='2026-11-02T00:00:00Z'
        sparse = snapshot(at=NOW)
        for samples, now in (([first,reset], '2026-11-01T00:00:06Z'),
                             ([first,last], '2026-11-02T00:00:06Z'),
                             ([first,future], '2026-11-01T00:00:06Z'),
                             ([sparse,sparse],NOW)):
            with self.subTest(samples=samples):
                page=render_view('history',dict(evaluated_at=NOW,snapshots=samples),None,now=now)
                self.assertIn('Unknown — needs fresh, contiguous, monotonic observations', page)
                self.assertNotIn('Observed counter change', page)
