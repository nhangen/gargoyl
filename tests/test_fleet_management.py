"""Management views consume existing evidence only; no enrollment or lifecycle."""
import copy
import json
import re
import unittest
from html import escape

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
        second['status'] = 'offline'
        second['last_heartbeat'] = '2026-10-31T23:00:00Z'
        second['version'] = '0.10.5'
        raw['providers'].append(second)
        raw['total_count'] = len(raw['providers'])
        self.fixture_providers = raw['providers']
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
                           aliases=kwargs.get('aliases', {}), preview=kwargs.get('preview', False))

    def test_only_fresh_unique_identity_receives_direct_history_and_native_review(self):
        rows = self.project()['rows']
        self.assertEqual((rows[0]['collection'], rows[0]['process_state'], rows[0]['history_samples'],
                          rows[0]['manual_restart']), ('local_associated', 'observed', 1, 'native_review'))
        self.assertEqual((rows[1]['collection'], rows[1]['history_samples'], rows[1]['manual_restart']),
                         ('inventory_only', None, 'unavailable'))
        page = self.page()
        self.assertIn('no remote history', page)
        self.assertIn('no enrollment, remote command or restart is initiated', page)
        self.assertIn('Account inventory read ' + NOW, page)
        self.assertIn('local report', page)
        self.assertIn('<br><span class="mono">provider-real-format-test-only</span>', page)
        self.assertIn('no provider control', page)
        self.assertNotIn('must-never-persist', page)
        for forbidden in ('<form', '<script', 'gargoyl-action:', 'token='):
            self.assertNotIn(forbidden, page)

    def test_management_table_shows_row_specific_reports_and_one_coverage_note(self):
        raw = response()
        third = {'id': 'missing-fields-test-only', 'name': 'Unreported provider'}
        raw['providers'] = [
            *self.fixture_providers,
            third,
        ]
        raw['total_count'] = 3
        page = self.page(inventory=normalize_inventory(raw, NOW))
        summary, body = page.split('<tbody>', 1)
        table, note = body.split('</tbody></table>', 1)
        local, remote, sparse = re.findall(r'<tr><th scope="row">.*?</tr>', table)
        self.assertIn('provider-real-format-test-only', local)
        self.assertIn('This Mac · unique identity match', local)
        self.assertIn('running', local)
        self.assertIn('>recent</td>', local)
        self.assertIn('>0.10.6</span>', local)
        self.assertIn('1 retained sample<', local)
        self.assertIn('Use <strong>Restart local…</strong> in the toolbar', local)
        self.assertIn('href="gargoyl-view://operation/">Operation status</a>', local)
        self.assertNotIn('>Restart local…</a>', table)
        self.assertIn('second-provider-test-only', remote)
        self.assertIn('<span class="adv">offline</span>', remote)
        self.assertIn('>report current</span>', summary)
        self.assertNotIn('report current', table)
        self.assertIn('>older</td>', remote)
        self.assertIn('>0.10.5</span>', remote)
        self.assertIn('missing-fields-test-only', sparse)
        self.assertIn('status not reported', sparse)
        self.assertIn('>unknown</td>', sparse)
        self.assertIn('>not reported</span>', sparse)
        for inventory_row in (remote, sparse):
            self.assertIn('Inventory only', inventory_row)
            for local_only in ('This Mac', 'Restart local', 'gargoyl-view://history/', 'gargoyl-view://operation/'):
                self.assertNotIn(local_only, inventory_row)
        self.assertNotIn('no verified direct collector association', table)
        self.assertEqual(note.count('no verified direct collector association'), 1)
        self.assertIn('no remote history', note)

    def test_preview_keeps_read_only_status_without_restart_instruction(self):
        page = self.page(preview=True)
        table, _ = page.split('</tbody></table>', 1)
        self.assertIn('This Mac · unique identity match', table)
        self.assertIn('href="gargoyl-view://operation/">Operation status</a>', table)
        self.assertNotIn('Restart local…', page)

    def test_large_inventory_fits_native_limits_and_provider_details_keep_full_values(self):
        for count, punctuation, value_length, alias_count in ((200, '"', 64, 0), (256, '&', 64, 0),
                                                               (229, '"', 16, 15)):
            with self.subTest(count=count, punctuation=punctuation, value_length=value_length):
                status = punctuation * value_length
                version = "'" * value_length if punctuation == '"' else punctuation * value_length
                raw = {'providers': [
                    {'id': punctuation * 125 + f'{index:03d}', 'name': punctuation * 128,
                     'status': status, 'version': version}
                    for index in range(count)
                ]}
                inventory = normalize_inventory(raw, NOW)
                aliases = {provider['id']: punctuation * 64 for provider in raw['providers'][:alias_count]}
                if aliases:
                    inventory['connection'] = 'disconnected'
                page = self.page(inventory=inventory, local=None, evidence=None, aliases=aliases)
                self.assertLessEqual(len(page.encode()), 500_000)
                self.assertLessEqual(len(json.dumps({'html': page}, ensure_ascii=False).encode()), 590_000)
                self.assertEqual(page.count('<tr><th scope="row">'), count)
                self.assertIn('Select a provider to see its full report values.', page)
                self.assertNotIn('<td>' + escape(status) + '</td>', page)
                self.assertNotIn('<td><span class="mono">' + escape(version) + '</span></td>', page)
                provider_id = raw['providers'][-1]['id']
                self.assertIn(escape(provider_id), page)
                link = re.search(r'href="gargoyl-view://(fleet-node-[a-f0-9]+)/"', page)
                detail = render_view(link.group(1), None, None, inventory=inventory, now=NOW)
                self.assertIn(escape(status), detail)
                self.assertIn(escape(version), detail)

    def test_names_and_aliases_never_supply_association_or_action_authority(self):
        page = self.page(local=None, aliases={'second-provider-test-only':'MBP-2026.local'})
        self.assertIn('MBP-2026.local', page)
        self.assertNotIn('unique identity match', page)
        self.assertNotIn('Open local history', page)
        self.assertNotIn('gargoyl-view://operation/">Operation status</a>', page)

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
        self.assertIn('An undetected reset can affect this comparison', page)
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
                self.assertIn('Unknown — needs fresh, ordered observations', page)
                self.assertNotIn('Observed counter change', page)
