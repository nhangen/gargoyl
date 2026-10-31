import re
import unittest
from html.parser import HTMLParser

from test_dashboard import HOST, NOW, snapshot

from gargoyl.dashboard import ADVERSE_VALUES, render_dashboard
from gargoyl.dashboard.theme import STYLE
from gargoyl.repair_view import render_restart_unavailable

OTHER = '00000000-0000-4000-8000-0000000000aa'


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.links, self.tags = [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if 'href' in attrs:
            self.links.append(attrs['href'])
        if 'src' in attrs:
            self.links.append(attrs['src'])


class ConsoleTests(unittest.TestCase):
    def test_live_overview_preserves_source_disagreement_and_anchors(self):
        page = render_dashboard([snapshot(), snapshot(value='stopped', source='coordinator')], [HOST], NOW)
        parser = Structure()
        parser.feed(page)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        self.assertTrue(all(link.startswith('#') and link[1:] in parser.ids for link in parser.links))
        self.assertIn('daemon_state_mismatch', page)
        self.assertIn('observed · running', page)
        self.assertIn('observed · <span class="adv">stopped</span>', page)
        self.assertIn('daemon · ' + NOW, page)
        self.assertIn('coordinator · ' + NOW, page)
        self.assertIn('Protocol confidence: <strong>unknown</strong>', page)
        self.assertFalse(set(parser.tags) & {'script', 'form', 'button', 'input', 'link', 'iframe'})

    def test_host_navigation_and_mobile_jump_resolve_for_every_inventory(self):
        for data, hosts in (([snapshot()], [HOST]), ([], [HOST]), ([], [])):
            with self.subTest(hosts=len(hosts), reports=len(data)):
                page = render_dashboard(data, hosts, NOW)
                parser = Structure()
                parser.feed(page)
                self.assertIn('<a class="jump-link" href="#fleet-overview">Jump to hosts</a>', page)
                self.assertIn('<a href="#needs-attention">Needs attention</a>', page)
                self.assertTrue({'fleet-overview', 'needs-attention'} <= set(parser.ids))
                self.assertTrue(all(link[1:] in parser.ids for link in parser.links))
        page = render_dashboard([snapshot(), snapshot(value='stopped', source='coordinator')], [HOST, OTHER], NOW)
        regions = re.findall(r'role="region" aria-label="([^"]+)"', page)
        self.assertGreater(len(regions), 2)
        self.assertEqual(len(regions), len(set(regions)))
        # Pages without the fleet overview must not carry dangling host links.
        self.assertNotIn('#fleet-overview', render_restart_unavailable())

    def test_absent_stale_blocked_conflicting_evidence_is_not_healthy(self):
        for data, now, expected in (
            ([], NOW, 'unknown · No report'),
            ([snapshot()], '2026-01-01T00:06:00Z', 'stale · running'),
            ([snapshot(state='blocked', value=None)], NOW, 'blocked · unknown'),
            ([snapshot(), snapshot(value='stopped')], NOW, 'unknown · conflicting observations'),
        ):
            with self.subTest(expected=expected):
                page = render_dashboard(data, [HOST], now)
                self.assertIn(expected, page)
                self.assertIn('Needs attention', page)
                self.assertNotIn('all healthy', page)
                self.assertIn('reported:', page) if data else None

    def test_production_output_contains_no_prototype_hosts_or_fake_repair_history(self):
        page = render_dashboard([], [HOST], NOW) + render_restart_unavailable()
        for text in ('71aa', 'e5c2', '9d40', 'b07d', '3f9a', '2026-10-30 14:02:30Z',
                     'Confirm repair', 'View audit', 'index.html', 'app.css'):
            self.assertNotIn(text, page)
        self.assertIn('Repairs disabled', page)
        self.assertIn('@media (prefers-color-scheme: light)', STYLE)
        self.assertIn('overflow-x: auto', STYLE)
        self.assertIn(':focus-visible', STYLE)
        self.assertNotIn('url(', STYLE)
        self.assertNotIn('@import', STYLE)

    def test_all_adverse_enum_reports_get_attention_without_health_inference(self):
        heartbeat = snapshot('heartbeat_age_seconds', 0, 'collector')
        for metric, values in ADVERSE_VALUES.items():
            for value in values:
                with self.subTest(metric=metric, value=value):
                    data = [heartbeat, snapshot(metric, value)]
                    page = render_dashboard(data, [HOST], NOW)
                    self.assertIn(metric + ': adverse reported value ' + value, page)
                    self.assertNotIn('No collector, correlation, stale, blocked, conflicting or adverse-report', page)
                    if metric in {'daemon_state', 'model_state', 'routing_eligible', 'attestation_state', 'memory_pressure'}:
                        self.assertIn('observed · <span class="adv">' + value + '</span>', page)
                    self.assertIn('Protocol confidence: <strong>unknown</strong>', page)
        zero = snapshot('requests_total', 0, 'daemon')
        page = render_dashboard([heartbeat, zero], [HOST], NOW)
        self.assertNotIn('requests_total: adverse', page)
        self.assertIn('Low or zero traffic alone is not a failure signal', page)

    def test_zero_hosts_is_an_explicit_empty_inventory(self):
        page = render_dashboard([], [], NOW)
        self.assertIn('0 hosts in expected inventory or supplied reports', page)
        self.assertIn('No expected hosts or reports supplied', page)
        self.assertIn('this is not a health verdict', page)


if __name__ == '__main__':
    unittest.main()
