"""Normalized evidence only; no raw logs, upstream API or repair execution."""
import copy
import unittest
from itertools import permutations

from gargoyl.dashboard import build_dashboard, render_dashboard
from gargoyl.telemetry import PolicyError

HOST = '00000000-0000-4000-8000-000000000001'
NOW = '2026-10-31T12:00:00Z'
LATER = '2026-10-31T12:00:10Z'


def sample(metric, value, source, *, at=NOW, state='observed', ttl=60):
    return dict(schema_version=1, host_id=HOST, collected_at=at,
                fields={metric: dict(value=value, source=source, timestamp=at,
                                     freshness_seconds=ttl, state=state, sensitivity='safe')})


def project(data, now=LATER):
    return build_dashboard(data, [HOST], now)['hosts'][0]


class DiagnosticConfidenceTests(unittest.TestCase):
    def test_running_eligible_and_reachable_do_not_prove_protocol_compatibility(self):
        data = [sample('daemon_state', 'running', 'daemon'),
                sample('routing_eligible', 'eligible', 'doctor'),
                sample('attestation_state', 'valid', 'daemon'),
                sample('coordinator_reachable', 'reachable', 'coordinator'),
                sample('routing_eligible', 'eligible', 'coordinator'),
                sample('error_code', 'none', 'coordinator')]
        host = project(data)
        self.assertEqual(host['diagnostics']['protocol_confidence'], 'unknown')
        self.assertEqual(host['diagnostics']['state'], 'unknown')
        page = render_dashboard(data, [HOST], LATER)
        local, coordinator = page.split('<h3>Local liveness and eligibility reports</h3>')[1].split(
            '<h3>Coordinator and protocol confidence</h3>')
        self.assertIn('<td>running</td><td>daemon</td>', local)
        self.assertIn('<td>eligible</td><td>doctor</td>', local)
        self.assertNotIn('<td>coordinator</td>', local)
        coordinator = coordinator.split('<h3>Model and memory evidence</h3>')[0]
        self.assertIn('<td>reachable</td><td>coordinator</td>', coordinator)
        self.assertIn('Protocol confidence: <strong>unknown</strong>', coordinator)
        self.assertIn('does not establish an error-free connection', coordinator)

    def test_repeated_coordinator_observations_warn_without_health_or_repair_verdict(self):
        data = [sample('heartbeat_age_seconds', 0, 'collector', at=LATER),
                sample('daemon_state', 'running', 'daemon'),
                sample('routing_eligible', 'eligible', 'doctor'),
                sample('error_code', 'invalid_state', 'coordinator'),
                sample('error_code', 'timeout', 'coordinator', at=LATER)]
        host = project(data)
        self.assertEqual(host['diagnostics'], dict(state='warning',
            observation_times=[NOW, LATER], codes=['invalid_state', 'timeout'],
            recurrence='repeated_observations', protocol_confidence='unknown', root_cause='unknown'))
        self.assertEqual(host['incidents'], [])
        self.assertEqual(host['latest']['daemon_state'][0]['value'], 'running')
        page = render_dashboard(data, [HOST], LATER)
        for text in ('Diagnostic warning: Repeated coordinator error observations',
                     'not a distinct error-event count or a restart trigger',
                     'Root cause and impact on routing remain unknown'):
            self.assertIn(text, page)
        for action in ('<form', '<button', '<input', 'onclick='):
            self.assertNotIn(action, page)

    def test_duplicate_polls_and_equivalent_timestamp_forms_do_not_establish_recurrence(self):
        first = sample('error_code', 'timeout', 'coordinator')
        duplicate = copy.deepcopy(first)
        duplicate['collected_at'] = LATER
        duplicate['fields']['error_code']['timestamp'] = '2026-10-31T12:00:00+00:00'
        for data in permutations([first, duplicate]):
            diagnostic = project(data)['diagnostics']
            self.assertEqual(diagnostic['state'], 'warning')
            self.assertEqual(diagnostic['recurrence'], 'unknown')
            self.assertEqual(diagnostic['observation_times'], [NOW])

    def test_conflicting_stale_blocked_future_and_missing_evidence_remain_unknown(self):
        errors = [sample('error_code', 'timeout', 'coordinator'),
                  sample('error_code', 'invalid_state', 'coordinator')]
        for data in permutations(errors):
            self.assertEqual(project(data)['diagnostics']['state'], 'unknown')
        for state in ('unknown', 'blocked', 'stale'):
            value = 'timeout' if state == 'stale' else None
            self.assertEqual(project([sample('error_code', value, 'coordinator', state=state)])
                             ['diagnostics']['state'], 'unknown')
        future = sample('error_code', 'timeout', 'coordinator', at='2026-10-31T12:00:11Z')
        self.assertEqual(project([future])['diagnostics']['state'], 'unknown')
        future_copy = sample('error_code', 'timeout', 'coordinator')
        future_copy['collected_at'] = '2026-10-31T12:00:11Z'
        self.assertEqual(project([errors[0], future_copy])['diagnostics']['state'], 'unknown')
        self.assertEqual(project([])['diagnostics']['state'], 'unknown')
        self.assertEqual(project([errors[0]], '2026-10-31T12:01:01Z')['diagnostics']['state'], 'unknown')

    def test_collection_and_doctor_errors_are_not_coordinator_errors(self):
        data = [sample('error_code', 'timeout', source, at=at)
                for source in ('collector', 'doctor') for at in (NOW, LATER)]
        self.assertEqual(project(data)['diagnostics']['state'], 'unknown')
        self.assertNotIn('Diagnostic warning:', render_dashboard(data, [HOST], LATER))

    def test_zero_or_low_traffic_never_creates_a_failure_or_root_cause(self):
        for requests in (0, 1):
            data = [sample('heartbeat_age_seconds', 0, 'collector', at=LATER),
                    sample('requests_total', requests, 'daemon'),
                    sample('tokens_total', 0, 'daemon')]
            host = project(data)
            self.assertEqual(host['incidents'], [])
            self.assertEqual(host['diagnostics']['root_cause'], 'unknown')
            page = render_dashboard(data, [HOST], LATER)
            self.assertIn('Low or zero traffic alone is not a failure signal', page)
            self.assertIn('No restart is inferred', page)
            self.assertIn('Collector liveness does not prove provider liveness', page)

    def test_model_and_memory_symptoms_do_not_supply_coordinator_diagnosis(self):
        data = [sample('model_state', 'failed', 'daemon'),
                sample('memory_pressure', 'critical', 'host'),
                sample('memory_headroom_bytes', 0, 'host')]
        self.assertEqual(project(data)['diagnostics']['state'], 'unknown')
        page = render_dashboard(data, [HOST], LATER)
        model = page.split('<h3>Model and memory evidence</h3>')[1].split('<h3>Local / coordinator')[0]
        self.assertIn('<td>failed</td><td>daemon</td>', model)
        self.assertIn('<td>critical</td><td>host</td>', model)
        self.assertIn('do not establish their cause', model)
        self.assertNotIn('Diagnostic warning:', page)

    def test_history_is_observations_not_event_count_or_claim_of_current_failure(self):
        data = [sample('error_code', 'timeout', 'coordinator'),
                sample('error_code', 'none', 'coordinator', at=LATER)]
        self.assertEqual(project(data)['diagnostics']['state'], 'warning')
        self.assertEqual(project(data)['diagnostics']['recurrence'], 'unknown')
        original = copy.deepcopy(data)
        projected = project(data)
        projected['diagnostics']['observation_times'].clear()
        self.assertEqual(data, original)
        self.assertEqual(project(data)['diagnostics']['observation_times'], [NOW])

    def test_unallowlisted_raw_error_text_is_rejected_before_diagnosis(self):
        for value in ('Failed to parse coordinator message', '<script>private</script>'):
            with self.assertRaises(PolicyError):
                render_dashboard([sample('error_code', value, 'coordinator')], [HOST], LATER)
