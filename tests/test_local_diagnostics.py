import copy
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from gargoyl.collector import collect
from gargoyl.collector_coordinator_log import (
    CoordinatorLogReader,
    _capture,
    parse_records,
    validate_log_report,
)
from gargoyl.collector_local_diagnostics import LocalDiagnostics
from gargoyl.monitor import LocalMonitor, render_log_report

NOW = '2026-10-31T16:00:00Z'
EPOCH = 1793462400
UID = os.getuid()
IMAGE = '/synthetic/provider'
IDENTITY = dict(pid=1234, born_us=(EPOCH-3600)*1000000, owner_uid=UID)


def record(**changes):
    value = dict(eventType='logEvent', subsystem='dev.darkbloom.provider', category='coordinator',
                 processID=1234, userID=UID, processImagePath='UNTRUSTED_PATH_DROPPED',
                 messageType='Error', timestamp='2026-10-31 15:59:30.000000+0000',
                 machTimestamp=1, threadID=2, traceID=3, eventMessage='<private>',
                 formatString='SECRET_DO_NOT_EXPORT', backtrace={'private': 'SECRET_DO_NOT_EXPORT'})
    value.update(changes)
    return value


def payload(records):
    return b'\n'.join(json.dumps(r).encode() for r in [*records, dict(finished=1, count=len(records))]) + b'\n'


class LogEvidenceTests(unittest.TestCase):
    def setUp(self):
        guard = patch('gargoyl.collector_coordinator_log._system_log_valid', return_value=True)
        guard.start()
        self.addCleanup(guard.stop)

    def parse(self, data):
        return parse_records(data, pid=1234, owner_uid=UID,
                             start='2026-10-31T15:55:00Z', end=NOW)

    def test_visible_record_counts_recency_redaction_and_duplicate_metadata(self):
        other = record(timestamp='2026-10-31 15:59:45.000000+0000', machTimestamp=2,
                       eventMessage='UNTRUSTED instructions and secrets must be discarded')
        result = self.parse(payload([record(), record(), other]))
        self.assertEqual(result, dict(count=2, redacted_count=1,
                                     latest_event_at='2026-10-31T15:59:45Z'))
        for sensitive in ('SECRET', 'UNTRUSTED', 'private', 'provider'):
            self.assertNotIn(sensitive, json.dumps(result))
        self.assertEqual(self.parse(payload([])), dict(count=0, redacted_count=0, latest_event_at=None))

    def test_duplicate_consumed_fields_are_validated_and_conflicts_are_order_independent(self):
        for records in ([record(), record(eventMessage=None)],
                        [record(), record(eventMessage='not redacted')],
                        [record(eventMessage='not redacted'), record()]):
            with self.assertRaises(ValueError):
                self.parse(payload(records))

    def test_scope_loss_time_unknown_schema_and_partial_output_refuse(self):
        cases = [dict(processID=1235), dict(userID=UID+1), dict(category='loop'),
                 dict(subsystem='other'), dict(eventType='lossEvent'), dict(messageType='Info'),
                 dict(timestamp='2026-10-31 16:00:01.000000+0000'),
                 dict(timestamp='2026-10-31 15:54:59.000000+0000'), dict(traceID='secret'),
                 dict(eventMessage=None)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(payload([record(**change)]))
        for data in (b'', b'{}', json.dumps(record()).encode(), payload([])+payload([]),
                     b'x'*65537, b'{"count":0,"count":1,"finished":1}'):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.parse(data)

    @patch('gargoyl.collector_coordinator_log._capture')
    def test_cached_query_keeps_original_time_rebinds_pid_and_never_retries_denial(self, capture):
        capture.return_value = payload([record()]), True
        reader = CoordinatorLogReader(executable=IMAGE, clock=lambda: NOW)
        first = reader.read(IDENTITY, lambda _: True, now=NOW, stop=threading.Event())
        self.assertEqual(first['state'], 'observed')
        self.assertEqual(reader.read(IDENTITY, lambda _: True, now=NOW, stop=threading.Event()), first)
        self.assertEqual(capture.call_count, 1)
        changed = dict(IDENTITY, born_us=IDENTITY['born_us']+1)
        capture.return_value = None, True  # OS query unavailable/denied, no raw error retained.
        self.assertEqual(reader.read(changed, lambda _: True, now=NOW, stop=threading.Event())['state'], 'unknown')
        reader._due = 0
        self.assertEqual(reader.read(changed, lambda _: True, now=NOW, stop=threading.Event())['state'], 'unknown')
        self.assertEqual(capture.call_count, 2)

    @patch('gargoyl.collector_coordinator_log._capture', side_effect=PermissionError('SECRET_DENIAL'))
    def test_permission_denial_is_fixed_and_never_retried(self, capture):
        reader = CoordinatorLogReader(executable=IMAGE, clock=lambda: NOW)
        for _ in range(2):
            result = reader.read(IDENTITY, lambda _: True, now=NOW, stop=threading.Event())
            self.assertEqual((result['state'], result['reason']), ('unknown', 'permission_denied'))
            self.assertNotIn('SECRET', json.dumps(result))
            reader._due = 0
        self.assertEqual(capture.call_count, 1)

    @patch('gargoyl.collector_coordinator_log._capture')
    def test_process_change_during_query_drops_results(self, capture):
        capture.return_value = payload([record()]), True
        states = iter([True, False])
        reader = CoordinatorLogReader(executable=IMAGE, clock=lambda: NOW)
        self.assertEqual(reader.read(IDENTITY, lambda _: next(states), now=NOW,
                                     stop=threading.Event())['state'], 'unknown')
        changed = dict(IDENTITY, born_us=IDENTITY['born_us']+1)
        self.assertEqual(reader.read(changed, lambda _: True, now=NOW, stop=threading.Event())['state'], 'observed')
        self.assertEqual(capture.call_count, 2)

    def test_real_owned_reader_child_is_bounded_for_output_and_timeout(self):
        for code in ("import sys,time;sys.stderr.write('x'*70000);sys.stderr.flush();time.sleep(10)",
                     "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(10)"):
            start = time.monotonic()
            data, clean = _capture([sys.executable, '-c', code], threading.Event())
            self.assertIsNone(data)
            self.assertTrue(clean)
            self.assertLess(time.monotonic()-start, 3.5)
        stop = threading.Event()
        stop.set()
        with patch('gargoyl.collector_coordinator_log.subprocess.Popen') as spawn:
            self.assertEqual(_capture([sys.executable], stop), (None, True))
            spawn.assert_not_called()

    @patch('gargoyl.collector_coordinator_log._capture')
    def test_incomplete_replaced_query_cannot_reuse_previous_success(self, capture):
        capture.return_value = payload([record()]), True
        reader = CoordinatorLogReader(executable=IMAGE, clock=lambda: NOW)
        self.assertEqual(reader.read(IDENTITY, lambda _: True, now=NOW,
                                     stop=threading.Event())['count'], 1)
        reader._due = 0
        capture.return_value = json.dumps(record()).encode(), True  # Missing completion marker.
        result = reader.read(IDENTITY, lambda _: True, now=NOW, stop=threading.Event())
        self.assertEqual((result['state'], result['count']), ('unknown', None))
        reader._due = 0
        reader.read(IDENTITY, lambda _: True, now=NOW, stop=threading.Event())
        self.assertEqual(capture.call_count, 2)

    def test_report_validation_and_staleness_prevent_stale_zero_health_or_html(self):
        report = dict(state='observed', reason='visible_records_only', observed_at=NOW,
                      freshness_seconds=45, window_start='2026-10-31T15:55:00Z', window_end=NOW,
                      count=0, redacted_count=0, latest_event_at=None)
        self.assertIn('not complete log coverage', render_log_report(report, NOW))
        stale = render_log_report(report, '2026-10-31T16:00:46Z')
        self.assertIn('stale', stale)
        self.assertNotIn('0 visible', stale)
        self.assertIn('Counts and recency are unknown', stale)
        for change in (dict(count='<script>secret</script>'), dict(extra='secret'),
                       dict(reason='SECRET'), dict(redacted_count=1)):
            with self.assertRaises(ValueError):
                validate_log_report(dict(report, **change))


class StructuredDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()/'state.json'
        self.data = dict(schema=1, pid=1234, version='0.10.5', written_at=EPOCH,
                         started_at=EPOCH-3600, inference_active=False, warm_models=['SECRET_MODEL'],
                         stats=dict(requests_served=1, tokens_generated=96),
                         process_identity=dict(pid=1234, start_time_micros=IDENTITY['born_us']),
                         coordinator_connection=dict(connected=True, since=EPOCH-120),
                         trust=dict(status='online', trust_level='hardware', received_at=EPOCH-5,
                                    authorization=dict(path='legacy', protocol=1,
                                    session_id='SECRET_SESSION', machine_id='SECRET_MACHINE')),
                         auth_token='SECRET_TOKEN_IGNORED')
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.data))

    def collector(self, verifier=lambda _: True, *, coordinator_errors=False):
        with patch('gargoyl.collector_local_diagnostics.MacOSProcessVerifier', return_value=verifier):
            return LocalDiagnostics(executable=IMAGE, owner_uid=UID, clock=lambda: NOW,
                                    coordinator_errors=coordinator_errors)

    def test_verified_process_and_structured_reports_have_independent_timestamps_and_sources(self):
        result = self.collector().collect(str(self.path), now=NOW)
        snapshot = collect('00000000-0000-4000-8000-000000000001', result.collected_at,
                           result.result.readings, errors=result.result.errors)
        fields = snapshot['fields']
        self.assertEqual((fields['daemon_state']['value'],fields['daemon_state']['source']), ('running','host'))
        self.assertEqual(fields['routing_eligible']['value'], 'eligible')
        self.assertEqual(fields['coordinator_reachable']['source'], 'daemon')
        self.assertEqual(fields['model_state']['value'], 'resident')
        self.assertNotEqual(fields['routing_eligible']['timestamp'], fields['daemon_state']['timestamp'])
        self.assertNotIn('SECRET', json.dumps(snapshot))
        self.assertNotIn('1234', json.dumps(snapshot))

    def test_supported_versions_reach_monitor_and_missing_source_does_not_cache_health(self):
        collector = self.collector()
        monitor = LocalMonitor(str(self.path), UID, '00000000-0000-4000-8000-000000000001',
                               clock=lambda: NOW, diagnostics=collector)
        for version in ('0.10.5', '0.10.6'):
            self.data['version'] = version
            self.write()
            self.assertEqual(monitor.tick()['fields']['daemon_state']['value'], 'running')
            page = monitor.render_page(NOW)
            self.assertIn('<td>running</td><td>host</td>', page)
            self.assertIn('Repairs disabled', page)
            self.assertIn('Protocol confidence: <strong>unknown</strong>', page)
            self.assertNotIn('SECRET', page)
        self.path.unlink()
        self.assertIsNone(monitor.tick()['fields']['daemon_state']['value'])
        self.assertNotIn('<td>running</td><td>host</td>', monitor.render_page(NOW))

    def test_stale_eligibility_is_not_refreshed_by_native_liveness_or_fresh_state(self):
        self.data['trust']['received_at'] = EPOCH-100
        self.write()
        result = self.collector().collect(str(self.path), now=NOW).result.readings
        self.assertEqual(result['routing_eligible']['state'], 'stale')
        self.assertEqual(result['daemon_state']['state'], 'observed')

    def test_missing_unsupported_or_mismatched_evidence_never_supplies_health(self):
        for change in ('identity', 'version', 'pid', 'query'):
            original = copy.deepcopy(self.data)
            if change == 'identity':
                self.data.pop('process_identity')
            if change == 'version':
                self.data['version'] = 'new-unsupported'
            if change == 'pid':
                self.data['process_identity']['pid'] = 9
            self.write()
            result = self.collector(lambda _: change != 'query').collect(str(self.path), now=NOW)
            self.assertNotIn('daemon_state', result.result.readings)
            self.assertNotIn('routing_eligible', result.result.readings)
            self.assertNotIn('model_state', result.result.readings)
            self.assertEqual(result.log_report['state'], 'unknown')
            self.data = original
        self.path.unlink()
        self.assertEqual(self.collector().collect(str(self.path), now=NOW).result.readings, {})

    def test_missing_bad_or_unsupported_eligibility_does_not_erase_liveness(self):
        for trust in (None, dict(status='online'),
                      dict(status='online', received_at=EPOCH-5,
                           authorization=dict(path='app_attest', expires_at=EPOCH+100))):
            self.data['trust'] = trust
            self.write()
            result = self.collector().collect(str(self.path), now=NOW).result.readings
            self.assertEqual(result['daemon_state']['value'], 'running')
            self.assertNotIn('routing_eligible', result)

    def test_prebirth_claims_are_withheld_without_erasing_independent_liveness(self):
        self.data['process_identity']['start_time_micros'] = (EPOCH-1)*1000000
        self.data['written_at'] = EPOCH-2
        self.write()
        readings = self.collector().collect(str(self.path), now=NOW).result.readings
        self.assertEqual(readings['daemon_state']['value'], 'running')
        self.assertEqual(readings['requests_total']['value'], 1)
        for metric in ('model_state', 'coordinator_reachable', 'routing_eligible'):
            self.assertNotIn(metric, readings)
        self.data['written_at'] = EPOCH
        self.write()
        readings = self.collector().collect(str(self.path), now=NOW).result.readings
        self.assertIn('model_state', readings)
        self.assertNotIn('coordinator_reachable', readings)  # Connection predates process.
        self.data['coordinator_connection']['since'] = EPOCH-0.5
        self.write()
        readings = self.collector().collect(str(self.path), now=NOW).result.readings
        self.assertIn('coordinator_reachable', readings)
        self.assertNotIn('routing_eligible', readings)  # Trust receipt predates process.

    def test_configured_stale_source_is_not_mislabeled_unconfigured(self):
        self.data['written_at'] = EPOCH-61
        self.data['trust']['received_at'] = EPOCH-100
        self.write()
        collector = self.collector(coordinator_errors=True)
        with patch.object(collector._logs, 'read') as query:
            result = collector.collect(str(self.path), now=NOW)
            self.assertEqual(result.log_report['reason'], 'source_stale')
            self.assertEqual(result.result.readings['daemon_state']['state'], 'observed')
            self.assertEqual(result.result.readings['model_state']['state'], 'stale')
            query.assert_not_called()

    def test_hold_or_lifecycle_drain_cannot_report_current_positive_eligibility(self):
        for field, value in (('addon_hold', {'holds': ['synthetic']}),
                             ('addon_hold', {'unknown': True}),
                             ('lifecycle', {'outcome': 'draining'}),
                             ('lifecycle', {'outcome': 'drained'})):
            self.data[field] = value
            self.write()
            readings = self.collector().collect(str(self.path), now=NOW).result.readings
            self.assertEqual(readings['daemon_state']['value'], 'running')
            self.assertEqual(readings['coordinator_reachable']['value'], 'reachable')
            self.assertNotIn('routing_eligible', readings)
            self.data.pop(field)

    def test_invalid_caller_source_is_rejected_before_any_read(self):
        collector = self.collector()
        with patch('gargoyl.collector_local_diagnostics._read') as read:
            for source in ('relative/file', '/source/../state.json', '/source//state.json'):
                with self.assertRaises(ValueError):
                    collector.collect(source, now=NOW)
            read.assert_not_called()

    def test_existing_source_permissions_symlinks_and_size_checks_still_apply(self):
        collector = self.collector()
        self.path.chmod(0o666)
        self.assertEqual(collector.collect(str(self.path), now=NOW).result.readings, {})
        self.path.unlink()
        self.path.symlink_to(self.path.parent/'missing')
        self.assertEqual(collector.collect(str(self.path), now=NOW).result.readings, {})
        self.path.unlink()
        self.path.write_bytes(b'x'*65537)
        self.assertEqual(collector.collect(str(self.path), now=NOW).result.readings, {})
