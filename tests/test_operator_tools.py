import http.client
import os
import re
import subprocess
import threading
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from operator_fixtures import HOST, NEW, OLD, FakeDarkbloom, verifier

from gargoyl.darkbloom_cli import (
    RunResult,
    classify_restart,
    parse_doctor,
    parse_version,
    restart_events,
    run_bounded,
)
from gargoyl.manual_restart import (
    ManualJournal,
    executable_stamp,
    observed_target,
    process_alive,
    process_start,
    read_operation,
    reconcile_operation,
)
from gargoyl.monitor import LocalMonitor, run_monitor
from gargoyl.operator_console import (
    ConsoleRestart,
    OperatorTools,
    Refused,
    inspect_executable,
)
from gargoyl.telemetry import PolicyError

RESTART = 'restart --timeout 600 --startup-timeout 180'


class CliParsingTests(unittest.TestCase):
    def test_version_and_doctor_parsing_fail_closed(self):
        self.assertEqual(parse_version(RunResult(0, b'0.10.6\n', None, True)), '0.10.6')
        for result in (RunResult(1, b'0.10.6\n', None, True), RunResult(0, b'Darkbloom 0.10.6\n', None, True),
                       RunResult(None, b'0.10.6\n', 'timeout', True)):
            self.assertIsNone(parse_version(result))
        doctor = b'DIAGNOSIS\n\nDETAILED CHECKS\n  [PASS] a: x\n  [WARN] b: y\n  [FAIL] c: z\n\n'
        self.assertEqual(parse_doctor(RunResult(1, doctor, None, True)),
                         {'passed': 1, 'warnings': 1, 'failed': 1, 'info': 0, 'exit': 1})
        # A failed check with a success exit status (or the reverse) is inconsistent, not a pass.
        self.assertIsNone(parse_doctor(RunResult(0, doctor, None, True)))
        self.assertIsNone(parse_doctor(RunResult(0, b'Darkbloom Doctor\nResult: 8/8\n', None, True)))
        self.assertIsNone(parse_doctor(RunResult(1, b'DETAILED CHECKS\n  garbage\n', None, True)))

    def test_restart_classification_uses_only_recognised_darkbloom_messages(self):
        def classify(text, code):
            return classify_restart(restart_events(text.encode())[0], code)
        relaunch = 'Drained provider relaunched; waiting for fresh authorization...\n'
        authorized = 'Provider restarted and freshly authorized (legacy).\n'
        self.assertEqual(classify(relaunch + authorized, 0), 'cli_confirmed')
        self.assertEqual(classify(relaunch + authorized, None), 'relaunched_unconfirmed')
        self.assertEqual(classify(relaunch, 64), 'relaunched_unconfirmed')
        self.assertEqual(classify(authorized, 0), 'unknown')  # success line without a relaunch
        self.assertEqual(classify('Error: Drain did not complete: 2 unfinished\n', 64), 'not_restarted_attention')
        self.assertEqual(classify('Error: Cannot confirm the running provider identity. No process or recovery '
                                  'setting was changed.\n', 64), 'refused_no_change')
        self.assertEqual(classify('Forced stop: drain acknowledgement unavailable\n' + relaunch + authorized, 0),
                         'forced_anomaly')
        self.assertEqual(classify('', 0), 'unknown')
        # Darkbloom's notInstalled catch also covers the post-drain stop: not "no change".
        self.assertEqual(classify('Draining accepted requests (deadline: 600s). New work is refused by the '
                                  'running provider.\nProvider is not running. Start it with `darkbloom start`.\n', 1),
                         'not_restarted_attention')
        events, unknown = restart_events(b'private text\n  3 accepted request(s) remaining\n')
        self.assertEqual((events, unknown), ([('remaining', 3)], 1))


class BoundedRunTests(unittest.TestCase):
    def test_exit_status_timeout_and_output_limit(self):
        fake = FakeDarkbloom()
        self.addCleanup(fake.cleanup)
        environment = fake.environment()
        result = run_bounded((fake.executable, 'doctor'), environment=environment, cwd=environment['HOME'],
                             timeout_seconds=10)
        self.assertEqual((result.returncode, result.error, result.cleanup_complete), (0, None, True))
        fake.configure(restart='success', delay=5)
        slow = run_bounded((fake.executable, 'restart'), environment=environment, cwd=environment['HOME'],
                           timeout_seconds=1.5, grace_seconds=0.5)
        self.assertEqual((slow.returncode, slow.error), (None, 'timeout'))
        self.assertTrue(slow.cleanup_complete)
        with self.assertRaises(PolicyError):
            run_bounded([fake.executable], environment=environment, cwd='/', timeout_seconds=1)


class Base(unittest.TestCase):
    """Real manual_restart journal, run_restart, invoke_restart and observed_target against the
    fake darkbloom; only the pilot-host preflight and the macOS kernel check are substituted."""

    def setUp(self):
        self.fake = FakeDarkbloom()
        self.addCleanup(self.fake.cleanup)
        self.directory = str(Path(self.fake.record_dir) / 'journal')
        self.restart = self.console()

    def console(self, *, kernel=None):
        check = kernel or verifier(OLD, NEW)

        def observe():
            return observed_target(self.fake.state, self.fake.executable, os.getuid(), verifier=check)

        def preflight():
            return observe(), executable_stamp(self.fake.executable)

        def inspect(stamp):
            if executable_stamp(self.fake.executable) != stamp:
                raise ValueError('installation changed')
            return observe()
        return ConsoleRestart(executable=self.fake.executable, directory=self.directory,
                              preflight=preflight, inspect=inspect, observe=observe)

    def finish(self, restart=None, timeout=30):
        restart = restart or self.restart
        deadline = time.time() + timeout
        time.sleep(0.2)
        while restart.live()['active'] and time.time() < deadline:
            time.sleep(0.1)
        self.assertFalse(restart.live()['active'])

    def start(self, restart=None):
        restart = restart or self.restart
        target, problem = restart.target()
        self.assertIsNone(problem)
        restart.start(now=None, confirmed_token=target['token'])
        return target


class ConsoleRestartTests(Base):
    def test_verified_success_records_child_and_discards_output(self):
        self.start()
        self.finish()
        record = read_operation(self.directory)
        self.assertEqual(record['state'], 'completed')
        self.assertEqual(record['replacement']['process']['pid'], NEW['pid'])
        self.assertIn('child', record)
        self.assertEqual(self.restart.gate(), (True, None))
        self.assertEqual(self.fake.calls(), [RESTART])
        self.assertEqual(sorted(os.listdir(self.directory)), ['lock', 'operation.json'])
        self.assertEqual(self.restart.live()['outcome'], 'cli_confirmed')

    def test_uncertain_outcomes_block_both_surfaces_until_read_only_reconcile(self):
        for kind, outcome, observation in (
                ('drain_incomplete', 'not_restarted_attention', 'original_process_observed'),
                ('unconfirmed', 'relaunched_unconfirmed', 'original_process_observed'),
                ('refused', 'refused_no_change', 'original_process_observed'),
                ('success_no_change', 'cli_confirmed', 'original_process_observed')):
            with self.subTest(kind=kind):
                self.fake.write_state(OLD)
                self.fake.configure(restart=kind)
                (self.fake.bin / 'calls.log').unlink(missing_ok=True)
                self.start()
                self.finish()
                self.assertEqual(read_operation(self.directory)['state'], 'unknown')
                self.assertEqual(self.restart.live()['outcome'], outcome)
                self.assertFalse(self.restart.gate()[0])
                with self.assertRaises(Refused):
                    self.restart.start(now=None, confirmed_token=self.restart.target()[0]['token'])
                time.sleep(0.3)
                self.assertEqual(self.fake.calls(), [RESTART])  # never retried
                self.restart.reconcile(now=None)
                record = read_operation(self.directory)
                self.assertEqual((record['state'], record['observation']), ('reconciled', observation))
                self.assertEqual(self.restart.gate(), (True, None))
                with self.assertRaises(Refused):
                    self.restart.reconcile(now=None)

    def test_kernel_rejected_replacement_is_not_verified(self):
        restart = self.console(kernel=verifier(OLD))
        self.start(restart)
        self.finish(restart)
        self.assertEqual(read_operation(self.directory)['state'], 'unknown')

    def test_changed_target_and_cli_lock_refuse_without_a_record(self):
        target = self.restart.target()[0]
        self.fake.write_state(NEW)
        with self.assertRaises(Refused):
            self.restart.start(now=None, confirmed_token=target['token'])
        with ManualJournal(self.directory):  # e.g. `gargoyl tools restart` running in a terminal
            target = self.restart.target()[0]
            with self.assertRaises(Refused) as caught:
                self.restart.start(now=None, confirmed_token=target['token'])
            self.assertIn('holds the restart lock', str(caught.exception))
        self.assertIsNone(read_operation(self.directory))
        self.assertEqual(self.fake.calls(), [])

    def test_concurrent_and_double_start_are_refused(self):
        self.fake.configure(restart='success', drain_delay=1.5)
        token = self.start()['token']
        with self.assertRaises(Refused):
            self.restart.start(now=None, confirmed_token=token)
        with self.assertRaises(Refused):
            self.restart.reconcile(now=None)
        deadline = time.time() + 5
        while self.restart.live()['phase'][0] != 'draining' and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.restart.live()['phase'], ('draining', 2))  # live progress from Darkbloom output
        self.finish()
        self.assertEqual(self.fake.calls(), [RESTART])

    def test_reconcile_refuses_while_recorded_child_is_alive(self):
        child = subprocess.Popen(['sleep', '30'])
        self.addCleanup(child.kill)
        with ManualJournal(self.directory) as journal:
            journal.write(dict(schema=1, operation_id='a' * 32, state='intent', started_at='2026-11-01T00:00:00Z',
                               reason='invocation_not_confirmed',
                               target=observed_target(self.fake.state, self.fake.executable, os.getuid(),
                                                      verifier=verifier(OLD)),
                               child=dict(pid=child.pid, born_us=process_start(child.pid))))
        self.assertFalse(self.restart.gate()[0])
        with self.assertRaises(Refused) as caught:
            self.restart.reconcile(now=None)
        self.assertIn('still running', str(caught.exception))
        child.kill()
        child.wait()
        self.restart.reconcile(now=None)
        self.assertEqual(read_operation(self.directory)['state'], 'reconciled')

    def test_unrecorded_or_unreadable_child_keeps_reconcile_closed(self):
        child = subprocess.Popen(['sleep', '30'])
        self.addCleanup(child.kill)
        self.assertTrue(process_alive({'pid': child.pid, 'born_us': None}))  # start time unreadable
        child.kill()
        child.wait()
        self.assertFalse(process_alive({'pid': child.pid, 'born_us': None}))
        target = observed_target(self.fake.state, self.fake.executable, os.getuid(), verifier=verifier(OLD))
        with ManualJournal(self.directory) as journal:  # crash between spawn and recording the child
            journal.write(dict(schema=1, operation_id='b' * 32, state='intent', reason='invocation_not_confirmed',
                               started_at=datetime.now(timezone.utc).isoformat(), target=target))
            with self.assertRaises(ValueError):
                reconcile_operation(journal, inspect_target=lambda: target)
            later = (datetime.now(timezone.utc) + timedelta(seconds=901)).isoformat()
            self.assertEqual(reconcile_operation(journal, inspect_target=lambda: target,
                                                 clock=lambda: later)['state'], 'reconciled')
        with self.assertRaises(Refused):
            self.restart.reconcile(now=None)  # nothing unresolved now

    def test_live_outcome_is_bound_to_its_operation(self):
        self.fake.configure(restart='drain_incomplete')
        self.start()
        self.finish()
        record = read_operation(self.directory)
        self.assertEqual(self.restart.live(record)['outcome'], 'not_restarted_attention')
        other = dict(record, operation_id='c' * 32)  # e.g. a later CLI operation
        self.assertIsNone(self.restart.live(other)['outcome'])

    def test_cli_restart_records_its_child_too(self):
        source = Path(__file__).resolve().parent.parent / 'gargoyl' / 'operator_tools.py'
        text = source.read_text()
        self.assertIn('invoke_with_child=True', text)
        self.assertIn('started=record_child', text)

    def test_unsafe_record_blocks_restart(self):
        self.start()
        self.finish()
        os.chmod(os.path.join(self.directory, 'operation.json'), 0o644)
        opened, reason = self.restart.gate()
        self.assertFalse(opened)
        self.assertIn('unsafe', reason)


class ConsoleHttpTests(Base):
    def setUp(self):
        super().setUp()
        self.monitor = LocalMonitor(self.fake.state, os.getuid(), HOST, interval=1)
        info = inspect_executable(self.fake.executable, self.fake.environment())
        self.assertEqual(info['version'], '0.10.6')
        self.tools = OperatorTools(self.monitor, executable=self.fake.executable, executable_info=info,
                                   environment=self.fake.environment(), restart=self.restart)
        self.stop = threading.Event()
        ready = threading.Event()
        self.port = None

        def started(port):
            self.port = port
            ready.set()
        self.thread = threading.Thread(target=run_monitor, args=(self.monitor,),
                                       kwargs=dict(port=0, stop=self.stop, ready=started, tools=self.tools))
        self.thread.start()
        self.assertTrue(ready.wait(10))
        self.addCleanup(self.thread.join)
        self.addCleanup(self.stop.set)

    def request(self, method, path, *, body=None, origin=True, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        sent = {'Host': f'127.0.0.1:{self.port}'}
        if origin:
            sent['Origin'] = f'http://127.0.0.1:{self.port}'
        if body is not None:
            body = urllib.parse.urlencode(body)
            sent['Content-Type'] = 'application/x-www-form-urlencoded'
        sent.update(headers or {})
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        data = response.read().decode()
        connection.close()
        return response.status, response.getheader('Location'), data

    def nonce(self, page, action):
        match = re.search(r'action="[^"]*' + re.escape(action) + r'"[^>]*>.*?name="nonce" value="([^"]+)"', page, re.S)
        self.assertIsNotNone(match, action)
        return match.group(1)

    def test_public_page_has_no_token_or_actions_and_private_area_requires_token(self):
        status, _, page = self.request('GET', '/', origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn(self.tools.token, page)
        self.assertNotIn('<form', page)
        self.assertIn('private link printed', page)
        self.assertEqual(self.request('GET', '/s/' + 'x' * 43 + '/tools', origin=False)[0], 404)
        status, _, page = self.request('GET', self.tools.base + '/tools', origin=False)
        self.assertEqual(status, 200)
        for name in ('Refresh diagnostics now', 'Doctor checks', 'Export redacted diagnostics', '/report.json',
                     'Coordinator protocol compatibility', 'Forced restart', 'Local details'):
            self.assertIn(name, page)
        csp, referrer = self.tools_headers()
        self.assertIn("form-action 'self'", csp)
        # Under no-referrer, browsers send `Origin: null` on same-origin POSTs, which the
        # exact-Origin guard rejects; found in real-browser QA.
        self.assertEqual(referrer, 'same-origin')

    def tools_headers(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        connection.request('GET', self.tools.base + '/tools', headers={'Host': f'127.0.0.1:{self.port}'})
        response = connection.getresponse()
        response.read()
        connection.close()
        return response.getheader('Content-Security-Policy'), response.getheader('Referrer-Policy')

    def test_post_guards_reject_cross_origin_missing_origin_type_and_size(self):
        path = self.tools.base + '/tools/run'
        _, _, page = self.request('GET', self.tools.base + '/tools', origin=False)
        nonce = self.nonce(page, '/tools/run')
        form = {'nonce': nonce, 'tool': 'version'}
        self.assertEqual(self.request('POST', path, body=form, origin=False)[0], 403)
        self.assertEqual(self.request('POST', path, body=form, headers={'Origin': 'http://evil.test'})[0], 403)
        self.assertEqual(self.request('POST', path, body=form, headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(self.request('POST', path, body=form, headers={'Content-Type': 'text/plain'})[0], 415)
        self.assertEqual(self.request('POST', path, body={'nonce': 'x' * 3000})[0], 413)
        self.assertEqual(self.request('POST', '/s/' + 'y' * 43 + '/tools/run', body=form)[0], 404)
        self.assertEqual(self.request('POST', '/', body=form)[0], 404)
        self.assertEqual(self.fake.calls()[-1:], ['--version'])  # only the startup inspection ran

    def test_tools_run_once_per_nonce_and_report_normalized_results(self):
        for tool, text in (('version', 'Darkbloom 0.10.6'), ('status', 'daemon running'),
                           ('doctor', '1 passed, 1 warnings, no failed checks')):
            _, _, page = self.request('GET', self.tools.base + '/tools', origin=False)
            nonce = self.nonce(page, '/tools/run')
            status, location, _ = self.request('POST', self.tools.base + '/tools/run', body={'nonce': nonce, 'tool': tool})
            self.assertEqual((status, location), (303, self.tools.base + '/tools'))
            self.request('POST', self.tools.base + '/tools/run', body={'nonce': nonce, 'tool': tool})  # replay
            deadline = time.time() + 15
            while time.time() < deadline and tool not in self.tools.results()[0]:
                time.sleep(0.1)
            self.assertIn(text, self.tools.results()[0][tool]['summary'])
        calls = self.fake.calls()
        self.assertEqual((calls.count('status'), calls.count('doctor')), (1, 1))
        _, _, page = self.request('GET', self.tools.base + '/tools', origin=False)
        for private in ('private-model-name', '/Users/private', 'private-provider-name', 'SECRET-DIAGNOSIS'):
            self.assertNotIn(private, page)

    def test_restart_confirmation_double_submit_and_reconcile_over_http(self):
        status, _, page = self.request('GET', self.tools.base + '/restart', origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn('http-equiv="refresh"', page)
        for text in ('New work is refused', 'restart --timeout 600 --startup-timeout 180',
                     'Not guaranteed: exactly-once', f'PID {OLD["pid"]}', 'gargoyl tools restart'):
            self.assertIn(text, page)
        nonce = self.nonce(page, '/restart')
        token = re.search(r'name="target" value="([^"]+)"', page).group(1)
        status, _, page = self.request('POST', self.tools.base + '/restart',
                                       body={'nonce': nonce, 'target': token, 'confirm': 'wrong'})
        self.assertIn('did not match. Nothing was run.', page)
        self.assertEqual(self.fake.calls().count('restart --timeout 600 --startup-timeout 180'), 0)
        _, _, page = self.request('GET', self.tools.base + '/restart', origin=False)
        nonce = self.nonce(page, '/restart')
        form = {'nonce': nonce, 'target': token, 'confirm': HOST[:8]}
        first = self.request('POST', self.tools.base + '/restart', body=form)
        second = self.request('POST', self.tools.base + '/restart', body=form)  # double click
        self.assertEqual((first[0], first[1]), (303, self.tools.base + '/restart/status'))
        self.assertEqual((second[0], second[1]), (303, self.tools.base + '/restart/status?form=used'))
        self.finish()
        self.assertEqual(read_operation(self.directory)['state'], 'completed')
        self.assertEqual(self.fake.calls().count('restart --timeout 600 --startup-timeout 180'), 1)
        status, _, page = self.request('GET', self.tools.base + '/restart/status', origin=False)
        self.assertIn('Verified restart', page)
        status, _, page = self.request('GET', self.tools.base + '/restart/status?form=used', origin=False)
        self.assertIn('did not start anything new', page)

    def test_reconcile_over_http_requires_typed_confirmation_and_public_headers_stay_strict(self):
        self.fake.configure(restart='drain_incomplete')
        self.start()
        self.finish()
        _, _, page = self.request('GET', self.tools.base + '/restart/status', origin=False)
        self.assertIn('Unresolved', page)
        nonce = self.nonce(page, '/restart/reconcile')
        _, _, page = self.request('POST', self.tools.base + '/restart/reconcile', body={'nonce': nonce, 'confirm': 'nope'})
        self.assertIn('Nothing was recorded', page)
        self.assertEqual(read_operation(self.directory)['state'], 'unknown')
        nonce = self.nonce(page, '/restart/reconcile')
        status, location, _ = self.request('POST', self.tools.base + '/restart/reconcile',
                                           body={'nonce': nonce, 'confirm': HOST[:8]})
        self.assertEqual(status, 303)
        self.assertEqual(read_operation(self.directory)['state'], 'reconciled')
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        connection.request('GET', '/', headers={'Host': f'127.0.0.1:{self.port}'})
        response = connection.getresponse()
        response.read()
        connection.close()
        self.assertEqual(response.getheader('Referrer-Policy'), 'no-referrer')
        self.assertIn("form-action 'none'", response.getheader('Content-Security-Policy'))


if __name__ == '__main__':
    unittest.main()
