import http.client
import json
import os
import re
import stat
import threading
import time
import unittest
import urllib.parse
from datetime import datetime, timezone
from unittest import mock

from operator_fixtures import HOST, NEW, OLD, FakeDarkbloom, verifier

from gargoyl.darkbloom_cli import (
    SUPPORTED_VERSIONS,
    RunResult,
    classify_restart,
    executable_digest,
    executable_file,
    parse_doctor,
    parse_version,
    restart_events,
    run_bounded,
)
from gargoyl.monitor import LocalMonitor, run_monitor
from gargoyl.operator_console import OperatorTools, inspect_executable
from gargoyl.restart_attempts import AttemptStore, Refused, RestartController
from gargoyl.telemetry import PolicyError


def now():
    return datetime.now(timezone.utc).isoformat()


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
    def setUp(self):
        self.fake = FakeDarkbloom()
        self.addCleanup(self.fake.cleanup)
        # Treat the fake as the recorded 0.10.6 build so restart is offered.
        patcher = mock.patch.dict(SUPPORTED_VERSIONS, {'0.10.6': executable_digest(self.fake.executable)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.info = {'version': '0.10.6', 'digest': SUPPORTED_VERSIONS['0.10.6'], 'recognised_build': True,
                     'file': executable_file(self.fake.executable)}

    def controller(self, *, verify=None, info=None, store=None):
        store = store or AttemptStore(str(self.fake.record_dir), os.getuid())
        self.stores.append(store)
        return RestartController(host=HOST, executable=self.fake.executable, executable_info=info or self.info,
                                 owner_uid=os.getuid(), source=self.fake.state, store=store,
                                 provider_verifier=verify if verify is not None else verifier(OLD, NEW),
                                 environment=self.fake.environment())

    def run(self, result=None):
        self.stores = []
        try:
            return super().run(result)
        finally:
            for store in self.stores:
                try:
                    store.close()
                except OSError:
                    pass

    def finish(self, controller):
        controller.wait(30)
        return controller.snapshot()['current']


class RestartControllerTests(Base):
    def test_verified_success_reopens_gate_and_discards_raw_output(self):
        controller = self.controller()
        target, reason = controller.target(now())
        self.assertIsNone(reason)
        self.assertEqual((target['pid'], target['kernel_verified']), (OLD['pid'], True))
        attempt = controller.start(now=now(), confirmed_token=target['token'])
        current = self.finish(controller)
        self.assertEqual((current['attempt_id'], current['outcome'], current['verified']),
                         (attempt, 'cli_confirmed', True))
        self.assertIn('new process', current['verification'])
        self.assertEqual(controller.gate(), (True, None))
        self.assertEqual(self.fake.calls(), ['restart --timeout 600 --startup-timeout 180'])
        self.assertEqual(sorted(os.listdir(self.fake.record_dir)), ['lock', 'restart.json'])
        mode = os.stat(self.fake.record_dir / 'restart.json').st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_cli_success_without_a_new_process_is_not_verified(self):
        self.fake.configure(restart='success_no_change')
        controller = self.controller()
        controller.start(now=now(), confirmed_token=controller.target(now())[0]['token'])
        current = self.finish(controller)
        self.assertEqual((current['outcome'], current['verified']), ('cli_confirmed', False))
        self.assertIn('still names the original process', current['verification'])
        self.assertFalse(controller.gate()[0])

    def test_kernel_rejection_of_new_process_blocks_verification(self):
        controller = self.controller(verify=verifier(OLD))
        controller.start(now=now(), confirmed_token=controller.target(now())[0]['token'])
        current = self.finish(controller)
        self.assertEqual((current['outcome'], current['verified']), ('cli_confirmed', False))
        self.assertIn('kernel does not confirm', current['verification'])
        self.assertFalse(controller.gate()[0])

    def test_every_uncertain_outcome_blocks_until_reconciled_and_never_retries(self):
        for kind, outcome in (('drain_incomplete', 'not_restarted_attention'),
                              ('unconfirmed', 'relaunched_unconfirmed'),
                              ('refused', 'refused_no_change'), ('forced', 'forced_anomaly')):
            with self.subTest(kind=kind):
                self.fake.write_state(OLD)
                self.fake.configure(restart=kind)
                for store in self.stores:
                    store.close()
                self.stores.clear()
                (self.fake.bin / 'calls.log').unlink(missing_ok=True)
                (self.fake.record_dir / 'restart.json').unlink(missing_ok=True)
                controller = self.controller()
                controller.start(now=now(), confirmed_token=controller.target(now())[0]['token'])
                current = self.finish(controller)
                self.assertEqual((current['outcome'], current['verified']), (outcome, False))
                opened, reason = controller.gate()
                self.assertFalse(opened)
                with self.assertRaises(Refused):
                    controller.start(now=now(), confirmed_token=controller.target(now())[0]['token'])
                time.sleep(0.3)
                self.assertEqual(len(self.fake.calls()), 1)  # no retry, no second launch
                note = controller.reconcile(now=now())
                self.assertIn('does not prove', note)
                self.assertEqual(controller.gate(), (True, None))
                with self.assertRaises(Refused):
                    controller.reconcile(now=now())

    def test_changed_target_unsupported_version_and_stale_state_refuse_before_claim(self):
        controller = self.controller()
        token = controller.target(now())[0]['token']
        self.fake.write_state(NEW)
        with self.assertRaises(Refused):
            controller.start(now=now(), confirmed_token=token)
        self.fake.write_state(OLD, age=120)
        self.assertIsNone(controller.target(now())[0])
        self.fake.write_state(OLD, version='0.10.4')
        self.assertIsNone(controller.target(now())[0])
        self.assertIsNone(controller.snapshot()['current'])
        self.assertEqual(self.fake.calls(), [])
        self.fake.write_state(OLD)
        for info, text in (({'version': '0.11.0'}, 'unsupported'),
                           (dict(self.info, recognised_build=False), 'not a recorded'),
                           (dict(self.info, file=[0, 0, 0, 0]), 'changed after this monitor inspected it')):
            controller.info = info
            target, reason = controller.target(now())
            self.assertIsNone(target)
            self.assertIn(text, reason)

    def test_concurrent_start_is_refused_while_running(self):
        self.fake.configure(restart='success', drain_delay=1.5)
        controller = self.controller()
        token = controller.target(now())[0]['token']
        controller.start(now=now(), confirmed_token=token)
        with self.assertRaises(Refused):
            controller.start(now=now(), confirmed_token=token)
        with self.assertRaises(Refused):
            controller.reconcile(now=now())
        self.assertEqual(self.finish(controller)['verified'], True)
        self.assertEqual(len(self.fake.calls()), 1)

    def test_monitor_restart_mid_attempt_watches_detached_child_and_reports_unknown(self):
        self.fake.configure(restart='success', drain_delay=1.5)
        first = self.controller()
        first.start(now=now(), confirmed_token=first.target(now())[0]['token'])
        first.close()  # simulate the monitor process ending; its child keeps running
        first.store.close()
        self.stores.remove(first.store)
        second = self.controller()
        current = second.snapshot()['current']
        self.assertEqual(current['phase'], 'running')
        self.assertFalse(second.gate()[0])
        with self.assertRaises(Refused):
            second.reconcile(now=now())
        current = self.finish(second)
        self.assertEqual((current['outcome'], current['verified'], current['note']),
                         ('relaunched_unconfirmed', False, 'interrupted'))
        self.assertFalse(second.gate()[0])
        second.reconcile(now=now())
        self.assertTrue(second.gate()[0])
        self.assertEqual(len(self.fake.calls()), 1)

    def test_claim_without_recorded_child_recovers_as_unknown(self):
        store = AttemptStore(str(self.fake.record_dir), os.getuid())
        store.save({'schema': 1, 'host': HOST, 'history': [], 'current': {
            'attempt_id': 'a' * 32, 'phase': 'claimed', 'claimed_at': now(), 'child': None,
            'target': {'pid': OLD['pid'], 'born_us': OLD['born_us']}}})
        controller = self.controller(store=store)
        current = controller.snapshot()['current']
        self.assertEqual((current['phase'], current['outcome'], current['verified']), ('finished', 'unknown', False))
        self.assertIn('before the restart command was recorded', current['verification'])
        self.assertFalse(controller.gate()[0])

    def test_store_requires_private_directory_and_exclusive_lock(self):
        store = AttemptStore(str(self.fake.record_dir), os.getuid())
        self.stores.append(store)
        with self.assertRaises(PolicyError):
            AttemptStore(str(self.fake.record_dir), os.getuid())
        os.chmod(self.fake.record_dir, 0o755)
        try:
            with self.assertRaises(PolicyError):
                AttemptStore(str(self.fake.record_dir), os.getuid())
        finally:
            os.chmod(self.fake.record_dir, 0o700)
        store.save({'schema': 1, 'host': HOST, 'current': None, 'history': []})
        os.chmod(self.fake.record_dir / 'restart.json', 0o644)
        with self.assertRaises(PolicyError):
            store.load()


class ConsoleHttpTests(Base):
    def setUp(self):
        super().setUp()
        self.monitor = LocalMonitor(self.fake.state, os.getuid(), HOST, interval=1)
        info = inspect_executable(self.fake.executable, self.fake.environment())
        self.assertEqual(info['version'], '0.10.6')
        self.controller_ = self.controller()
        self.tools = OperatorTools(self.monitor, executable=self.fake.executable, executable_info=info,
                                   environment=self.fake.environment(), restart=self.controller_)
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
        for name in ('Refresh diagnostics now', 'Doctor checks', 'Export redacted diagnostics',
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

    def test_export_is_redacted_json(self):
        status, _, body = self.request('GET', self.tools.base + '/export.json', origin=False)
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual((payload['schema'], payload['host']), (1, HOST))
        for private in (self.fake.executable, self.fake.state, self.tools.token):
            self.assertNotIn(private, body)

    def test_restart_confirmation_double_submit_and_reconcile_over_http(self):
        status, _, page = self.request('GET', self.tools.base + '/restart', origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn('http-equiv="refresh"', page)
        for text in ('New work is refused', 'restart --timeout 600 --startup-timeout 180',
                     'Not guaranteed: exactly-once', f'PID {OLD["pid"]}'):
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
        self.assertEqual((second[0], second[1]), (303, self.tools.base + '/restart/status'))
        current = self.finish(self.controller_)
        self.assertTrue(current['verified'])
        self.assertEqual(self.fake.calls().count('restart --timeout 600 --startup-timeout 180'), 1)
        status, _, page = self.request('GET', self.tools.base + '/restart/status', origin=False)
        self.assertIn('Verified restart', page)


if __name__ == '__main__':
    unittest.main()
