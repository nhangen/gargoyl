import contextlib
import errno
import gc
import http.client
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from gargoyl.cli import main
from gargoyl.monitor import LocalMonitor, MonitorViewer, run_monitor, status

HOST = '00000000-0000-4000-8000-000000000001'
NOW = '2026-10-30T12:00:00Z'
EPOCH = datetime.fromisoformat(NOW.replace('Z', '+00:00')).timestamp()


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.path = self.directory / 'state.json'
        self.write()
        self.monitor = LocalMonitor(str(self.path), os.getuid(), HOST, interval=1, clock=lambda: NOW)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, requests=7, epoch=EPOCH):
        data = dict(schema=1, pid=123, version='fixture', written_at=epoch,
                    started_at=epoch-100, inference_active=False, warm_models=[],
                    stats=dict(requests_served=requests, tokens_generated=42),
                    secret='MUST_NEVER_APPEAR')
        new = self.directory / 'replacement'
        new.write_text(json.dumps(data))
        new.replace(self.path)

    def test_updates_bounded_history_and_current_failure_recovers(self):
        for i in range(70):
            self.write(i)
            self.monitor.tick()
        page = self.monitor.render_page(NOW)
        self.assertIn('70 completed polls', page)
        self.assertNotIn('MUST_NEVER_APPEAR', page)
        self.assertEqual(len(self.monitor._history), 64)
        self.path.unlink()
        failed = self.monitor.tick()
        self.assertIsNone(failed['fields']['requests_total']['value'])
        self.assertEqual(self.monitor.snapshots(now=NOW), [failed])
        self.assertIn('unavailable', self.monitor.render_page(NOW))
        self.path.write_text('{malformed')
        self.assertEqual(self.monitor.tick()['fields']['error_code']['value'], 'invalid_state')
        self.write(99)
        self.assertEqual(self.monitor.tick()['fields']['requests_total']['value'], 99)
        self.assertEqual(self.monitor.tick()['fields']['error_code']['value'], 'none')

    def test_repair_explanations_ignore_telemetry_authorization_claims(self):
        # Daemon 0.10.5 lifecycle fields are unsigned local observations, not
        # v2 target/drain/replay authority. Even apparently healthy/drained
        # source content must not expose a repair action.
        data = json.loads(self.path.read_text())
        data.update(process_identity=dict(pid=123, start_time_micros=1),
                    lifecycle=dict(request_id="fixture", outcome="drained",
                                   remaining=0, coordinator_acknowledged=True),
                    repair_available=True)
        self.path.write_text(json.dumps(data))
        for state in ("fresh", "stale", "missing"):
            with self.subTest(state=state):
                if state == "stale":
                    data["written_at"] = EPOCH - 61
                    data["started_at"] = EPOCH - 100
                    self.path.write_text(json.dumps(data))
                elif state == "missing":
                    self.path.unlink()
                self.monitor.tick()
                page = self.monitor.render_page(NOW)
                for reason in ("Target unverified", "Drain unverified",
                               "Repeat safety unverified", "Repair authorization unavailable",
                               "read-only reconciliation", "Provider restart unavailable"):
                    self.assertIn(reason, page)
                for control in ("<form", "<button", "<input", "onclick=", "repair_available"):
                    self.assertNotIn(control, page)

    def test_source_time_stays_stale_and_future_rejected(self):
        self.write(epoch=EPOCH-61)
        snapshot = self.monitor.tick()
        self.assertEqual(snapshot['fields']['requests_total']['state'], 'stale')
        self.assertNotEqual(snapshot['fields']['requests_total']['timestamp'], NOW)
        self.assertEqual(snapshot['fields']['heartbeat_age_seconds']['state'], 'observed')
        self.write(epoch=EPOCH+1)
        self.assertEqual(self.monitor.tick()['fields']['error_code']['value'], 'invalid_state')

    def test_protections_preserved(self):
        self.directory.chmod(0o755)
        self.assertEqual(self.monitor.tick()['fields']['error_code']['value'], 'permission_denied')
        self.directory.chmod(0o700)
        self.path.unlink()
        self.path.symlink_to(self.directory / 'absent')
        self.assertEqual(self.monitor.tick()['fields']['error_code']['value'], 'unavailable')

    def test_live_http_repeated_updates_stop_restart_and_host_guard(self):
        for _ in range(2):
            stop = threading.Event()
            ready = threading.Event()
            ports = []
            errors = []

            def started(port):
                ports.append(port)
                ready.set()

            def run():
                try:
                    run_monitor(self.monitor, port=0, stop=stop, ready=started)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(ready.wait(5))
            try:
                connection = http.client.HTTPConnection('127.0.0.1', ports[0], timeout=3)
                connection.request('GET', '/', headers={'Host': 'evil.example'})
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.close()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(status(ports[0]), 0)
                first = self.monitor._collections
                self.write(100)
                deadline = threading.Event()
                # Real scheduler must acquire again without a browser request.
                for attempt in range(30):
                    if self.monitor._collections > first:
                        break
                    deadline.wait(0.1)
                self.assertGreater(self.monitor._collections, first)
                connection = http.client.HTTPConnection('127.0.0.1', ports[0], timeout=3)
                connection.request('GET', '/')
                response = connection.getresponse()
                body = response.read().decode()
                self.assertEqual(response.status, 200)
                self.assertIn('http-equiv="refresh"', body)
                self.assertIn('100', body)
                self.assertIn('Repairs disabled', body)
                self.assertIn('Provider restart unavailable', body)
                self.assertIn('Repeat safety unverified', body)
                for method, target, expected in (("POST", "/", 501),
                                                 ("POST", "/repair/restart", 501),
                                                 ("GET", "/repair/restart", 404)):
                    connection.close()
                    connection = http.client.HTTPConnection('127.0.0.1', ports[0], timeout=3)
                    connection.request(method, target)
                    rejected = connection.getresponse()
                    self.assertEqual(rejected.status, expected)
                    rejected.read()
                self.assertNotIn('MUST_NEVER_APPEAR', body)
                connection.close()
            finally:
                stop.set()
                thread.join(8)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(status(ports[0]), 1)

    def test_cli_sigterm_and_sigint_cleanup(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            process = subprocess.Popen([sys.executable, '-m', 'gargoyl', 'monitor',
                '--input', str(self.path), '--owner-uid', str(os.getuid()),
                '--host', HOST, '--port', '0', '--interval', '1'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                line = process.stdout.readline()
                self.assertIn('Gargoyl listening on http://127.0.0.1:', line)
                port = int(line.split('127.0.0.1:')[1].split('/')[0])
                process.send_signal(sig)
                out, err = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, err)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(status(port), 1)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_runtime_failure_closes_listener_and_staleness_ages_without_poll(self):
        self.monitor.tick()
        page = self.monitor.render_page('2026-10-30T12:02:00Z')
        self.assertIn('collector_heartbeat_not_current', page)
        self.assertIn('stale', page)
        stop = threading.Event()
        ports = []
        original = self.monitor.tick
        calls = 0

        def fail_second(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('PRIVATE_FAILURE_MUST_NOT_APPEAR')
            return original(**kwargs)

        self.monitor.tick = fail_second
        with self.assertRaises(OSError):
            run_monitor(self.monitor, port=0, stop=stop, ready=ports.append)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(status(ports[0]), 1)

    def test_invalid_source_configuration_exits_two_before_read_or_bind(self):
        # Finalize unrelated earlier tests before capturing exact CLI stderr.
        gc.collect()
        invalid = [('/source.json', str(2**32-1)), ('/source.json', str(2**32)),
                   ('/source.json', '-1'), ('relative.json', '501'),
                   ('/private//source.json', '501'), ('/private/./source.json', '501'),
                   ('/private/../source.json', '501'), ('/', '501'),
                   ('/private/source.json/', '501'), ('/' + 'x' * 4096, '501'),
                   ('/private/\0source.json', '501'), ('/private/\ud800source.json', '501')]
        for source, uid in invalid:
            with self.subTest(source=repr(source), uid=uid):
                output, error = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error), \
                     patch('gargoyl.monitor.read_daemon_state') as read, \
                     patch('gargoyl.monitor.MonitorViewer') as viewer:
                    code = main(['monitor', '--input', source, '--owner-uid', uid,
                                 '--host', HOST])
                self.assertEqual(code, 2)
                self.assertEqual(output.getvalue(), '')
                self.assertEqual(error.getvalue(), 'CLI input or configuration unavailable or invalid.\n')
                read.assert_not_called()
                viewer.assert_not_called()

    def test_largest_valid_uid_is_configuration_without_access(self):
        with patch('gargoyl.monitor.read_daemon_state') as read:
            monitor = LocalMonitor('/private/source.json', 2**32-2, HOST)
        self.assertEqual(monitor.owner_uid, 2**32-2)
        read.assert_not_called()

    def exchange(self, viewer, *, host=None, origin=None):
        viewer.timeout = 3
        worker = threading.Thread(target=viewer.handle_request)
        worker.start()
        payload = bytearray()
        try:
            with socket.create_connection(('127.0.0.1', viewer.server_port), timeout=3) as client:
                authority = host or f'127.0.0.1:{viewer.server_port}'
                request = f'GET / HTTP/1.1\r\nHost: {authority}\r\n'
                if origin is not None:
                    request += f'Origin: {origin}\r\n'
                client.sendall((request + '\r\n').encode('ascii'))
                # Read through the server FIN before closing the client, leaving
                # the server endpoint in TIME_WAIT rather than relying on a race.
                while block := client.recv(65536):
                    payload.extend(block)
                    self.assertLess(len(payload), 1048576)
        finally:
            worker.join(6)
        self.assertFalse(worker.is_alive())
        return bytes(payload)

    def test_immediate_same_port_restart_after_real_http_exchange(self):
        self.monitor.tick()
        with MonitorViewer(self.monitor, [HOST], clock=lambda: NOW) as first:
            port = first.server_port
            self.assertTrue(self.exchange(first).startswith(b'HTTP/1.0 200'))
        # No sleep, alternate port, or system TCP tuning: restart the same
        # listener immediately after an actual server-closed HTTP connection.
        with MonitorViewer(self.monitor, [HOST], clock=lambda: NOW, port=port) as restarted:
            self.assertTrue(self.exchange(restarted).startswith(b'HTTP/1.0 200'))

    def test_active_listener_cannot_be_displaced_and_guards_remain(self):
        self.monitor.tick()
        with MonitorViewer(self.monitor, [HOST], clock=lambda: NOW) as viewer:
            with self.assertRaises(OSError) as refused:
                MonitorViewer(self.monitor, [HOST], clock=lambda: NOW, port=viewer.server_port)
            self.assertEqual(refused.exception.errno, errno.EADDRINUSE)
            self.assertTrue(self.exchange(viewer, host='evil.invalid').startswith(b'HTTP/1.0 403'))
            self.assertTrue(self.exchange(viewer, origin='https://evil.invalid').startswith(b'HTTP/1.0 403'))
            self.assertTrue(self.exchange(viewer).startswith(b'HTTP/1.0 200'))
            self.assertEqual(viewer.server_address[0], '127.0.0.1')
            self.assertEqual(viewer.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 0)

    def test_configuration_and_restart_clear_memory(self):
        self.monitor.tick()
        restarted = LocalMonitor(str(self.path), os.getuid(), HOST)
        self.assertEqual(restarted.snapshots(now=NOW), [])
        for interval in (0, 61, float('nan'), True):
            with self.assertRaises(ValueError):
                LocalMonitor(str(self.path), os.getuid(), HOST, interval=interval)
