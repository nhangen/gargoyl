"""CLI tests execute only self-authored synthetic producers."""

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_collector_adapters import DOCTOR_TEXT

from gargoyl.cli import main
from gargoyl.collector_acquisition import AcquisitionResult
from gargoyl.collector_adapters import AdapterResult

NOW = '2026-01-01T00:00:00Z'


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.env = self.path / 'environment.json'
        self.env.write_text('{}')
        self.producer = self.path / 'synthetic'
        self.write("assert sys.argv[1:] == ['status']\nprint('Status: ○ Stopped')")

    def write(self, body):
        self.producer.write_text(f'#!{sys.executable}\nimport sys, os, time\n' + body)
        self.producer.chmod(0o700)

    def capture(self):
        return ['capture', 'status', '--executable', str(self.producer), '--cwd', str(self.path),
                '--environment', str(self.env)]

    def run_main(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_inspect_requires_source_timestamp_and_never_executes(self):
        source = self.path / 'supplied.txt'
        source.write_text('Status: ○ Stopped\n')
        with patch('gargoyl.cli.BoundedAcquirer') as acquisition:
            code, output, error = self.run_main(['inspect', 'status', '--input', str(source), '--observed-at', NOW])
            acquisition.assert_not_called()
        self.assertEqual((code, error), (0, ''))
        value = json.loads(output)
        self.assertEqual(value['observed_at'], NOW)
        self.assertEqual(value['readings']['daemon_state']['value'], 'stopped')
        self.assertNotIn('cleanup_complete', value)
        self.assertEqual(self.run_main(['inspect', 'status', '--input', str(source)])[0], 2)

    def test_stdin_invalid_utf8_overflow_and_source_text_are_private(self):
        for payload in (b'private-marker', b'\xff', b'x' * 65537):
            stream = io.TextIOWrapper(io.BytesIO(payload))
            with patch('sys.stdin', stream):
                code, output, error = self.run_main(['inspect', 'doctor', '--input', '-', '--observed-at', NOW])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output)['errors'], ['invalid_state'])
            self.assertNotIn('private-marker', output + error)

    def test_capture_explicit_environment_and_fixed_argument(self):
        self.env.write_text('{"FIXTURE":"allowed"}')
        self.write("assert sys.argv[1:] == ['status']\n"
                   "assert os.environ['FIXTURE'] == 'allowed'\n"
                   "assert 'PRIVATE_PARENT_MARKER' not in os.environ\nprint('Status: ○ Stopped')")
        with patch.dict(os.environ, {'PRIVATE_PARENT_MARKER': 'secret'}):
            code, output, error = self.run_main(self.capture())
        value = json.loads(output)
        self.assertEqual((code, error), (0, ''))
        self.assertTrue(value['cleanup_complete'])
        self.assertEqual(value['readings']['daemon_state']['value'], 'stopped')
        self.assertNotIn('secret', output)

    def test_bad_configuration_never_launches_or_echoes_values(self):
        for environment in ('{"private-marker":"a","private-marker":"b"}', '[]', '{"x":1}'):
            self.env.write_text(environment)
            with patch('gargoyl.collector_acquisition.subprocess.Popen') as launch:
                code, output, error = self.run_main(self.capture())
                launch.assert_not_called()
            self.assertEqual((code, output), (2, ''))
            self.assertNotIn('private-marker', error)
        code, output, error = self.run_main(['private-marker'])
        self.assertEqual(code, 2)
        self.assertNotIn('private-marker', output + error)

    def test_nonzero_and_overflow_do_not_emit_partial_readings(self):
        for body in ("print('Status: ● Running'); sys.exit(1)", "print('private-marker'*7000)"):
            self.write(body)
            code, output, error = self.run_main(self.capture())
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output)['readings'], {})
            self.assertNotIn('private-marker', output + error)

    def test_incomplete_cleanup_overrides_success(self):
        acquired = AcquisitionResult('darkbloom_status_text_v1', NOW, NOW, AdapterResult({}, ()), False)
        previous = signal.getsignal(signal.SIGINT)
        with patch('gargoyl.cli.BoundedAcquirer.acquire', return_value=acquired):
            code, output, _ = self.run_main(self.capture())
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output)['errors'], ['unavailable'])
        self.assertEqual(signal.getsignal(signal.SIGINT), previous)

    def test_real_signal_requests_cleanup_and_returns_130(self):
        self.write("open('started', 'w').close()\ntime.sleep(30)")
        for sig in (signal.SIGINT, signal.SIGTERM):
            marker = self.path / 'started'
            marker.unlink(missing_ok=True)
            process = subprocess.Popen([sys.executable, '-m', 'gargoyl', *self.capture()],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists())
                process.send_signal(sig)
                output, error = process.communicate(timeout=4)
                self.assertEqual(process.returncode, 130, error)
                value = json.loads(output)
                self.assertTrue(value['cleanup_complete'])
                self.assertEqual(value['readings'], {})
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_real_timeout_is_bounded(self):
        self.write("print('Status: ● Running', flush=True)\ntime.sleep(30)")
        start = time.monotonic()
        code, output, _ = self.run_main(self.capture())
        self.assertLess(time.monotonic() - start, 7)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)['errors'], ['timeout'])
        self.assertEqual(json.loads(output)['readings'], {})

    def test_doctor_capture_normalizes_complete_synthetic_report(self):
        self.write("assert sys.argv[1:] == ['doctor']\nprint(" + repr(DOCTOR_TEXT) + ")")
        args = self.capture()
        args[1] = 'doctor'
        code, output, error = self.run_main(args)
        self.assertEqual((code, error), (0, ''))
        value = json.loads(output)
        self.assertEqual(value['readings']['doctor_state']['value'], 'passed')
        self.assertNotIn('Synthetic Chip', output)
