"""Only explicit temporary JSON fixtures; never installed daemon files or commands."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_collector_state_file import EPOCH, LATER, NOW, fixture

from gargoyl.cli import main


class StateCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 'state.json'
        self.path.write_text(json.dumps(fixture()))
        self.path.chmod(0o600)

    def run_cli(self, *, path=None, uid=None, now=NOW, extra=()):
        output, error = io.StringIO(), io.StringIO()
        args = ['inspect', 'state', '--input', str(path or self.path), '--owner-uid',
                str(os.getuid() if uid is None else uid), *extra]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error), \
             patch('gargoyl.cli._utc_now', return_value=now), \
             patch('gargoyl.cli.BoundedAcquirer') as acquire, \
             patch('gargoyl.cli.parse_observations') as text_parse:
            code = main(args)
            acquire.assert_not_called()
            text_parse.assert_not_called()
        return code, json.loads(output.getvalue()) if output.getvalue() else None, error.getvalue()

    def test_preserves_source_time_and_only_selected_observations(self):
        code, value, error = self.run_cli()
        self.assertEqual((code, error), (0, ''))
        self.assertEqual(value['source_kind'], 'darkbloom_daemon_state_json_v1')
        self.assertEqual(value['observed_at'], NOW)
        self.assertEqual(set(value['readings']), {'requests_total', 'tokens_total', 'model_state'})
        self.assertEqual(value['readings']['requests_total']['value'], 3)
        self.assertTrue(all(field['timestamp'] == NOW for field in value['readings'].values()))
        self.assertNotIn('synthetic-private', json.dumps(value))
        self.assertNotIn('12345', json.dumps(value))
        self.assertNotIn('cleanup_complete', value)
        self.assertNotIn('daemon_state', value['readings'])

    def test_stale_and_empty_preserve_written_time_without_health_claim(self):
        code, value, _ = self.run_cli(now=LATER)
        self.assertEqual(code, 0)
        self.assertEqual(value['observed_at'], NOW)
        self.assertTrue(all(field['state'] == 'stale' for field in value['readings'].values()))
        data = fixture()
        data.update(warm_models=[], current_model=None, stats={})
        self.path.write_text(json.dumps(data))
        code, value, _ = self.run_cli()
        self.assertEqual((code, value['observed_at'], value['readings'], value['errors']), (0, NOW, {}, []))

    def test_missing_malformed_oversized_and_future_have_null_time(self):
        for payload in ('private-marker', 'x' * 65537,
                        json.dumps(dict(fixture(), written_at=EPOCH + 1))):
            self.path.write_text(payload)
            code, value, error = self.run_cli()
            self.assertEqual(code, 1)
            self.assertIsNone(value['observed_at'])
            self.assertEqual(value['readings'], {})
            self.assertEqual(value['errors'], ['invalid_state'])
            self.assertNotIn('private-marker', json.dumps(value) + error)
        self.path.unlink()
        code, value, _ = self.run_cli()
        self.assertEqual((code, value['observed_at'], value['errors']), (1, None, ['unavailable']))

    def test_owner_and_symlink_failures_never_fall_back(self):
        code, value, _ = self.run_cli(uid=os.getuid() + 1)
        self.assertEqual((code, value['observed_at'], value['errors']), (1, None, ['permission_denied']))
        link = self.path.parent / 'link.json'
        link.symlink_to(self.path)
        code, value, _ = self.run_cli(path=link)
        self.assertEqual((code, value['observed_at'], value['errors']), (1, None, ['unavailable']))

    def test_no_stdin_relative_paths_negative_uid_or_timestamp_override(self):
        for options in ({'path': '-'}, {'path': 'state.json'}, {'uid': -1},
                        {'extra': ('--observed-at', NOW)}):
            code, value, error = self.run_cli(**options)
            self.assertEqual((code, value), (2, None))
            self.assertEqual(error, 'CLI input or configuration unavailable or invalid.\n')
        with patch('gargoyl.cli.read_daemon_state') as read:
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(['inspect', 'state', '--input', str(self.path)]), 2)
            read.assert_not_called()

    def test_text_option_order_remains_compatible_and_owner_option_is_state_only(self):
        self.path.write_text('Status: ○ Stopped')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['inspect', '--input', str(self.path), 'status', '--observed-at', NOW])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())['readings']['daemon_state']['value'], 'stopped')
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(['inspect', 'status', '--input', str(self.path), '--observed-at', NOW,
                         '--owner-uid', str(os.getuid())])
        self.assertEqual(code, 2)
