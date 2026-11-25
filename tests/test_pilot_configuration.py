"""Only temporary owner-local policy/installation fixtures
no live actions."""
import io
import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.gui_runtime import monitor_configuration, set_grants
from gargoyl.pilot_configuration import (
    SCHEMA,
    defaults,
    grant_flags,
    load_pilot_configuration,
    save_pilot_grants,
    validate_grants,
)


class PilotConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.bin = self.home / 'relocated/.venv/bin'
        self.bin.mkdir(parents=True)
        self.python = str(self.bin / 'python')
        cli = self.bin / 'gargoyl'
        cli.write_text('synthetic fixture, never executed')
        cli.chmod(0o700)
        self.directory = self.home / 'Library/Application Support/Gargoyl'
        self.directory.mkdir(parents=True, mode=0o700)
        self.path = self.directory / 'pilot.json'
        self.base = defaults(self.home, self.python)
        self.value = dict(schema=1, owner_uid=os.getuid(), hostname='synthetic-local',
                          host_id=self.base.host_id, source=self.base.source,
                          provider_executable=self.base.provider_executable,
                          monitor_executable=self.base.monitor_executable,
                          versions=dict(SUPPORTED_VERSIONS))

    def write(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value))
        self.path.chmod(0o600)

    def load(self):
        with patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            return load_pilot_configuration(home=self.home, python=self.python)

    def test_absent_policy_preserves_approved_target_and_derives_relocated_cli(self):
        policy = self.load()
        self.assertEqual((policy.owner_uid, policy.hostname), (501, 'MBP-2026.local'))
        self.assertEqual(policy.monitor_executable, str(self.bin / 'gargoyl'))
        self.assertFalse(self.path.exists())
        with patch('os.getuid', return_value=502), self.assertRaises(ValueError):
            policy.require_local()

    def test_private_policy_is_local_only_and_can_only_narrow_reviewed_versions(self):
        self.value['versions'] = {'0.10.6': SUPPORTED_VERSIONS['0.10.6']}
        self.write()
        with patch('subprocess.Popen') as execute:
            policy = self.load()
        execute.assert_not_called()
        self.assertEqual(policy.versions, frozenset({'0.10.6'}))
        self.assertEqual(policy.owner_uid, os.getuid())
        self.write(dict(self.value, hostname='another-machine'))
        with self.assertRaises(ValueError):
            self.load()
        self.write(dict(self.value, owner_uid=os.getuid()+1))
        with self.assertRaises(ValueError):
            self.load()

    def test_unknown_fields_commands_versions_and_provenance_are_refused(self):
        invalid = [dict(self.value, extra='secret-synthetic-payload'),
                   dict(self.value, owner_uid=True), dict(self.value, owner_uid=0),
                   dict(self.value, schema=True), dict(self.value, hostname='bad\nname'),
                   dict(self.value, host_id='not-a-uuid'),
                   dict(self.value, source='/arbitrary/source'),
                   dict(self.value, provider_executable='/usr/bin/true'),
                   dict(self.value, monitor_executable='/arbitrary/gargoyl'),
                   dict(self.value, versions={}),
                   dict(self.value, versions={'99.0.0': 'a'*64}),
                   dict(self.value, versions={'0.10.6': 'a'*64})]
        for value in invalid:
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(ValueError) as error:
                    self.load()
                self.assertNotIn('secret-synthetic-payload', str(error.exception))

    def test_duplicate_malformed_oversized_and_nonprivate_files_fail_closed(self):
        for content in ['{"schema":1,"schema":1}', '{bad', '['*2000+']'*2000, 'x'*8193]:
            self.path.write_text(content)
            self.path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.load()
        self.write()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()
        self.path.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaises(ValueError):
            self.load()

    def test_links_and_nonregular_policy_are_refused_without_following(self):
        self.write()
        real = self.directory / 'original'
        self.path.rename(real)
        self.path.symlink_to(real)
        with self.assertRaises((OSError, ValueError)):
            self.load()
        self.path.unlink()
        os.link(real, self.path)
        with self.assertRaises(ValueError):
            self.load()
        self.path.unlink()
        real.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError):
            self.load()
        self.path.unlink()
        moved = self.directory.with_name('original-directory')
        self.directory.rename(moved)
        self.directory.symlink_to(moved)
        with self.assertRaises(ValueError):
            self.load()

    def test_rewrite_during_read_is_refused(self):
        self.write()
        original = os.read
        def changing(fd, limit):
            payload = original(fd, limit)
            self.path.write_text('{}')
            return payload
        with patch('os.read', side_effect=changing), self.assertRaises(ValueError):
            self.load()

    def test_monitor_validation_accepts_relocated_sibling_without_executing(self):
        self.write()
        agent = self.home / 'Library/LaunchAgents/dev.gargoyl.monitor.plist'
        agent.parent.mkdir()
        args = [str(self.bin / 'gargoyl'), 'monitor', '--input', self.base.source,
                '--owner-uid', str(os.getuid()), '--host', self.base.host_id,
                '--interval', '5', '--port', '8766', '--provider-executable',
                self.base.provider_executable, '--coordinator-errors']
        agent.write_bytes(plistlib.dumps(dict(Label='dev.gargoyl.monitor', ProgramArguments=args)))
        original = agent.read_bytes()
        with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
             patch('subprocess.run') as execute:
            self.assertEqual(monitor_configuration(), agent)
            self.assertEqual(agent.read_bytes(), original)
            args[0] = '/arbitrary/gargoyl'
            agent.write_bytes(plistlib.dumps(dict(Label='dev.gargoyl.monitor', ProgramArguments=args)))
            with self.assertRaises(ValueError):
                monitor_configuration()
        execute.assert_not_called()

    def test_fresh_policy_restrictions_block_preflight_before_command(self):
        from test_manual_restart import TARGET

        from gargoyl.manual_restart import installation_preflight
        executable = Path(self.base.provider_executable)
        executable.parent.mkdir(parents=True)
        executable.write_text('synthetic fixture, never executed')
        executable.chmod(0o700)
        agent = self.home / 'Library/LaunchAgents/io.darkbloom.provider.plist'
        agent.parent.mkdir()
        agent.write_bytes(plistlib.dumps(dict(Label='io.darkbloom.provider',
                                             ProgramArguments=[str(executable), 'start', '--foreground'])))
        self.write()
        target = dict(TARGET, process=dict(TARGET['process'], owner_uid=os.getuid()))
        with patch('gargoyl.manual_restart.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), patch('sys.platform', 'darwin'), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
             patch('gargoyl.manual_restart.observed_target', return_value=target), \
             patch('gargoyl.manual_restart._job_running', return_value=target['process']['pid']), \
             patch('subprocess.run', return_value=Mock(returncode=0, stdout=b'0.10.6\n', stderr=b'')) as execute:
            self.assertEqual(installation_preflight(str(executable), self.base.source, os.getuid())[0], target)
            execute.assert_called_once()
            execute.reset_mock()
            self.value['versions'] = {'0.10.5': SUPPORTED_VERSIONS['0.10.5']}
            self.write()
            with self.assertRaises(ValueError):
                installation_preflight(str(executable), self.base.source, os.getuid())
            execute.assert_not_called()
            self.value['hostname'] = 'another-machine'
            self.write()
            with self.assertRaises(ValueError):
                installation_preflight(str(executable), self.base.source, os.getuid())
            execute.assert_not_called()

    def test_configured_local_identity_is_propagated_without_cross_host_fallback(self):
        from test_dashboard import NOW, snapshot

        from gargoyl.native_views import render_view
        second = '00000000-0000-4000-8000-000000000002'
        item = dict(snapshot(), host_id=second)
        evidence = dict(evaluated_at=NOW, snapshots=[item])
        with self.assertRaises(ValueError):
            render_view('evidence', evidence, None, now=NOW)
        page = render_view('evidence', evidence, None, now=NOW, local_host_id=second)
        self.assertIn('host-' + second, page)
        self.assertNotIn('host-' + self.base.host_id, page)
        page = render_view('fleet', evidence, None, now=NOW, local_host_id=second)
        self.assertIn('This Mac', page)
        self.assertNotIn('Direct local observations unavailable', page)

    def test_foreign_file_or_directory_owner_is_refused_before_payload_read(self):
        import stat
        from types import SimpleNamespace
        self.write()
        fstat = os.fstat
        for directory in (False, True):
            def foreign(fd):
                info = fstat(fd)
                if stat.S_ISDIR(info.st_mode) == directory:
                    return SimpleNamespace(st_uid=os.getuid()+1, st_mode=info.st_mode,
                                           st_nlink=info.st_nlink, st_size=info.st_size)
                return info
            with self.subTest(directory=directory), patch('os.fstat', side_effect=foreign), \
                 patch('os.read') as read, self.assertRaises(ValueError):
                self.load()
            read.assert_not_called()

    def test_cli_confirmation_names_configured_target_and_old_name_cannot_authorize(self):
        import contextlib
        import io

        from test_manual_restart import TARGET

        from gargoyl.operator_tools import main
        self.write()
        output, terminal = io.StringIO(), io.StringIO()
        output.isatty = lambda: True
        terminal.isatty = lambda: True
        with patch('gargoyl.operator_tools.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
             patch('sys.stdin', terminal), patch('sys.stdout', output), \
             patch('gargoyl.operator_tools.installation_preflight', return_value=(TARGET, 'stamp')), \
             patch('gargoyl.operator_tools.invoke_restart') as invoke, \
             patch('builtins.input', return_value='RESTART MBP-26') as consent, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['restart', '--input', self.base.source, '--owner-uid', str(os.getuid()),
                                   '--provider-executable', self.base.provider_executable]), 1)
        self.assertIn('current provider of this synthetic-local installation', output.getvalue())
        self.assertNotIn('MBP-26', output.getvalue())
        consent.assert_called_once_with('Type RESTART synthetic-local to invoke once: ')
        invoke.assert_not_called()

    def test_cli_reconciliation_also_requires_the_configured_target_phrase(self):
        import contextlib
        import io

        from test_manual_restart import NOW, TARGET

        from gargoyl.manual_restart import ManualJournal, read_operation
        from gargoyl.operator_tools import main
        self.write()
        journal_path = str(self.home / '.gargoyl-manual-restart')
        with ManualJournal(journal_path) as journal:
            journal.write(dict(schema=1, operation_id='a'*32, state='unknown',
                               started_at=NOW, target=TARGET, reason='completion_unverified'))
        output, terminal = io.StringIO(), io.StringIO()
        output.isatty = lambda: True
        terminal.isatty = lambda: True
        with patch('gargoyl.operator_tools.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
             patch('sys.stdin', terminal), patch('sys.stdout', output), \
             patch('builtins.input', return_value='RECONCILE MBP-26') as consent, \
             patch('gargoyl.manual_restart.reconcile_operation') as reconcile, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['reconcile', '--record']), 1)
        consent.assert_called_once_with('Type RECONCILE synthetic-local to record: ')
        reconcile.assert_not_called()
        self.assertEqual(read_operation(journal_path)['state'], 'unknown')

    def test_grant_flags_and_validation_sequence(self):
        self.assertEqual(validate_grants(None), ())
        self.assertEqual(validate_grants([]), ())
        self.assertEqual(validate_grants(['provider_executable']), ('provider_executable',))
        self.assertEqual(
            validate_grants(['provider_executable', 'operator_tools', 'restart', 'account_read_only']),
            ('provider_executable', 'operator_tools', 'restart', 'account_read_only'),
        )
        for invalid in [
            'not-a-list',
            [123],
            ['unknown_grant'],
            ['restart'],  # requires operator_tools
            ['operator_tools'],  # requires provider_executable
            ['restart', 'operator_tools'],  # invalid order
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_grants(invalid)

        flags = list(grant_flags(('provider_executable',), self.base.provider_executable))
        self.assertEqual(flags, ['--provider-executable', self.base.provider_executable, '--coordinator-errors'])
        all_flags = list(grant_flags(
            ('provider_executable', 'operator_tools', 'restart', 'account_read_only'),
            self.base.provider_executable,
        ))
        self.assertEqual(
            all_flags,
            ['--provider-executable', self.base.provider_executable, '--coordinator-errors',
             '--operator-tools', '--enable-restart'],
        )
        self.assertNotIn('account_read_only', all_flags)

    def test_grants_persistence_round_trip_and_activation_state(self):
        grants = ('provider_executable', 'operator_tools', 'restart')
        request = json.dumps(dict(grants=list(grants), confirm='provider_executable operator_tools restart')).encode() + b'\n'
        r, w = os.pipe()
        os.write(w, request)
        os.close(w)
        stream = os.fdopen(r, 'rb')
        try:
            with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
                 patch('sys.executable', self.python), \
                 patch('os.uname', return_value=Mock(nodename='synthetic-local')):
                state = set_grants(stream=stream, home=self.home, python=self.python)
                self.assertEqual(state['kind'], 'activation')
                self.assertEqual(state['grants'], list(grants))
                self.assertIn('--enable-restart', state['command'])
                self.assertIn('--operator-tools', state['command'])
                self.assertIn('--coordinator-errors', state['command'])

                policy = self.load()
                self.assertEqual(policy.grants, grants)
                # Schema 2 written to pilot.json
                content = json.loads(self.path.read_text())
                self.assertEqual(content['schema'], SCHEMA)
                self.assertEqual(content['grants'], list(grants))

                # dev.gargoyl.monitor.plist updated and immediately validated
                agent = monitor_configuration()
                self.assertTrue(agent.exists())
        finally:
            stream.close()

    def test_grants_revocation_path(self):
        # First save grants
        with patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            save_pilot_grants(home=self.home, python=self.python,
                              grants=('provider_executable', 'operator_tools'))
        policy = self.load()
        self.assertEqual(policy.grants, ('provider_executable', 'operator_tools'))

        # Revocation requires explicit "REVOKE ALL" confirmation
        bad_confirm = json.dumps(dict(grants=[], confirm='WRONG CONFIRM')).encode() + b'\n'
        r, w = os.pipe()
        os.write(w, bad_confirm)
        os.close(w)
        stream = os.fdopen(r, 'rb')
        try:
            with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
                 patch('sys.executable', self.python), \
                 patch('os.uname', return_value=Mock(nodename='synthetic-local')):
                with self.assertRaises(ValueError) as error:
                    set_grants(stream=stream, home=self.home, python=self.python)
                self.assertIn('grant consent unavailable', str(error.exception))
        finally:
            stream.close()

        # Valid revocation
        revoke_request = json.dumps(dict(grants=[], confirm='REVOKE ALL')).encode() + b'\n'
        r, w = os.pipe()
        os.write(w, revoke_request)
        os.close(w)
        stream = os.fdopen(r, 'rb')
        try:
            with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
                 patch('sys.executable', self.python), \
                 patch('os.uname', return_value=Mock(nodename='synthetic-local')):
                state = set_grants(stream=stream, home=self.home, python=self.python)
                self.assertEqual(state['grants'], [])
                self.assertNotIn('--enable-restart', state['command'])
                self.assertNotIn('--operator-tools', state['command'])
                self.assertNotIn('--provider-executable', state['command'])

                revoked_policy = self.load()
                self.assertEqual(revoked_policy.grants, ())
                agent = monitor_configuration()
                self.assertTrue(agent.exists())
        finally:
            stream.close()

    def test_code_level_gates_enforce_grants(self):
        from gargoyl.gui_runtime import main as gui_main
        # Start with no grants
        with patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            save_pilot_grants(home=self.home, python=self.python, grants=())
        fifo_in_r, fifo_in_w = os.pipe()
        fifo_out_r, fifo_out_w = os.pipe()
        in_file = os.fdopen(fifo_in_r, 'rb', buffering=0)
        out_file = os.fdopen(fifo_out_w, 'wb', buffering=0)
        in_text = io.TextIOWrapper(in_file)
        out_text = io.TextIOWrapper(out_file)
        try:
            with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
                 patch('gargoyl.gui_runtime.console_owner', return_value=True), \
                 patch('sys.executable', self.python), \
                 patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
                 patch('sys.argv', ['gui_runtime.py', 'restart']), \
                 patch('sys.stdin', in_text), \
                 patch('sys.stdout', out_text), \
                 patch('os.getuid', return_value=501):
                # restart should fail because restart grant is missing
                self.assertEqual(gui_main(), 1)
        finally:
            in_text.close()
            out_text.close()
            os.close(fifo_in_w)
            os.close(fifo_out_r)
