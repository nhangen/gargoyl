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
from gargoyl.gui_runtime import monitor_argv, monitor_configuration, set_grants
from gargoyl.pilot_configuration import (
    ALLOWED_GRANTS,
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

    def provider_fixture(self):
        from test_manual_restart import TARGET
        executable = Path(self.base.provider_executable)
        executable.parent.mkdir(parents=True)
        executable.write_text('synthetic fixture, never executed')
        executable.chmod(0o700)
        agent = self.home / 'Library/LaunchAgents/io.darkbloom.provider.plist'
        agent.parent.mkdir()
        agent.write_bytes(plistlib.dumps(dict(Label='io.darkbloom.provider',
                                             ProgramArguments=[str(executable), 'start', '--foreground'])))
        return executable, dict(TARGET, process=dict(TARGET['process'], owner_uid=os.getuid()))

    def recorded(self, grants):
        self.write(dict(self.value, schema=2, grants=list(grants)))

    def request(self, grants, confirm):
        r, w = os.pipe()
        os.write(w, json.dumps(dict(grants=list(grants), confirm=confirm)).encode() + b'\n')
        os.close(w)
        stream = os.fdopen(r, 'rb')
        self.addCleanup(stream.close)
        return stream

    def set_grants(self, grants, confirm):
        with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            return set_grants(stream=self.request(grants, confirm), home=self.home, python=self.python)

    def monitor_arguments(self):
        agent = self.home / 'Library/LaunchAgents/dev.gargoyl.monitor.plist'
        return plistlib.loads(agent.read_bytes())['ProgramArguments']

    def test_grant_flags_and_validation_sequence(self):
        self.assertEqual(validate_grants(None), ())
        for allowed in ALLOWED_GRANTS:
            with self.subTest(allowed=allowed):
                self.assertEqual(validate_grants(list(allowed)), allowed)
                flags = list(grant_flags(allowed, self.base.provider_executable))
                self.assertEqual('--provider-executable' in flags, 'provider_executable' in allowed)
                self.assertEqual('--operator-tools' in flags, 'operator_tools' in allowed)
                self.assertEqual('--enable-restart' in flags, 'restart' in allowed)
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
        self.assertEqual(
            list(grant_flags(('provider_executable', 'operator_tools', 'restart', 'account_read_only'),
                             self.base.provider_executable)),
            ['--provider-executable', self.base.provider_executable, '--coordinator-errors',
             '--operator-tools', '--enable-restart'],
        )

    def test_unrecorded_policies_keep_the_approved_pilot_monitor_and_permits(self):
        pre_grant_suffix = ['--provider-executable', self.base.provider_executable, '--coordinator-errors']
        absent = self.load()
        self.write()
        schema_one = self.load()
        for policy in (absent, schema_one):
            with self.subTest(owner=policy.owner_uid):
                self.assertEqual(policy.grants, ('provider_executable',))
                self.assertFalse(policy.recorded)
                self.assertEqual(monitor_argv(self.home, policy)[-3:], pre_grant_suffix)
                self.assertTrue(policy.permits('restart'))
                self.assertTrue(policy.permits('account_read_only'))
                self.assertFalse(policy.permits('operator_tools'))
        self.recorded(())
        revoked = self.load()
        self.assertTrue(revoked.recorded)
        self.assertFalse(revoked.permits('restart'))
        self.assertFalse(revoked.permits('account_read_only'))
        self.assertNotIn('--provider-executable', monitor_argv(self.home, revoked))

    def test_restart_gate_in_preflight_refuses_every_path_without_the_grant(self):
        from gargoyl.manual_restart import installation_preflight
        executable, target = self.provider_fixture()
        with patch('gargoyl.manual_restart.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), patch('sys.platform', 'darwin'), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')), \
             patch('gargoyl.manual_restart.observed_target', return_value=target), \
             patch('gargoyl.manual_restart._job_running', return_value=target['process']['pid']), \
             patch('subprocess.run', return_value=Mock(returncode=0, stdout=b'0.10.6\n', stderr=b'')) as execute:
            for grants in [(), ('provider_executable', 'operator_tools'),
                           ('provider_executable', 'operator_tools', 'account_read_only')]:
                with self.subTest(grants=grants):
                    self.recorded(grants)
                    with self.assertRaisesRegex(ValueError, 'restart permission not granted'):
                        installation_preflight(str(executable), self.base.source, os.getuid())
                    execute.assert_not_called()
            self.recorded(('provider_executable', 'operator_tools', 'restart'))
            self.assertEqual(installation_preflight(str(executable), self.base.source, os.getuid())[0], target)
            execute.assert_called_once()

    def test_grants_persistence_round_trip_and_activation_state(self):
        grants = ('provider_executable', 'operator_tools', 'restart')
        state = self.set_grants(grants, 'provider_executable operator_tools restart')
        self.assertEqual(state['kind'], 'activation')
        self.assertEqual(state['grants'], list(grants))
        self.assertTrue(state['recorded'])
        self.assertEqual(state['permits'], list(grants))
        self.assertEqual(state['command'], self.monitor_arguments())
        self.assertEqual(state['command'][-5:], ['--provider-executable', self.base.provider_executable,
                                                 '--coordinator-errors', '--operator-tools', '--enable-restart'])
        policy = self.load()
        self.assertEqual(policy.grants, grants)
        content = json.loads(self.path.read_text())
        self.assertEqual(content['schema'], SCHEMA)
        self.assertEqual(content['grants'], list(grants))
        with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            monitor_configuration()

    def test_grants_revocation_path(self):
        self.set_grants(('provider_executable', 'operator_tools'), 'provider_executable operator_tools')
        self.assertIn('--operator-tools', self.monitor_arguments())
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'grant consent unavailable'):
            self.set_grants((), 'WRONG CONFIRM')
        with self.assertRaisesRegex(ValueError, 'grant consent unavailable'):
            self.set_grants(('provider_executable', 'operator_tools', 'restart'), 'restart')
        self.assertEqual(self.path.read_bytes(), before)
        state = self.set_grants((), 'REVOKE ALL')
        self.assertEqual(state['grants'], [])
        self.assertEqual(state['permits'], [])
        self.assertEqual(self.load().grants, ())
        arguments = self.monitor_arguments()
        for flag in ('--enable-restart', '--operator-tools', '--provider-executable'):
            self.assertNotIn(flag, arguments)

    def test_saving_grants_changes_only_grants(self):
        narrowed = {'0.10.5': SUPPORTED_VERSIONS['0.10.5']}
        self.value.update(host_id='00000000-0000-4000-8000-0000000000aa', versions=narrowed)
        self.write()
        self.set_grants(('provider_executable',), 'provider_executable')
        content = json.loads(self.path.read_text())
        self.assertEqual(content['host_id'], '00000000-0000-4000-8000-0000000000aa')
        self.assertEqual(content['versions'], narrowed)
        self.assertEqual((content['owner_uid'], content['hostname']), (os.getuid(), 'synthetic-local'))
        self.assertEqual(content['grants'], ['provider_executable'])

    def test_saving_over_an_unreviewed_policy_refuses_and_leaves_it(self):
        self.write(dict(self.value, versions={'9.9.9': 'x'}))
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.set_grants((), 'REVOKE ALL')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse((self.home / 'Library/LaunchAgents/dev.gargoyl.monitor.plist').exists())

    def test_first_save_creates_the_private_directory(self):
        self.directory.rmdir()
        with patch('os.uname', return_value=Mock(nodename='synthetic-local')):
            policy = save_pilot_grants(home=self.home, python=self.python, grants=('account_read_only',))
        self.assertEqual(policy.grants, ('account_read_only',))
        self.assertEqual(os.stat(self.directory).st_mode & 0o777, 0o700)

    def test_failed_plist_write_restores_the_previous_policy(self):
        self.write()
        before = self.path.read_bytes()
        with patch('gargoyl.gui_runtime.update_monitor_plist', side_effect=OSError('disk full')), \
             self.assertRaisesRegex(ValueError, 'monitor plist unavailable'):
            self.set_grants((), 'REVOKE ALL')
        self.assertEqual(self.path.read_bytes(), before)
        self.path.unlink()
        with patch('gargoyl.gui_runtime.update_monitor_plist', side_effect=OSError('disk full')), \
             self.assertRaisesRegex(ValueError, 'monitor plist unavailable'):
            self.set_grants((), 'REVOKE ALL')
        self.assertFalse(self.path.exists())

    def test_foreign_monitor_plist_is_not_overwritten(self):
        agent = self.home / 'Library/LaunchAgents/dev.gargoyl.monitor.plist'
        agent.parent.mkdir()
        foreign = plistlib.dumps(dict(Label='com.example.other', ProgramArguments=['/bin/true']))
        agent.write_bytes(foreign)
        agent.chmod(0o600)
        self.write()
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'monitor plist unavailable'):
            self.set_grants((), 'REVOKE ALL')
        self.assertEqual(agent.read_bytes(), foreign)
        self.assertEqual(self.path.read_bytes(), before)

    def run_main(self, mode, payload=b'', nodename='synthetic-local'):
        from gargoyl.gui_runtime import main as gui_main
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        os.write(in_w, payload)
        os.close(in_w)
        stdin = io.TextIOWrapper(os.fdopen(in_r, 'rb', buffering=0))
        stdout = io.TextIOWrapper(os.fdopen(out_w, 'wb', buffering=0), write_through=True)
        with patch('gargoyl.gui_runtime.owner_home', return_value=self.home), \
             patch('gargoyl.gui_runtime.console_owner', return_value=True), \
             patch('sys.executable', self.python), \
             patch('os.uname', return_value=Mock(nodename=nodename)), \
             patch('sys.argv', ['gui_runtime.py', mode]), \
             patch('sys.stdin', stdin), patch('sys.stdout', stdout):
            code = gui_main()
        stdout.close()
        stdin.close()
        with os.fdopen(out_r, 'rb') as reader:
            events = [json.loads(line) for line in reader.read().splitlines() if line.strip()]
        return code, events

    def test_activation_mode_reports_recorded_state(self):
        self.recorded(('account_read_only',))
        code, events = self.run_main('activation')
        self.assertEqual(code, 0)
        self.assertEqual(events[-1]['grants'], ['account_read_only'])
        self.assertTrue(events[-1]['recorded'])
        self.assertEqual(events[-1]['permits'], ['account_read_only'])

    def test_set_grants_mode_saves_and_reports_specific_failures(self):
        self.write()
        code, events = self.run_main('set-grants', json.dumps(dict(grants=[], confirm='REVOKE ALL')).encode() + b'\n')
        self.assertEqual(code, 0)
        self.assertEqual(events[-1]['kind'], 'activation')
        self.assertEqual(self.load().grants, ())
        code, events = self.run_main('set-grants', json.dumps(dict(grants=[], confirm='nope')).encode() + b'\n')
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]['kind'], 'unavailable')
        self.assertIn('confirmation did not match', events[-1]['text'])
        code, events = self.run_main('set-grants', json.dumps(dict(grants=[], confirm='REVOKE ALL', extra=1)).encode() + b'\n')
        self.assertEqual(code, 1)
        self.assertIn('malformed', events[-1]['text'])

    def test_fleet_modes_refuse_without_the_account_grant(self):
        self.recorded(('provider_executable',))
        with patch('gargoyl.fleet_session.run_session') as session:
            for mode in ('fleet-session', 'fleet-session-remember', 'fleet-restore'):
                with self.subTest(mode=mode):
                    code, events = self.run_main(mode)
                    self.assertEqual(code, 1)
                    self.assertIn('account read-only permission is not granted', events[-1]['text'])
        session.assert_not_called()

    def test_unrecorded_account_sessions_do_not_require_the_pilot_identity(self):
        with patch('gargoyl.fleet_session.run_session') as session, \
             patch('gargoyl.fleet_state.FleetCache'):
            code, events = self.run_main('fleet-session', nodename='another-mac.local')
        session.assert_called_once()
        self.recorded(('account_read_only',))
        with patch('gargoyl.fleet_session.run_session') as session, \
             patch('gargoyl.fleet_state.FleetCache'):
            code, events = self.run_main('fleet-session', nodename='another-mac.local')
        session.assert_not_called()
        self.assertIn('could not be read for this owner and Mac', events[-1]['text'])

    def test_failed_rollback_reports_partial_state(self):
        self.write()
        with patch('gargoyl.gui_runtime.update_monitor_plist', side_effect=OSError('disk full')), \
             patch('gargoyl.gui_runtime.write_pilot_payload', side_effect=OSError('disk full')), \
             self.assertRaisesRegex(ValueError, 'grant rollback unavailable'):
            self.set_grants((), 'REVOKE ALL')
