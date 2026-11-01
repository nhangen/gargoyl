"""Only temporary owner-local policy/installation fixtures
no live actions."""
import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.gui_runtime import monitor_configuration
from gargoyl.pilot_configuration import defaults, load_pilot_configuration


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
