"""Synthetic capability output and shared admission regressions; no live provider."""
import contextlib
import io
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_manual_restart import NOW, REPLACEMENT, TARGET

from gargoyl.gui_runtime import graphical_restart
from gargoyl.manual_restart import ManualJournal, reconcile_operation, run_restart
from gargoyl.monitor import main
from gargoyl.operator_console import ConsoleRestart


class CapabilityOutputTests(unittest.TestCase):
    def test_private_link_only_reaches_interactive_stdout(self):
        # Fixed fake capability: never generate/read a real runtime capability.
        capability = 'SYNTHETIC_CAPABILITY_ONLY'
        for terminal in (False, True):
            with self.subTest(terminal=terminal):
                output, error = io.StringIO(), io.StringIO()
                output.isatty = lambda: terminal
                args = SimpleNamespace(command='monitor', port=0, coordinator_errors=False,
                                       provider_executable=None, enable_restart=True,
                                       operator_tools=True, input='/synthetic/state.json',
                                       owner_uid=501, host='synthetic', interval=5)
                tools = SimpleNamespace(base='/s/' + capability, restart=True)

                def run(*args, ready, **kwargs):
                    ready(12345)
                    return 0

                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error), \
                     patch('gargoyl.monitor.LocalMonitor'), \
                     patch('gargoyl.monitor.build_operator_tools', return_value=tools), \
                     patch('gargoyl.monitor.run_monitor', side_effect=run):
                    self.assertEqual(main(args), 0)
                self.assertIn('http://127.0.0.1:12345/', output.getvalue())
                self.assertNotIn(capability, error.getvalue())
                if terminal:
                    self.assertIn('/s/' + capability + '/', output.getvalue())
                else:
                    self.assertNotIn(capability, output.getvalue())
                    self.assertNotIn('/s/', output.getvalue())
                    self.assertIn('link withheld', output.getvalue())


class SharedRestartGateTests(unittest.TestCase):
    def test_all_surfaces_agree_and_reconciliation_never_restarts(self):
        for state in (None, 'intent', 'unknown', 'completed', 'reconciled'):
            for surface in ('cli', 'native'):
                with self.subTest(state=state, surface=surface), tempfile.TemporaryDirectory() as tmp:
                    with ManualJournal(str(Path(tmp).resolve() / 'journal')) as journal:
                        if state is not None:
                            record = dict(schema=1, operation_id='a' * 32, state='intent',
                                          started_at=NOW, target=TARGET, reason='invocation_not_confirmed')
                            if state == 'unknown':
                                record.update(state=state, reason='completion_unverified')
                            if state == 'completed':
                                record.update(state=state, reason='cli_success_and_replacement_observed',
                                              replacement=REPLACEMENT, finished_at=NOW)
                            journal.write(record)
                            if state == 'reconciled':
                                # Uses actual durable reconciliation; no invocation is supplied.
                                reconcile_operation(journal, inspect_target=lambda: TARGET,
                                                    alive=lambda _: False,
                                                    clock=lambda: (datetime.fromisoformat(NOW.replace('Z', '+00:00')) + timedelta(seconds=901)).isoformat().replace('+00:00', 'Z'))
                        console = object.__new__(ConsoleRestart)
                        console._active = False
                        prior = journal.read()
                        # gate(None) means read current record, so supply that test seam.
                        console.record = lambda: prior
                        allowed = state in (None, 'completed', 'reconciled')
                        self.assertEqual(console.gate(prior)[0], allowed)
                        invoke = Mock(return_value=0)
                        confirm = Mock(return_value=True)
                        events = []

                        def approval():
                            preview = next(e for e in events if e['kind'] == 'preview')
                            return {key: preview[key] for key in ('request_id', 'preview_digest')} | {'approved': True}

                        def execute():
                            if surface == 'cli':
                                return run_restart(journal, TARGET,
                                                   inspect_target=Mock(side_effect=[TARGET, REPLACEMENT]),
                                                   invoke=invoke, confirm=confirm, progress=lambda _: None,
                                                   clock=lambda: NOW)
                            return graphical_restart(journal=journal,
                                                     preflight=lambda: (TARGET, 'stamp'),
                                                     inspect_target=Mock(side_effect=[TARGET, REPLACEMENT]),
                                                     invoke=invoke, receive=approval,
                                                     owner=lambda: True, send=events.append,
                                                     monotonic=lambda: 1, wall_clock=lambda: 100)
                        if allowed:
                            self.assertEqual(execute()['state'], 'completed')
                            invoke.assert_called_once()
                        else:
                            with self.assertRaises(ValueError):
                                execute()
                            invoke.assert_not_called()
                            confirm.assert_not_called()
                            self.assertEqual(events, [])
                            self.assertEqual(journal.read(), prior)
