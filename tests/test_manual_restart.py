import copy
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gargoyl.cli import main
from gargoyl.manual_restart import (
    ManualJournal,
    installation_preflight,
    invoke_restart,
    read_operation,
    run_restart,
)

NOW = "2026-10-31T12:00:00Z"
TARGET = dict(
    process=dict(pid=123, born_us=1793447900000000, owner_uid=os.getuid()),
    version="0.10.6",
    observed_at=NOW,
)
REPLACEMENT = dict(
    process=dict(pid=124, born_us=1793448000000000, owner_uid=os.getuid()),
    version="0.10.6",
    observed_at=NOW,
)


class ManualRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name).resolve() / "journal")

    def run_operation(self, journal, *, invoke=None, inspect=None, confirm=None):
        return run_restart(
            journal,
            TARGET,
            inspect_target=inspect or Mock(side_effect=[TARGET, REPLACEMENT]),
            invoke=invoke or Mock(return_value=0),
            confirm=confirm or Mock(return_value=True),
            progress=lambda text: None,
            clock=lambda: NOW,
        )

    def test_confirm_and_fsync_intent_precede_one_invocation_and_verified_result(self):
        with ManualJournal(self.path) as journal:

            def invoke():
                record = read_operation(self.path)
                self.assertEqual(record["state"], "intent")
                self.assertEqual(record["target"], TARGET)
                return 0

            result = self.run_operation(journal, invoke=Mock(side_effect=invoke))
            self.assertEqual(result["state"], "completed")
            self.assertEqual(read_operation(self.path)["replacement"], REPLACEMENT)
        self.assertEqual(Path(self.path).stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            (Path(self.path) / "operation.json").stat().st_mode & 0o777, 0o600
        )

    def test_no_confirmation_or_changed_target_never_creates_intent_or_invokes(self):
        for confirm, inspector in (
            (False, Mock()),
            (True, Mock(return_value=REPLACEMENT)),
        ):
            with ManualJournal(self.path) as journal:
                action = Mock()
                with self.assertRaises(ValueError):
                    self.run_operation(
                        journal,
                        invoke=action,
                        confirm=Mock(return_value=confirm),
                        inspect=inspector,
                    )
                action.assert_not_called()
                self.assertIsNone(journal.read())

    def test_double_submission_is_locked_and_unresolved_intent_blocks_reopen(self):
        with ManualJournal(self.path) as journal:
            with self.assertRaises(BlockingIOError):
                ManualJournal(self.path)

            def crash():
                raise KeyboardInterrupt()

            with self.assertRaises(KeyboardInterrupt):
                self.run_operation(journal, invoke=Mock(side_effect=crash))
        with ManualJournal(self.path) as journal:
            action = Mock()
            with self.assertRaises(ValueError):
                self.run_operation(journal, invoke=action)
            action.assert_not_called()
        self.assertEqual(read_operation(self.path)["state"], "unknown")

    def test_nonzero_or_unverified_replacement_never_succeeds_and_never_retries(self):
        for code, replacement in ((1, REPLACEMENT), (0, TARGET)):
            directory = self.path + str(code)
            with ManualJournal(directory) as journal:
                action = Mock(return_value=code)
                with self.assertRaises(ValueError):
                    self.run_operation(
                        journal,
                        invoke=action,
                        inspect=Mock(side_effect=[TARGET, replacement]),
                    )
                self.assertEqual(action.call_count, 1)
                self.assertEqual(journal.read()["state"], "unknown")

    def test_journal_write_failure_prevents_invocation_and_readonly_reconcile_creates_nothing(
        self,
    ):
        self.assertIsNone(read_operation(self.path))
        self.assertFalse(Path(self.path).exists())
        with ManualJournal(self.path) as journal:
            action = Mock()
            with patch("os.fsync", side_effect=OSError()), self.assertRaises(OSError):
                self.run_operation(journal, invoke=action)
            action.assert_not_called()

    def test_symlinks_modes_and_untrusted_record_fields_fail_closed(self):
        with ManualJournal(self.path) as journal:
            self.run_operation(journal)
        p = Path(self.path) / "operation.json"
        p.chmod(0o644)
        with self.assertRaises(ValueError):
            read_operation(self.path)
        p.chmod(0o600)
        data = json.loads(p.read_text())
        data["secret"] = "NEVER_PRINT"
        p.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            read_operation(self.path)
        p.unlink()
        p.symlink_to(Path(self.temp.name) / "elsewhere")
        with self.assertRaises(OSError):
            read_operation(self.path)

    def test_fixed_no_force_command_discards_output_and_termination_is_cli_only(self):
        child = Mock()
        child.poll.side_effect = [None]
        child.wait.side_effect = subprocess.TimeoutExpired("fixture", 2)
        with patch(
            "gargoyl.manual_restart.subprocess.Popen", return_value=child
        ) as spawn:
            stop = threading.Event()
            stop.set()
            with self.assertRaises(RuntimeError):
                invoke_restart(
                    "/synthetic/provider", interrupted=stop, progress=lambda x: None
                )
        self.assertEqual(
            spawn.call_args.args[0],
            [
                "/synthetic/provider",
                "restart",
                "--timeout",
                "600",
                "--startup-timeout",
                "180",
            ],
        )
        self.assertEqual(spawn.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(child.send_signal.call_count, 1)

    def test_cli_requires_interactive_terminal_never_calls_provider_on_pipe(self):
        with (
            patch("sys.stdin.isatty", return_value=False),
            patch("gargoyl.operator_tools.installation_preflight") as preflight,
        ):
            self.assertEqual(
                main(
                    [
                        "tools",
                        "restart",
                        "--input",
                        "/synthetic/state",
                        "--owner-uid",
                        str(os.getuid()),
                        "--provider-executable",
                        "/synthetic/provider",
                    ]
                ),
                1,
            )
            preflight.assert_not_called()

    def test_clock_and_new_timestamp_cannot_retarget_confirmation(self):
        newer = copy.deepcopy(TARGET)
        newer["observed_at"] = "2026-10-31T12:00:01Z"
        with ManualJournal(self.path) as journal:
            self.assertEqual(
                self.run_operation(
                    journal, inspect=Mock(side_effect=[newer, REPLACEMENT])
                )["state"],
                "completed",
            )


class InstallationProfileTests(unittest.TestCase):
    @unittest.skipUnless(os.getuid() == 501, "native pilot ownership fixture")
    def test_no_custom_config_cluster_or_new_watchdog_activation(self):
        import plistlib
        from contextlib import ExitStack

        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            executable = home / ".darkbloom/Darkbloom.app/Contents/MacOS/darkbloom"
            executable.parent.mkdir(parents=True)
            executable.write_text("synthetic not executed")
            executable.chmod(0o700)
            plist = home / "Library/LaunchAgents/io.darkbloom.provider.plist"
            plist.parent.mkdir(parents=True)

            def write(extra):
                plist.write_bytes(
                    plistlib.dumps(
                        dict(
                            Label="io.darkbloom.provider",
                            ProgramArguments=[
                                str(executable),
                                "start",
                                "--foreground",
                                "--coordinator-url",
                                "https://synthetic.invalid",
                                *extra,
                            ],
                        )
                    )
                )

            with ExitStack() as stack:
                stack.enter_context(
                    patch(
                        "gargoyl.manual_restart.subprocess.run",
                        return_value=Mock(returncode=0, stdout=b"0.10.6\n", stderr=b""),
                    )
                )
                stack.enter_context(
                    patch("gargoyl.manual_restart.owner_home", return_value=home)
                )
                stack.enter_context(patch("sys.platform", "darwin"))
                stack.enter_context(patch("os.getuid", return_value=501))
                stack.enter_context(
                    patch("os.uname", return_value=Mock(nodename="MBP-2026.local"))
                )
                stack.enter_context(
                    patch("gargoyl.manual_restart.observed_target", return_value=TARGET)
                )
                # fstat owner is the actual fixture owner; normal MBP pilot is501.
                for flags in (
                    ["--config", "private"],
                    ["--cluster-member"],
                    ["--local-endpoint"],
                ):
                    write(flags)
                    with self.assertRaises(ValueError):
                        installation_preflight(
                            str(executable),
                            str(home / ".darkbloom/daemon-state.json"),
                            501,
                        )
                write([])
                with (
                    patch(
                        "gargoyl.manual_restart._job_running",
                        side_effect=[123, ValueError("existing_watchdog_required")],
                    ),
                    self.assertRaises(ValueError),
                ):
                    installation_preflight(
                        str(executable), str(home / ".darkbloom/daemon-state.json"), 501
                    )
                with patch(
                    "gargoyl.manual_restart._job_running", side_effect=[123, 999]
                ):
                    self.assertEqual(
                        installation_preflight(
                            str(executable),
                            str(home / ".darkbloom/daemon-state.json"),
                            501,
                        )[0],
                        TARGET,
                    )
