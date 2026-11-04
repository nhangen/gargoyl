import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_manual_restart import NOW, REPLACEMENT, TARGET

from gargoyl.gui_runtime import (
    control_monitor,
    export_evidence,
    graphical_restart,
    read_confirmation,
)
from gargoyl.manual_restart import (
    ManualJournal,
    read_operation,
    reconcile_operation,
    restart_gate_allows,
    run_restart,
)
from gargoyl.operator_console import ConsoleRestart

LATER = "2026-10-31T12:20:00Z"  # past RECONCILE_UNIDENTIFIED_SECONDS


class GraphicalRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name).resolve() / "journal")
        self.events = []

    def run_gui(
        self,
        journal,
        *,
        receive=None,
        preflight=None,
        owner=None,
        send=None,
        invoke=None,
        wall=None,
    ):
        def approval():
            preview = next(e for e in self.events if e["kind"] == "preview")
            return {
                key: preview[key] for key in ("request_id", "preview_digest")
            } | dict(approved=True)

        return graphical_restart(
            journal=journal,
            preflight=preflight or Mock(return_value=(TARGET, "stamp")),
            inspect_target=Mock(side_effect=[TARGET, REPLACEMENT]),
            invoke=invoke or Mock(return_value=0),
            receive=receive or approval,
            owner=owner or Mock(return_value=True),
            send=send or self.events.append,
            monotonic=lambda: 10,
            wall_clock=wall or (lambda: 100),
        )

    def test_one_bound_native_confirmation_reuses_shared_durable_journal(self):
        with ManualJournal(self.path) as journal:
            action = Mock(return_value=0)
            result = self.run_gui(journal, invoke=action)
            self.assertEqual(result["state"], "completed")
            action.assert_called_once()
            self.assertEqual(read_operation(self.path)["replacement"], REPLACEMENT)
        self.assertEqual(sum(e["kind"] == "preview" for e in self.events), 1)

    def test_cancel_forged_expired_or_wrong_owner_invokes_nothing(self):
        for variation in ("cancel", "request", "digest", "extra", "expired", "owner"):
            with self.subTest(variation=variation):
                self.events.clear()
                action = Mock()

                def reply():
                    item = next(e for e in self.events if e["kind"] == "preview")
                    result = dict(
                        request_id=item["request_id"],
                        preview_digest=item["preview_digest"],
                        approved=True,
                    )
                    if variation == "cancel":
                        result["approved"] = False
                    if variation == "request":
                        result["request_id"] = "old-request"
                    if variation == "digest":
                        result["preview_digest"] = "other"
                    if variation == "extra":
                        result["command"] = "restart"
                    return result

                with ManualJournal(self.path) as journal:
                    with self.assertRaises(ValueError):
                        self.run_gui(
                            journal,
                            invoke=action,
                            receive=reply,
                            wall=Mock(side_effect=[100, 200])
                            if variation == "expired"
                            else None,
                            owner=Mock(side_effect=[True, False])
                            if variation == "owner"
                            else None,
                        )
                    action.assert_not_called()
                    self.assertIsNone(journal.read())

    def test_changed_target_and_existing_unknown_gate_block_graphical_submission(self):
        with ManualJournal(self.path) as journal:
            action = Mock()
            with self.assertRaises(ValueError):
                self.run_gui(
                    journal,
                    invoke=action,
                    preflight=Mock(
                        side_effect=[(TARGET, "stamp"), (REPLACEMENT, "stamp")]
                    ),
                )
            action.assert_not_called()
            self.assertIsNone(journal.read())
            self.events.clear()
            with self.assertRaises(RuntimeError):
                self.run_gui(journal, invoke=Mock(side_effect=RuntimeError()))
            self.assertEqual(journal.read()["state"], "unknown")
        with ManualJournal(self.path) as journal:
            action = Mock()
            with self.assertRaises(ValueError):
                self.run_gui(journal, invoke=action)
            action.assert_not_called()

    def write_record(self, path, state):
        """Leave a real journal at `path` in `state` using only the public journal API."""
        with ManualJournal(path) as journal:
            with self.assertRaises(ValueError):  # unverified replacement -> unknown
                run_restart(
                    journal,
                    TARGET,
                    inspect_target=Mock(side_effect=[TARGET, TARGET]),
                    invoke=Mock(return_value=0),
                    confirm=Mock(return_value=True),
                    progress=lambda text: None,
                    clock=lambda: NOW,
                )
            if state == "reconciled":
                reconcile_operation(
                    journal,
                    inspect_target=Mock(return_value=TARGET),
                    alive=lambda child: False,
                    clock=lambda: LATER,
                )
            elif state == "intent":
                record = journal.read()
                del record["finished_at"]
                journal.write(
                    dict(record, state="intent", reason="invocation_not_confirmed")
                )
        self.assertEqual(read_operation(path)["state"], state)

    def test_reconciled_record_reopens_native_cli_and_console_gates_alike(self):
        def console(path):
            return ConsoleRestart(
                executable="/unused", directory=path, preflight=Mock(),
                inspect=Mock(), observe=Mock(),
            )

        for state in ("intent", "unknown"):
            with self.subTest(state=state):
                path = self.path + "-" + state
                self.write_record(path, state)
                self.assertFalse(restart_gate_allows(read_operation(path)))
                opened, reason = console(path).gate()
                self.assertFalse(opened)
                self.assertIn("Reconcile before another restart", reason)
                action = Mock()
                with ManualJournal(path) as journal:
                    with self.assertRaisesRegex(ValueError, "unresolved operation"):
                        self.run_gui(journal, invoke=action, preflight=Mock())
                    with self.assertRaises(ValueError):
                        run_restart(
                            journal, TARGET, inspect_target=Mock(), invoke=action,
                            confirm=Mock(return_value=True), progress=lambda text: None,
                        )
                action.assert_not_called()
                self.assertEqual(read_operation(path)["state"], state)

        self.write_record(self.path, "reconciled")
        self.assertTrue(restart_gate_allows(read_operation(self.path)))
        self.assertEqual(console(self.path).gate(), (True, None))
        with ManualJournal(self.path) as journal:
            self.assertEqual(self.run_gui(journal)["state"], "completed")
        self.write_record(self.path, "reconciled")
        with ManualJournal(self.path) as journal:
            record = run_restart(
                journal, TARGET, inspect_target=Mock(side_effect=[TARGET, REPLACEMENT]),
                invoke=Mock(return_value=0), confirm=Mock(return_value=True),
                progress=lambda text: None, clock=lambda: LATER,
            )
        self.assertEqual(record["state"], "completed")

    def test_broken_progress_after_approval_does_not_cancel_or_repeat(self):
        def deliver(value):
            if value["kind"] == "preview":
                self.events.append(value)
            else:
                raise BrokenPipeError()

        with ManualJournal(self.path) as journal:
            action = Mock(return_value=0)
            self.assertEqual(
                self.run_gui(journal, invoke=action, send=deliver)["state"], "completed"
            )
            action.assert_called_once()
            self.assertEqual(journal.read()["state"], "completed")

    def test_cli_and_native_attempts_share_one_lock(self):
        with ManualJournal(self.path):
            with self.assertRaises(BlockingIOError):
                ManualJournal(self.path)

    def test_pipe_eof_duplicate_and_oversized_approval_are_refused(self):
        for data in (b"", b"{}\n{}\n", b"x" * 4097):
            read, write = os.pipe()
            with os.fdopen(read, "rb", buffering=0) as stream:
                os.write(write, data)
                os.close(write)
                with self.assertRaises(ValueError):
                    read_confirmation(stream, timeout=0.1)
        read, write = os.pipe()
        with os.fdopen(read, "rb", buffering=0) as stream:
            os.write(write, b'{"approved":false}\n')
            os.close(write)
            self.assertEqual(
                read_confirmation(stream, timeout=0.1), {"approved": False}
            )

    def test_worker_finishes_fixture_after_gui_pipe_closes(self):
        # Actual child process + pipes, synthetic action only. No native auth or provider.
        source = str(Path(__file__).resolve().parents[1])
        script = """import sys,json,time
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[1]+'/tests')
from gargoyl.gui_runtime import graphical_restart,emit,read_confirmation
from gargoyl.manual_restart import ManualJournal
from test_manual_restart import TARGET,REPLACEMENT
with ManualJournal(sys.argv[2]) as journal:
 count=[0]
 def inspect():
  count[0]+=1
  return TARGET if count[0]==1 else REPLACEMENT
 def invoke():
  time.sleep(.15)
  return 0
 graphical_restart(journal=journal,preflight=lambda:(TARGET,'stamp'),inspect_target=inspect,
 invoke=invoke,receive=lambda:read_confirmation(sys.stdin.buffer),owner=lambda:True,send=emit)
"""
        child = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", script, source, self.path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        preview = json.loads(child.stdout.readline())
        child.stdin.write(
            json.dumps(
                dict(
                    request_id=preview["request_id"],
                    preview_digest=preview["preview_digest"],
                    approved=True,
                )
            ).encode()
            + b"\n"
        )
        child.stdin.flush()
        child.stdin.close()
        child.stdout.close()
        self.assertEqual(child.wait(timeout=5), 0)
        self.assertEqual(read_operation(self.path)["state"], "completed")


class MonitorControlTests(unittest.TestCase):
    def test_controls_only_fixed_existing_gargoyl_job(self):
        runner = Mock(side_effect=[Mock(returncode=0), Mock(returncode=0)])
        with patch("gargoyl.gui_runtime.console_owner", return_value=True):
            control_monitor(
                "stop-monitor",
                run=runner,
                validate=lambda: Path("/synthetic/monitor.plist"),
            )
        self.assertEqual(
            runner.call_args_list[1].args[0],
            ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/dev.gargoyl.monitor"],
        )
        for call in runner.call_args_list:
            self.assertNotIn("io.darkbloom", str(call))

    def test_export_rebuilds_allowlisted_evidence_and_drops_supplied_html(self):
        from test_diagnostic_confidence import NOW, sample

        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = json.dumps(
            dict(
                evaluated_at=NOW,
                snapshots=[sample("daemon_state", "running", "daemon")],
                dashboard="PRIVATE_PAYLOAD",
                credentials="PRIVATE_PAYLOAD",
            )
        ).encode()
        with patch(
            "gargoyl.gui_runtime.http.client.HTTPConnection", return_value=connection
        ):
            result = export_evidence()
        self.assertNotIn("PRIVATE_PAYLOAD", json.dumps(result))
        self.assertFalse(result["automatic_repair_enabled"])
        connection.request.assert_called_once_with("GET", "/report.json")
        connection.close.assert_called_once()
        response.read.return_value = b"x" * 524289
        with patch(
            "gargoyl.gui_runtime.http.client.HTTPConnection", return_value=connection
        ):
            with self.assertRaises(ValueError):
                export_evidence()

    def test_unknown_monitor_state_never_retries_or_bootstraps(self):
        runner = Mock(return_value=Mock(returncode=1))
        with (
            patch("gargoyl.gui_runtime.console_owner", return_value=True),
            self.assertRaises(ValueError),
        ):
            control_monitor(
                "start-monitor",
                run=runner,
                validate=lambda: Path("/synthetic/monitor.plist"),
            )
        self.assertEqual(runner.call_count, 1)

    def test_native_view_plumbs_preview_environment(self):
        from gargoyl.gui_runtime import native_view

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("gargoyl.gui_runtime.export_evidence", side_effect=OSError),
            patch("socket.gethostname", return_value="MBP-2026.local"),
        ):
            tmp_path = Path(tmp).resolve()
            with (
                patch("gargoyl.gui_runtime.owner_home", return_value=tmp_path),
                patch.dict(os.environ, {"GARGOYL_PREVIEW": "1"}),
            ):
                view_result = native_view("fleet")
                self.assertEqual(view_result["kind"], "view")
                self.assertEqual(view_result["view"], "fleet")
                self.assertIn("Read-only preview mode", view_result["html"])
                self.assertNotIn("Normal operator application is not running", view_result["html"])

            with (
                patch("gargoyl.gui_runtime.owner_home", return_value=tmp_path),
                patch.dict(os.environ, {}, clear=True),
            ):
                normal_result = native_view("fleet")
                self.assertNotIn("Read-only preview mode", normal_result["html"])
