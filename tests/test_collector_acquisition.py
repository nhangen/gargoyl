"""Execute only this suite's locally authored synthetic POSIX producer."""
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_collector_adapters import DOCTOR_TEXT

from gargoyl.collector_acquisition import BoundedAcquirer
from gargoyl.telemetry import PolicyError

STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
NOW = "2026-01-01T00:00:00Z"

FIXTURE = '''import os, signal, sys, time
mode = os.environ.get("MODE", "good")
if mode == "args":
    assert sys.argv[1:] == ["status"]
    assert "SYNTHETIC_PARENT_SECRET" not in os.environ
    assert sys.stdin.read() == ""
if mode == "hang":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True: time.sleep(.01)
if mode == "child":
    pid = os.fork()
    if pid == 0:
        while True: time.sleep(.01)
    def stop(sig, frame):
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    while True: time.sleep(.01)
if mode == "stdout_flood":
    while True: os.write(1, b"synthetic-secret" * 4096)
if mode == "stderr_flood":
    while True: os.write(2, b"synthetic-secret" * 4096)
if mode == "combined":
    os.write(1, b"x" * 40000)
    os.write(2, b"y" * 40000)
    sys.exit(0)
if mode == "exact":
    message = "Status: ● Running\\n".encode()
    os.write(1, message)
    os.write(2, b"x" * (int(os.environ["CAP"]) - len(message)))
    sys.exit(0)
if mode == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
if mode == "invalid":
    os.write(1, b"\\xffsynthetic-secret")
    sys.exit(0)
if mode == "empty":
    sys.exit(0)
if mode == "nonzero":
    os.write(1, "Status: ● Running\\n".encode())
    sys.exit(9)
if mode == "stderr":
    os.write(2, b"synthetic-secret")
if sys.argv[1] == "doctor":
    print(DOCTOR_REPORT, end="")
else:
    print("Status: ● Running — serving synthetic-secret")
'''


@unittest.skipUnless(os.name == "posix", "POSIX process groups required")
class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executable = self.root / "synthetic-producer"
        fd = os.open(self.executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "w") as stream:
            stream.write(f"#!{sys.executable}\nDOCTOR_REPORT = {DOCTOR_TEXT!r}\n" + FIXTURE)
        self.stop = threading.Event()

    def acquirer(self, mode="good", **overrides):
        options = dict(environment={"MODE": mode}, cwd=str(self.root),
                       wall_clock=lambda: NOW, monotonic_clock=time.monotonic,
                       total_timeout_seconds=.8, cleanup_grace_seconds=.3)
        options.update(overrides)
        return BoundedAcquirer(str(self.executable), **options)

    def assert_failure(self, result, code):
        self.assertEqual(result.result.readings, {})
        self.assertEqual(result.result.errors, (code,))
        self.assertNotIn("synthetic-secret", repr(result))
        self.assertNotIn(str(self.root), repr(result))

    def test_total_budget_is_read_only_validated_configuration(self):
        acquirer = self.acquirer(total_timeout_seconds=2, cleanup_grace_seconds=.5)
        self.assertEqual(acquirer.total_timeout_seconds, 2)
        with self.assertRaises(AttributeError):
            acquirer.total_timeout_seconds = 99
        self.assertEqual(acquirer.total_timeout_seconds, 2)

    def test_fixed_arguments_explicit_environment_and_private_result(self):
        with patch.dict(os.environ, {"SYNTHETIC_PARENT_SECRET": "synthetic-secret"}):
            result = self.acquirer("args").acquire(STATUS, stop_event=self.stop)
        self.assertTrue(result.cleanup_complete)
        self.assertEqual(result.observed_at, NOW)
        self.assertEqual(result.result.readings["daemon_state"]["timestamp"], NOW)
        self.assertNotIn("synthetic-secret", repr(result))
        doctor = self.acquirer().acquire(DOCTOR, stop_event=self.stop)
        self.assertEqual(doctor.result.readings["doctor_state"]["value"], "passed")
        self.assertTrue(doctor.cleanup_complete)

    def test_execution_failure_mapping_and_no_partial_success(self):
        for mode, code in (("nonzero", "unavailable"), ("signal", "unavailable"),
                           ("stdout_flood", "unavailable"), ("stderr_flood", "unavailable"),
                           ("combined", "unavailable"), ("invalid", "invalid_state"),
                           ("empty", "invalid_state")):
            with self.subTest(mode=mode):
                result = self.acquirer(mode).acquire(STATUS, stop_event=self.stop)
                self.assert_failure(result, code)
                self.assertTrue(result.cleanup_complete)
        self.assertFalse(self.acquirer("stderr").acquire(STATUS, stop_event=self.stop).result.errors)

    def test_combined_budget_boundary_and_environment_copy(self):
        environment = {"MODE": "exact", "CAP": "256"}
        acquirer = self.acquirer(environment=environment, max_output_bytes=256)
        environment["CAP"] = "257"
        result = acquirer.acquire(STATUS, stop_event=self.stop)
        self.assertEqual(result.result.errors, ())
        self.assertTrue(result.cleanup_complete)
        self.assert_failure(self.acquirer(environment=environment, max_output_bytes=256).acquire(
            STATUS, stop_event=self.stop), "unavailable")

    def test_silent_hang_is_killed_reaped_within_total_budget(self):
        start = time.monotonic()
        result = self.acquirer("hang").acquire(STATUS, stop_event=self.stop)
        self.assert_failure(result, "timeout")
        self.assertTrue(result.cleanup_complete)
        self.assertLess(time.monotonic() - start, 1.5)

    def test_child_held_pipes_are_terminated_with_group(self):
        start = time.monotonic()
        result = self.acquirer("child").acquire(STATUS, stop_event=self.stop)
        self.assert_failure(result, "timeout")
        self.assertTrue(result.cleanup_complete)
        self.assertLess(time.monotonic() - start, 1.5)

    def test_missing_and_permission_launch_failures(self):
        self.executable.unlink()
        self.assert_failure(self.acquirer().acquire(STATUS, stop_event=self.stop), "unavailable")
        self.executable.write_text("synthetic nonexecutable file")
        self.assert_failure(self.acquirer().acquire(STATUS, stop_event=self.stop), "permission_denied")

    def test_cancel_before_launch_and_during_execution(self):
        self.stop.set()
        with patch("gargoyl.collector_acquisition.subprocess.Popen") as launch:
            self.assert_failure(self.acquirer().acquire(STATUS, stop_event=self.stop), "unavailable")
            launch.assert_not_called()
        self.stop.clear()
        timer = threading.Timer(.1, self.stop.set)
        timer.start()
        try:
            result = self.acquirer("hang").acquire(STATUS, stop_event=self.stop)
            self.assert_failure(result, "unavailable")
            self.assertTrue(result.cleanup_complete)
        finally:
            timer.cancel()
            timer.join()

    def test_config_validation_never_launches(self):
        cases = ({"total_timeout_seconds": 10**1000},
                 {"cleanup_grace_seconds": 10**1000},
                 {"max_output_bytes": 10**1000},
                 {"total_timeout_seconds": True}, {"total_timeout_seconds": float("inf")},
                 {"total_timeout_seconds": 31}, {"cleanup_grace_seconds": 0},
                 {"cleanup_grace_seconds": .8}, {"max_output_bytes": True},
                 {"max_output_bytes": 65537}, {"environment": {"BAD=KEY": "secret"}},
                 {"environment": {"KEY": "x" * 65537}}, {"cwd": "relative"},
                 {"wall_clock": None}, {"monotonic_clock": None})
        with patch("gargoyl.collector_acquisition.subprocess.Popen") as launch:
            for options in cases:
                with self.assertRaises(PolicyError):
                    self.acquirer(**options)
            with self.assertRaises(PolicyError):
                self.acquirer().acquire("arbitrary-command", stop_event=self.stop)
            launch.assert_not_called()

    def test_invalid_and_stalled_clocks_fail_safely(self):
        with patch("gargoyl.collector_acquisition.subprocess.Popen") as launch:
            for value in (-1, True, float("nan"), float("inf"), 2**54):
                with self.assertRaises(PolicyError):
                    self.acquirer(monotonic_clock=lambda: value).acquire(STATUS, stop_event=self.stop)
            with self.assertRaises(PolicyError):
                self.acquirer(wall_clock=lambda: "synthetic-secret").acquire(STATUS, stop_event=self.stop)
            launch.assert_not_called()
        # Frozen injected clocks cannot defeat the independent real elapsed guard.
        start = time.monotonic()
        # Leave more real cleanup slack for loaded CI while retaining the frozen
        # injected-clock proof, strict cleanup assertion and finite elapsed bound.
        result = self.acquirer("hang", monotonic_clock=lambda: 0,
                               total_timeout_seconds=1.5,
                               cleanup_grace_seconds=.8).acquire(STATUS, stop_event=self.stop)
        self.assert_failure(result, "timeout")
        self.assertTrue(result.cleanup_complete)
        self.assertLess(time.monotonic() - start, 2.2)
        clock = iter((10, 9))
        result = self.acquirer("hang", monotonic_clock=lambda: next(clock)).acquire(STATUS, stop_event=self.stop)
        self.assert_failure(result, "unavailable")
        self.assertTrue(result.cleanup_complete)

    def test_unconfirmed_group_cleanup_halts_further_acquisition(self):
        acquirer = self.acquirer()
        # Inject only failed cleanup verification; the real child still exits/reaps.
        with patch("gargoyl.collector_acquisition._group_exists", return_value=True):
            result = acquirer.acquire(STATUS, stop_event=self.stop)
        self.assertFalse(result.cleanup_complete)
        self.assert_failure(result, "unavailable")
        with self.assertRaises(PolicyError):
            acquirer.acquire(STATUS, stop_event=self.stop)

    def test_wall_start_and_completion_are_distinct(self):
        times = iter((NOW, "2026-01-01T00:00:03Z"))
        result = self.acquirer(wall_clock=lambda: next(times)).acquire(STATUS, stop_event=self.stop)
        self.assertEqual(result.observed_at, NOW)
        self.assertEqual(result.completed_at, "2026-01-01T00:00:03Z")
        self.assertEqual(result.result.readings["daemon_state"]["timestamp"], NOW)
