import contextlib
import io
import json
import math
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from gargoyl.foreground import ForegroundConfig, main, run_configured, run_foreground
from gargoyl.security import CollectionIdentity, SpoolCipher
from gargoyl.telemetry import PolicyError

HOST = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"
STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
NOW = "2026-01-01T00:00:00Z"


class Clock:
    now = 0.0

    def read(self):
        return self.now


class Stop:
    def __init__(self, clock, *, at=61):
        self.clock, self.at = clock, at
        self.stopped = False
        self.waits = []

    def is_set(self):
        return self.stopped or self.clock.now >= self.at

    def wait(self, seconds):
        self.waits.append(seconds)
        self.clock.now += seconds
        return self.is_set()


class Acquisition:
    total_timeout_seconds = 5.0

    def __init__(self, clock, duration=0):
        self.clock, self.duration = clock, duration
        self.calls = []
        self.closed = False
        self.cleanup_complete = True

    def acquire(self, kind, *, stop_event):
        self.calls.append((kind, self.clock.now, threading.get_ident()))
        self.clock.now += self.duration
        return SimpleNamespace(
            source_kind=kind,
            observed_at=NOW,
            completed_at=NOW,
            result=SimpleNamespace(readings={}, errors=()),
            cleanup_complete=self.cleanup_complete,
        )

    def close(self):
        self.closed = True


class Transport:
    total_timeout_seconds = 10.0
    closed = False

    def send(self, snapshot):
        return False

    def close(self):
        self.closed = True


class Runtime:
    ttl = 60

    def __init__(self, clock, transport=None):
        self.clock = clock
        self.identity = CollectionIdentity(HOST)
        self.transport = transport or Transport()
        self.collected = []
        self.delivered = []
        self.delivery_duration = 0
        self.delivery_result = "idle"

    def collect_acquired(self, results):
        self.collected.append((self.clock.now, dict(results), threading.get_ident()))
        return {"synthetic": "persisted"}

    def deliver_tick(self):
        self.delivered.append(self.clock.now)
        self.clock.now += self.delivery_duration
        return self.delivery_result


class ForegroundTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.stop = Stop(self.clock)
        self.acquisition = Acquisition(self.clock)
        self.runtime = Runtime(self.clock)
        self.config = ForegroundConfig(HOST, (STATUS,))

    def run_loop(self):
        return run_foreground(
            self.config,
            runtime=self.runtime,
            acquisition=self.acquisition,
            monotonic_clock=self.clock.read,
            stop_event=self.stop,
        )

    def test_cadence_and_borrowed_resources_stay_single_owner(self):
        result = self.run_loop()
        self.assertEqual(result.status, "stopped")
        self.assertEqual(result.collections, 3)
        self.assertEqual([item[0] for item in self.runtime.collected], [0, 30, 60])
        self.assertTrue(
            all(item[2] == threading.get_ident() for item in self.runtime.collected)
        )
        self.assertTrue(
            all(item[2] == threading.get_ident() for item in self.acquisition.calls)
        )
        self.assertTrue(all(0 < delay <= 1 for delay in self.stop.waits))
        self.assertFalse(self.acquisition.closed)
        self.assertFalse(self.runtime.transport.closed)

    def test_overrun_skips_slots_without_catchup_burst(self):
        self.config = ForegroundConfig(HOST, (STATUS, DOCTOR), 3)
        self.acquisition.duration = 2
        self.runtime.delivery_duration = 4
        self.runtime.delivery_result = "retry"
        self.stop.at = 18
        result = self.run_loop()
        self.assertEqual([item[0] for item in self.runtime.collected], [4, 13])
        self.assertEqual([item[1] for item in self.acquisition.calls], [0, 2, 9, 11])
        self.assertEqual(result.collections, 2)
        self.assertEqual(result.retries, 2)
        self.assertEqual(self.stop.waits, [1, 1])

    def test_pre_stopped_does_no_work(self):
        self.stop.stopped = True
        result = self.run_loop()
        self.assertEqual(result.collections, 0)
        self.assertEqual(self.acquisition.calls, [])
        self.assertEqual(self.runtime.delivered, [])

    def test_stop_after_acquisition_does_not_publish_fresh_heartbeat(self):
        original = self.acquisition.acquire

        def acquire(kind, *, stop_event):
            result = original(kind, stop_event=stop_event)
            self.stop.stopped = True
            return result

        self.acquisition.acquire = acquire
        self.config = ForegroundConfig(HOST, (STATUS, DOCTOR))
        result = self.run_loop()
        self.assertEqual(result.status, "stopped")
        self.assertEqual(len(self.acquisition.calls), 1)
        self.assertEqual(self.runtime.collected, [])
        self.assertEqual(self.runtime.delivered, [])

    def test_incomplete_cleanup_overrides_stop_and_prevents_persistence(self):
        self.acquisition.cleanup_complete = False
        self.acquisition.duration = 1
        self.stop.at = 0.5
        result = self.run_loop()
        self.assertEqual(result.status, "incomplete_shutdown")
        self.assertEqual(result.reason, "acquisition_cleanup_incomplete")
        self.assertEqual(self.runtime.collected, [])
        self.assertEqual(self.runtime.delivered, [])

    def test_unexpected_acquisition_failure_does_not_claim_cleanup(self):
        self.acquisition.acquire = Mock(
            side_effect=RuntimeError("synthetic-private-detail")
        )
        result = self.run_loop()
        self.assertEqual(result.status, "incomplete_shutdown")
        self.assertNotIn("synthetic-private-detail", repr(result))
        self.assertEqual(self.runtime.collected, [])

    def test_runtime_failures_stop_with_safe_codes(self):
        for operation, reason in (
            ("collect_acquired", "collection_failed"),
            ("deliver_tick", "delivery_state_failed"),
        ):
            with self.subTest(operation=operation):
                self.runtime = Runtime(self.clock)
                setattr(
                    self.runtime,
                    operation,
                    Mock(side_effect=OSError("synthetic-private-detail")),
                )
                result = self.run_loop()
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.reason, reason)
                self.assertNotIn("synthetic-private-detail", repr(result))

    def test_huge_dependency_budgets_raise_policy_errors_before_work(self):
        for target in (self.acquisition, self.runtime.transport):
            original = target.total_timeout_seconds
            target.total_timeout_seconds = 10**400
            with self.assertRaises(PolicyError) as caught:
                self.run_loop()
            self.assertEqual(
                str(caught.exception),
                "invalid foreground configuration or dependencies",
            )
            target.total_timeout_seconds = original
        self.assertEqual(self.acquisition.calls, [])
        self.assertEqual(self.runtime.collected, [])

    def test_acquisition_results_pass_through_without_redating(self):
        result = SimpleNamespace(
            source_kind=STATUS,
            observed_at="2025-12-31T23:59:59Z",
            completed_at=NOW,
            result=SimpleNamespace(readings={}, errors=("timeout",)),
            cleanup_complete=True,
        )
        self.acquisition.acquire = Mock(return_value=result)
        self.stop.at = 1
        outcome = self.run_loop()
        self.assertEqual(outcome.collections, 1)
        self.assertIs(self.runtime.collected[0][1][STATUS], result)
        self.assertEqual(result.observed_at, "2025-12-31T23:59:59Z")

    def test_invalid_runtime_results_and_wait_errors_fail_safely(self):
        self.runtime.collect_acquired = Mock(return_value=None)
        self.assertEqual(self.run_loop().reason, "invalid_collection_outcome")
        self.runtime = Runtime(self.clock)
        self.runtime.delivery_result = "synthetic-private-detail"
        result = self.run_loop()
        self.assertEqual(result.reason, "invalid_delivery_outcome")
        self.assertNotIn("synthetic-private-detail", repr(result))
        self.runtime = Runtime(self.clock)
        self.stop.wait = Mock(side_effect=OSError("synthetic-private-detail"))
        self.assertEqual(self.run_loop().reason, "wait_failed")

    def test_stop_after_bounded_delivery(self):
        self.runtime.delivery_duration = 10
        self.runtime.delivery_result = "sent"
        self.stop.at = 1
        result = self.run_loop()
        self.assertEqual(result.status, "stopped")
        self.assertEqual(result.deliveries, 1)
        self.assertEqual(self.clock.now, 10)
        self.assertEqual(self.stop.waits, [])

    def test_bad_monotonic_clocks_fail_without_spinning(self):
        for values in ((float("nan"),), (-1,), (True,), (10, 9)):
            with self.subTest(values=values):
                values_iter = iter(values)
                result = run_foreground(
                    self.config,
                    runtime=self.runtime,
                    acquisition=self.acquisition,
                    monotonic_clock=lambda: next(values_iter),
                    stop_event=self.stop,
                )
                self.assertEqual(result.reason, "invalid_monotonic_clock")
        self.assertEqual(self.acquisition.calls, [])

    def test_require_explicit_valid_total_budgets_and_fixed_ttl(self):
        for value in (None, 0, -1, True, math.inf, math.nan):
            with self.subTest(value=value):
                self.acquisition.total_timeout_seconds = value
                with self.assertRaises(PolicyError):
                    self.run_loop()
        self.acquisition.total_timeout_seconds = 5
        self.runtime.transport.total_timeout_seconds = 31
        with self.assertRaises(PolicyError):
            self.run_loop()
        self.runtime.transport.total_timeout_seconds = 10
        self.runtime.ttl = 30
        with self.assertRaises(PolicyError):
            self.run_loop()
        self.assertEqual(self.acquisition.calls, [])


class ConfigurationTests(unittest.TestCase):
    def mapping(self):
        return {
            "version": 1,
            "host_id": HOST,
            "sources": [STATUS],
            "interval_seconds": 30,
        }

    def test_strict_non_secret_schema(self):
        self.assertEqual(
            ForegroundConfig.from_mapping(self.mapping()),
            ForegroundConfig(HOST, (STATUS,)),
        )
        for key, value in (
            ("version", True),
            ("host_id", "synthetic-hostname"),
            ("sources", []),
            ("sources", [STATUS, STATUS]),
            ("sources", ["arbitrary-command"]),
            ("interval_seconds", 0),
            ("interval_seconds", True),
            ("interval_seconds", 61),
            ("ttl", 60),
            ("key", "synthetic-private-detail"),
            ("executable", "synthetic-private-path"),
        ):
            data = self.mapping()
            data[key] = value
            with self.assertRaises(PolicyError) as caught:
                ForegroundConfig.from_mapping(data)
            self.assertNotIn("synthetic-private", str(caught.exception))

    def test_huge_integer_configuration_and_cli_are_rejected_safely(self):
        data = self.mapping()
        data["interval_seconds"] = 10**400
        payload = json.dumps(data)
        self.assertLess(len(payload), 4096)
        with self.assertRaises(PolicyError) as caught:
            ForegroundConfig.from_mapping(data)
        self.assertEqual(
            str(caught.exception), "invalid foreground configuration or dependencies"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(payload)
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(["--check-config", str(path)]), 2)
            self.assertEqual(
                output.getvalue(), "Foreground configuration unavailable or invalid.\n"
            )

    def test_validation_only_cli_never_constructs_runtime_or_echoes_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            cases = (
                (json.dumps(self.mapping()).encode(), 0),
                (b'{"key":"synthetic-private-detail"}', 2),
                (b'{"version":1,"version":1}', 2),
                (b" " * 4097, 2),
                (b"\xff", 2),
            )
            for payload, expected in cases:
                path.write_bytes(payload)
                output = io.StringIO()
                with (
                    patch("gargoyl.foreground.CollectorRuntime") as runtime,
                    patch("gargoyl.foreground.EncryptedHistory") as history,
                ):
                    with (
                        contextlib.redirect_stdout(output),
                        contextlib.redirect_stderr(output),
                    ):
                        self.assertEqual(main(["--check-config", str(path)]), expected)
                    runtime.assert_not_called()
                    history.assert_not_called()
                self.assertNotIn("synthetic-private", output.getvalue())
                self.assertNotIn(str(path), output.getvalue())


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.stop = Stop(self.clock, at=1)
        self.acquisition = Acquisition(self.clock)
        self.identity = CollectionIdentity(HOST)
        self.transport = Transport()
        self.arguments = dict(
            identity=self.identity,
            cipher=SpoolCipher(self.identity, b"x" * 32),
            transport=self.transport,
            acquisition=self.acquisition,
            spool_directory="unused-synthetic-directory",
            wall_clock=lambda: NOW,
            monotonic_clock=self.clock.read,
            stop_event=self.stop,
        )
        self.config = ForegroundConfig(HOST, (STATUS,))

    def test_owned_history_closed_after_work_and_borrowed_objects_preserved(self):
        runtime = Runtime(self.clock, self.transport)
        events = []
        original = runtime.collect_acquired

        def collect(results):
            events.append("collect")
            return original(results)

        runtime.collect_acquired = collect
        with (
            patch("gargoyl.foreground.EncryptedHistory") as history,
            patch("gargoyl.foreground.CollectorRuntime", return_value=runtime),
        ):
            history.return_value.close.side_effect = lambda: events.append("close")
            result = run_configured(self.config, **self.arguments)
            history.return_value.close.assert_called_once()
        self.assertEqual(result.status, "stopped")
        self.assertEqual(events, ["collect", "close"])
        self.assertFalse(self.acquisition.closed)
        self.assertFalse(self.transport.closed)

    def test_invalid_identity_and_missing_budget_fail_before_storage(self):
        self.arguments["identity"] = CollectionIdentity(OTHER)
        with patch("gargoyl.foreground.EncryptedHistory") as history:
            with self.assertRaises(PolicyError):
                run_configured(self.config, **self.arguments)
            history.assert_not_called()
        self.arguments["identity"] = self.identity
        self.transport.total_timeout_seconds = None
        with patch("gargoyl.foreground.EncryptedHistory") as history:
            with self.assertRaises(PolicyError):
                run_configured(self.config, **self.arguments)
            history.assert_not_called()

    def test_startup_and_shutdown_errors_are_safe(self):
        with (
            patch("gargoyl.foreground.CollectorRuntime"),
            patch(
                "gargoyl.foreground.EncryptedHistory",
                side_effect=OSError("synthetic-secret"),
            ),
        ):
            result = run_configured(self.config, **self.arguments)
            self.assertEqual(result.reason, "history_initialization_failed")
            self.assertNotIn("synthetic-secret", repr(result))
        with (
            patch(
                "gargoyl.foreground.CollectorRuntime",
                side_effect=RuntimeError("synthetic-secret"),
            ),
            patch("gargoyl.foreground.EncryptedHistory") as history,
        ):
            result = run_configured(self.config, **self.arguments)
            self.assertEqual(result.reason, "runtime_initialization_failed")
            history.return_value.close.assert_called_once()
        with (
            patch(
                "gargoyl.foreground.CollectorRuntime", return_value=Runtime(self.clock)
            ),
            patch("gargoyl.foreground.EncryptedHistory") as history,
        ):
            history.return_value.close.side_effect = OSError("synthetic-secret")
            result = run_configured(self.config, **self.arguments)
            self.assertEqual(result.status, "incomplete_shutdown")
            self.assertEqual(result.reason, "history_close_failed")

    def test_keyboard_interrupt_during_owned_close_reports_incomplete_shutdown(self):
        with (
            patch(
                "gargoyl.foreground.CollectorRuntime", return_value=Runtime(self.clock)
            ),
            patch("gargoyl.foreground.EncryptedHistory") as history,
        ):
            history.return_value.close.side_effect = KeyboardInterrupt()
            result = run_configured(self.config, **self.arguments)
            self.assertEqual(result.status, "incomplete_shutdown")
            self.assertEqual(result.reason, "history_close_failed")
            history.return_value.close.assert_called_once()

    def test_composition_closes_real_encrypted_history(self):
        with tempfile.TemporaryDirectory() as directory:
            self.arguments["spool_directory"] = Path(directory) / "spool"
            with patch(
                "gargoyl.foreground.CollectorRuntime", return_value=Runtime(self.clock)
            ) as runtime:
                result = run_configured(self.config, **self.arguments)
            self.assertEqual(result.status, "stopped")
            owned_history = runtime.call_args.args[1]
            with self.assertRaises(Exception):
                owned_history.pending(NOW)
            self.assertTrue(
                (self.arguments["spool_directory"] / "history.sqlite3").exists()
            )
