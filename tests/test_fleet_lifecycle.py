"""Test reader lifecycle recording, incarnation verification and nonsecret diagnostics."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_fleet_state import NOW, response

from gargoyl.fleet_account import FleetError, PendingLogin
from gargoyl.fleet_session import SessionClosed, run_session
from gargoyl.fleet_state import (
    FleetCache,
    effective_lifecycle,
    validate_reader_lifecycle,
)


class FleetLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = FleetCache(Path(self.temp.name).resolve() / "cache", os.getuid())
        self.events = []
        self.client = Mock()
        self.client.begin.return_value = PendingLogin(
            "desktop-account-private-device-code", "TEST-CODE", 900, 1
        )
        self.client.poll.return_value = "darkbloom-at-private-test-token"
        self.client.providers.return_value = response()

    def test_reader_lifecycle_validation_and_storage(self):
        valid = {
            "schema": 1,
            "status": "running",
            "observed_at": NOW,
            "owner_uid": os.getuid(),
            "incarnation": {"pid": 1234, "born_us": 5678},
            "started_at": NOW,
            "last_read_at": NOW,
            "exit_reason": "none",
            "exit_status": None,
            "retry_count": 0,
            "retry_budget": 5,
        }
        self.assertEqual(validate_reader_lifecycle(valid), valid)
        self.cache.write_lifecycle(valid)
        loaded = self.cache.read_lifecycle(NOW)
        self.assertEqual(loaded, valid)

        # Rejects unknown keys, bad schema, bad statuses, or negative retry counts
        for bad in (
            dict(valid, schema=2),
            dict(valid, status="forged"),
            dict(valid, exit_reason="invented"),
            dict(valid, retry_count=-1),
            dict(valid, token="darkbloom-at-must-never-persist"),
            dict(valid, incarnation={"pid": -1, "born_us": 1}),
        ):
            with self.assertRaises(FleetError):
                validate_reader_lifecycle(bad)

    def test_session_records_lifecycle_and_incarnation(self):
        waits = [0]

        def wait(seconds):
            if seconds >= 30:
                waits[0] += 1
                if waits[0] == 2:
                    raise SessionClosed

        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            initial_token="darkbloom-at-fixture-token",
        )
        lifecycle = self.cache.read_lifecycle(NOW)
        self.assertIsNotNone(lifecycle)
        self.assertEqual(lifecycle["schema"], 1)
        self.assertEqual(lifecycle["owner_uid"], os.getuid())
        self.assertIsNotNone(lifecycle["incarnation"])
        self.assertEqual(lifecycle["incarnation"]["pid"], os.getpid())
        self.assertEqual(lifecycle["last_read_at"], NOW)
        self.assertEqual(lifecycle["status"], "exited")
        self.assertEqual(lifecycle["exit_reason"], "pipe_eof")

        raw_file = Path(self.cache.directory, "reader_lifecycle.json").read_text()
        self.assertNotIn("fixture-token", raw_file)
        self.assertNotIn("providers", raw_file)

    def test_transient_failure_records_transient_status_without_auth_rejection(self):
        self.client.providers.side_effect = [
            response(),
            FleetError("unavailable"),
            SessionClosed,
        ]
        waits = [0]

        def wait(seconds):
            if seconds >= 30:
                waits[0] += 1
                if waits[0] == 2:
                    # Inspect lifecycle mid-run during transient failure
                    mid = self.cache.read_lifecycle(NOW)
                    self.assertEqual(mid["status"], "transient_failure")
                    raise SessionClosed

        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            initial_token="darkbloom-at-fixture-token",
        )
        final = self.cache.read_lifecycle(NOW)
        self.assertEqual(final["status"], "exited")
        self.assertNotEqual(final["exit_reason"], "auth_required")

    def test_auth_required_records_stopped_and_auth_reason(self):
        self.client.providers.side_effect = [response(), FleetError("auth_required")]
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            initial_token="darkbloom-at-fixture-token",
        )
        final = self.cache.read_lifecycle(NOW)
        self.assertEqual(final["status"], "stopped")
        self.assertEqual(final["exit_reason"], "auth_required")

    def test_effective_lifecycle_detects_dead_process_and_pid_reuse(self):
        running = {
            "schema": 1,
            "status": "running",
            "observed_at": NOW,
            "owner_uid": os.getuid(),
            "incarnation": {"pid": 99999, "born_us": 1000000},
            "started_at": NOW,
            "last_read_at": NOW,
            "exit_reason": "none",
            "exit_status": None,
            "retry_count": 0,
            "retry_budget": 5,
        }
        self.cache.write_lifecycle(running)

        # Process is alive with matching incarnation: returns running
        alive_eff = effective_lifecycle(
            self.cache, NOW, alive=lambda inc: inc == running["incarnation"]
        )
        self.assertEqual(alive_eff["status"], "running")

        # Process exited or missing: effective status becomes exited with unknown reason
        dead_eff = effective_lifecycle(self.cache, NOW, alive=lambda _: False)
        self.assertEqual(dead_eff["status"], "exited")
        self.assertEqual(dead_eff["exit_reason"], "unknown")
        # NEVER claims expired credentials or revoked auth
        self.assertNotEqual(dead_eff["exit_reason"], "auth_required")
        self.assertNotEqual(dead_eff["exit_reason"], "expired")

        # PID was reused (alive returns False because born_us differs)
        reused_eff = effective_lifecycle(
            self.cache,
            NOW,
            alive=lambda inc: inc["pid"] == 99999 and inc.get("born_us") == 2000000,
        )
        self.assertEqual(reused_eff["status"], "exited")
        self.assertEqual(reused_eff["exit_reason"], "unknown")
