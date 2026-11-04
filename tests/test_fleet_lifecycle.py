"""Test reader lifecycle recording, incarnation verification and nonsecret diagnostics."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_fleet_state import NOW, response

from gargoyl.fleet_account import FleetError, PendingLogin
from gargoyl.fleet_session import SessionClosed, run_session, session_lock
from gargoyl.fleet_state import (
    FleetCache,
    effective_lifecycle,
    validate_reader_lifecycle,
)
from gargoyl.manual_restart import process_start


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
            "gui_owner": {"pid": 4321, "born_us": 8765},
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

        # Accepts None gui_owner or omitted gui_owner
        valid_none_gui = dict(valid, gui_owner=None)
        self.assertEqual(validate_reader_lifecycle(valid_none_gui), valid_none_gui)
        valid_no_gui = {k: v for k, v in valid.items() if k != "gui_owner"}
        self.assertEqual(validate_reader_lifecycle(valid_no_gui), valid_no_gui)

        # Rejects unknown keys, bad schema, bad statuses, or negative retry counts
        for bad in (
            dict(valid, schema=2),
            dict(valid, status="forged"),
            dict(valid, exit_reason="invented"),
            dict(valid, retry_count=-1),
            dict(valid, token="darkbloom-at-must-never-persist"),
            dict(valid, incarnation={"pid": -1, "born_us": 1}),
            dict(valid, gui_owner={"pid": -1, "born_us": 1}),
            dict(valid, gui_owner={"pid": 1, "born_us": -1}),
            dict(valid, gui_owner="not-a-dict"),
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
        self.assertIsNone(lifecycle["exit_status"])

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

    def test_contender_under_held_lock_does_not_overwrite_lifecycle(self):
        owner_record = {
            "schema": 1,
            "status": "starting",
            "observed_at": NOW,
            "owner_uid": os.getuid(),
            "incarnation": {"pid": 11111, "born_us": 22222},
            "started_at": NOW,
            "last_read_at": None,
            "exit_reason": "none",
            "exit_status": None,
            "retry_count": 0,
            "retry_budget": 5,
        }
        self.cache.write_lifecycle(owner_record)

        with session_lock(self.cache):
            contender_events = []
            run_session(
                self.cache,
                owner=lambda: True,
                wait=lambda _: None,
                send=contender_events.append,
                client=self.client,
                now=lambda: NOW,
                monotonic=lambda: 0,
                initial_token="darkbloom-at-contender-token",
            )
            self.assertEqual(
                contender_events,
                [{"kind": "fleet-unavailable", "reason": "session_busy"}],
            )

        disk_record = self.cache.read_lifecycle(NOW)
        self.assertEqual(disk_record, owner_record)
        self.assertEqual(disk_record["status"], "starting")
        self.assertEqual(disk_record["incarnation"], {"pid": 11111, "born_us": 22222})

    def test_effective_lifecycle_kernel_incarnation_and_unverified_fallback(self):
        my_pid = os.getpid()
        real_born_us = process_start(my_pid)
        self.assertIsNotNone(real_born_us)

        record = {
            "schema": 1,
            "status": "running",
            "observed_at": NOW,
            "owner_uid": os.getuid(),
            "incarnation": {"pid": my_pid, "born_us": real_born_us},
            "started_at": NOW,
            "last_read_at": NOW,
            "exit_reason": "none",
            "exit_status": None,
            "retry_count": 0,
            "retry_budget": 5,
        }
        self.cache.write_lifecycle(record)
        eff = effective_lifecycle(self.cache, NOW)
        self.assertEqual(eff["status"], "running")

        # PID reuse: live PID with mismatched start time resolves to exited/unknown
        record["incarnation"] = {"pid": my_pid, "born_us": real_born_us + 42}
        self.cache.write_lifecycle(record)
        eff = effective_lifecycle(self.cache, NOW)
        self.assertEqual(eff["status"], "exited")
        self.assertEqual(eff["exit_reason"], "unknown")

        # Unverified start time (born_us is None): never assumed running
        record["incarnation"] = {"pid": my_pid, "born_us": None}
        self.cache.write_lifecycle(record)
        eff = effective_lifecycle(self.cache, NOW)
        self.assertEqual(eff["status"], "exited")
        self.assertEqual(eff["exit_reason"], "unknown")

        # Owner UID mismatch: resolves to exited/owner_inactive
        record["incarnation"] = {"pid": my_pid, "born_us": real_born_us}
        record["owner_uid"] = os.getuid() + 1
        self.cache.write_lifecycle(record)
        eff = effective_lifecycle(self.cache, NOW)
        self.assertEqual(eff["status"], "exited")
        self.assertEqual(eff["exit_reason"], "owner_inactive")

    def test_read_lifecycle_is_non_mutating_when_retention_exceeded(self):
        record = {
            "schema": 1,
            "status": "running",
            "observed_at": "2026-10-01T00:00:00Z",
            "owner_uid": os.getuid(),
            "incarnation": {"pid": 1234, "born_us": 5678},
            "started_at": "2026-10-01T00:00:00Z",
            "last_read_at": "2026-10-01T00:00:00Z",
            "exit_reason": "none",
            "exit_status": None,
            "retry_count": 0,
            "retry_budget": 5,
        }
        self.cache.write_lifecycle(record)
        path = Path(self.cache.directory, "reader_lifecycle.json")
        self.assertTrue(path.exists())

        result = self.cache.read_lifecycle(NOW)
        self.assertIsNone(result)
        self.assertTrue(path.exists())
