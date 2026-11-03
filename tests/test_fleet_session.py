import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_fleet_state import NOW, response

from gargoyl.fleet_account import FleetError, PendingLogin
from gargoyl.fleet_session import SessionClosed, run_session, session_lock
from gargoyl.fleet_state import FleetCache


class FleetSessionTests(unittest.TestCase):
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

    def test_disconnect_drops_session_without_secret_persistence_or_extra_requests(
        self,
    ):
        def wait(seconds):
            if seconds >= 30:
                raise SessionClosed

        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
        )
        encoded = (
            json.dumps(self.events)
            + Path(self.cache.directory, "fleet.json").read_text()
        )
        self.assertNotIn("private-device-code", encoded)
        self.assertNotIn("private-test-token", encoded)
        self.assertEqual(self.client.providers.call_count, 1)
        self.assertEqual(self.cache.read(NOW)["connection"], "disconnected")

    def test_remember_transfers_one_credential_only_after_first_validated_read(self):
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
            remember=True,
        )
        credentials = [e for e in self.events if e["kind"] == "fleet-credential"]
        self.assertEqual(len(credentials), 1)
        self.assertEqual(credentials[0]["purpose"], "desktop_account")
        self.assertEqual(credentials[0]["token"], self.client.poll.return_value)
        self.assertEqual(self.client.providers.call_count, 2)
        self.assertNotIn(
            "private-test-token", Path(self.cache.directory, "fleet.json").read_text()
        )

    def test_remember_never_transfers_on_invalid_fleet_or_closed_owner(self):
        self.client.providers.side_effect = FleetError("invalid_data")
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            remember=True,
        )
        self.assertFalse(any(e["kind"] == "fleet-credential" for e in self.events))
        self.assertIsNone(self.cache.read(NOW))

    def test_restore_uses_saved_scope_without_device_grant_or_reexporting_token(self):
        def wait(seconds):
            if seconds >= 30:
                raise SessionClosed

        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            initial_token="darkbloom-at-private-restored-token",
            session_seconds=120,
        )
        self.client.begin.assert_not_called()
        self.client.poll.assert_not_called()
        self.assertEqual(
            self.client.providers.call_args.args,
            ("darkbloom-at-private-restored-token",),
        )
        self.assertNotIn("private-restored-token", json.dumps(self.events))
        self.assertNotIn(
            "private-restored-token",
            Path(self.cache.directory, "fleet.json").read_text(),
        )

    def test_restore_refuses_broad_token_and_reads_arriving_after_expiry(self):
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
            initial_token="eigeninference-pt-broad",
        )
        self.client.providers.assert_not_called()
        self.client.begin.assert_not_called()
        self.assertIsNone(self.cache.read(NOW))
        clock = Mock(side_effect=[0, 0, 2])
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=clock,
            initial_token="darkbloom-at-private-restored-token",
            session_seconds=1,
        )
        self.assertIsNone(self.cache.read(NOW))
        self.assertFalse(any(e["kind"] == "fleet-updated" for e in self.events))

    def test_concurrent_sessions_refused_before_any_grant_request(self):
        with session_lock(self.cache):
            run_session(
                self.cache,
                owner=lambda: True,
                wait=lambda _: None,
                send=self.events.append,
                client=self.client,
            )
        self.client.begin.assert_not_called()
        self.assertEqual(
            self.events, [{"kind": "fleet-unavailable", "reason": "session_busy"}]
        )

    def test_closed_gui_after_network_response_cannot_commit_inventory(self):
        closed = [False]

        def providers(_):
            closed[0] = True
            return response()

        def wait(_):
            if closed[0]:
                raise SessionClosed

        self.client.providers.side_effect = providers
        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
        )
        self.assertIsNone(self.cache.read(NOW))

    def test_scope_refusal_is_specific_and_never_retried(self):
        self.client.begin.side_effect = FleetError("scope_refused")
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
        )
        self.assertEqual(self.client.begin.call_count, 1)
        self.client.providers.assert_not_called()
        self.assertEqual(
            self.events, [{"kind": "fleet-unavailable", "reason": "scope_refused"}]
        )

    def test_auth_failure_stops_and_keeps_original_fetch_time(self):
        self.client.providers.side_effect = [response(), FleetError("auth_required")]
        run_session(
            self.cache,
            owner=lambda: True,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
            now=lambda: NOW,
            monotonic=lambda: 0,
        )
        self.assertEqual(self.client.providers.call_count, 2)
        value = self.cache.read(NOW)
        self.assertEqual(value["connection"], "auth_required")
        self.assertEqual(value["fetched_at"], NOW)

    def test_lost_active_owner_never_starts_account_request(self):
        run_session(
            self.cache,
            owner=lambda: False,
            wait=lambda _: None,
            send=self.events.append,
            client=self.client,
        )
        self.client.begin.assert_not_called()

    def test_real_pipe_disconnect_intent_records_intentional_disconnect(self):
        from gargoyl.fleet_session import pipe_wait

        r, w = os.pipe()
        try:
            os.write(w, b"disconnect\n")
            os.close(w)
            w = None
            stream = open(r, "rb", buffering=0)
            self.addCleanup(stream.close)
            run_session(
                self.cache,
                owner=lambda: True,
                wait=lambda seconds: pipe_wait(stream, seconds, lambda: True),
                send=self.events.append,
                client=self.client,
                initial_token="darkbloom-at-private-restored-token",
                now=lambda: NOW,
                monotonic=lambda: 0,
            )
            lifecycle = self.cache.read_lifecycle(NOW)
            self.assertIsNotNone(lifecycle)
            self.assertEqual(lifecycle["status"], "stopped")
            self.assertEqual(lifecycle["exit_reason"], "intentional_disconnect")
        finally:
            if w is not None:
                os.close(w)

    def test_real_pipe_quit_intent_records_intentional_quit(self):
        from gargoyl.fleet_session import pipe_wait

        r, w = os.pipe()
        try:
            os.write(w, b"quit\n")
            os.close(w)
            w = None
            stream = open(r, "rb", buffering=0)
            self.addCleanup(stream.close)
            run_session(
                self.cache,
                owner=lambda: True,
                wait=lambda seconds: pipe_wait(stream, seconds, lambda: True),
                send=self.events.append,
                client=self.client,
                initial_token="darkbloom-at-private-restored-token",
                now=lambda: NOW,
                monotonic=lambda: 0,
            )
            lifecycle = self.cache.read_lifecycle(NOW)
            self.assertIsNotNone(lifecycle)
            self.assertEqual(lifecycle["status"], "stopped")
            self.assertEqual(lifecycle["exit_reason"], "intentional_quit")
        finally:
            if w is not None:
                os.close(w)

    def test_real_pipe_bare_eof_records_pipe_eof(self):
        from gargoyl.fleet_session import pipe_wait

        r, w = os.pipe()
        try:
            os.close(w)
            w = None
            stream = open(r, "rb", buffering=0)
            self.addCleanup(stream.close)
            run_session(
                self.cache,
                owner=lambda: True,
                wait=lambda seconds: pipe_wait(stream, seconds, lambda: True),
                send=self.events.append,
                client=self.client,
                initial_token="darkbloom-at-private-restored-token",
                now=lambda: NOW,
                monotonic=lambda: 0,
            )
            lifecycle = self.cache.read_lifecycle(NOW)
            self.assertIsNotNone(lifecycle)
            self.assertEqual(lifecycle["status"], "exited")
            self.assertEqual(lifecycle["exit_reason"], "pipe_eof")
        finally:
            if w is not None:
                os.close(w)

    def test_transient_failure_then_session_closed_clears_unavailable_and_does_not_show_retrying(self):
        from gargoyl.fleet_session import SessionClosed
        from gargoyl.native_views import render_view

        wait_count = 0

        def wait_step(seconds):
            nonlocal wait_count
            if seconds >= 30:
                wait_count += 1
                if wait_count >= 2:
                    raise SessionClosed("pipe_eof")

        self.client.providers.side_effect = [response(), FleetError("unavailable")]
        run_session(
            self.cache,
            owner=lambda: True,
            wait=wait_step,
            send=self.events.append,
            client=self.client,
            initial_token="darkbloom-at-private-restored-token",
            now=lambda: NOW,
            monotonic=lambda: 0,
        )
        inv = self.cache.read(NOW)
        self.assertIsNotNone(inv)
        self.assertEqual(inv["connection"], "disconnected")
        lifecycle = self.cache.read_lifecycle(NOW)
        self.assertIsNotNone(lifecycle)
        self.assertEqual(lifecycle["status"], "exited")
        self.assertEqual(lifecycle["exit_reason"], "pipe_eof")

        # Verify render_view gives precedence to exited lifecycle and does NOT claim live retrying
        html = render_view("fleet", None, None, inventory=inv, now=NOW, lifecycle=lifecycle)
        self.assertIn("Supervising pipe closed (cause unknown)", html)
        self.assertNotIn("retrying with backoff", html)
