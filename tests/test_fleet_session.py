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
            self.events, [{"kind": "fleet-unavailable", "reason": "unavailable"}]
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
