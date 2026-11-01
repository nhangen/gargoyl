import threading
import time
import unittest
from unittest.mock import Mock

from gargoyl.fleet_account import (
    CONSOLE_URL,
    AccountClient,
    BoundedTransport,
    FleetError,
    decode_json,
    request,
)


class AccountTests(unittest.TestCase):
    def valid(self):
        return dict(
            purpose="desktop_account",
            device_code="desktop-account-test-code",
            user_code="TEST-CODE",
            verification_uri="https://console.darkbloom.dev/link?code=TEST-CODE",
            expires_in=900,
            interval=2,
        )

    def test_only_acknowledged_readonly_grant_can_be_polled(self):
        transport = Mock(
            side_effect=[
                self.valid(),
                {"status": "authorization_pending"},
                {
                    "status": "authorized",
                    "purpose": "desktop_account",
                    "token": "darkbloom-at-test-token-123",
                },
            ]
        )
        client = AccountClient(transport=transport, monotonic=lambda: 10)
        pending = client.begin()
        self.assertNotIn("TEST-CODE", repr(pending))
        self.assertIsNone(client.poll(pending))
        self.assertEqual(client.poll(pending), "darkbloom-at-test-token-123")
        self.assertEqual(
            transport.call_args_list[0].kwargs, {"body": {"purpose": "desktop_account"}}
        )

    def test_graphical_link_preserves_only_fixed_readonly_purpose_context(self):
        from urllib.parse import parse_qs, urlsplit

        from gargoyl.native_app import SWIFT

        url = urlsplit(CONSOLE_URL)
        self.assertEqual(
            (url.scheme, url.netloc, url.path),
            ("https", "console.darkbloom.dev", "/link"),
        )
        self.assertEqual(parse_qs(url.query), {"purpose": ["desktop_account"]})
        self.assertIn('let fleetSignInURL = URL(string:"' + CONSOLE_URL + '")!', SWIFT)
        self.assertIn("NSWorkspace.shared.open(fleetSignInURL)", SWIFT)
        transport = Mock(
            return_value=dict(
                self.valid(), verification_uri=CONSOLE_URL + "&code=PRIVATE-CODE"
            )
        )
        pending = AccountClient(transport=transport, monotonic=lambda: 0).begin()
        self.assertNotIn("PRIVATE-CODE", repr(pending))
        self.assertNotIn("PRIVATE-CODE", CONSOLE_URL)

    def test_refuses_legacy_scope_and_untrusted_verification_origin_before_poll(self):
        for update in (
            {"purpose": "provider"},
            {"purpose": None},
            {"device_code": "provider-code"},
            {"verification_uri": "https://evil.test/link"},
            {"verification_uri": "https://console.darkbloom.dev@evil.test/link"},
            {"verification_uri": "https://console.darkbloom.dev/action"},
            {"verification_uri": "http://console.darkbloom.dev/link"},
            {"verification_uri": "https://console.darkbloom.dev/link?purpose=provider"},
            {
                "verification_uri": "https://console.darkbloom.dev/link?purpose=desktop_account&purpose=provider"
            },
            {"expires_in": True},
            {"interval": 0},
        ):
            transport = Mock(return_value=dict(self.valid(), **update))
            with self.assertRaises(FleetError):
                AccountClient(transport=transport).begin()
            self.assertEqual(transport.call_count, 1)

    def test_authorized_response_cannot_downgrade_or_inject_headers(self):
        for response in (
            {
                "status": "authorized",
                "purpose": "provider",
                "token": "eigeninference-pt-test",
            },
            {
                "status": "authorized",
                "purpose": "desktop_account",
                "token": "darkbloom-at-test\r\nInjected",
            },
            {"status": "authorized", "token": "darkbloom-at-test-token-123"},
            {"error": "private raw payload"},
        ):
            client = AccountClient(
                transport=Mock(side_effect=[self.valid(), response]),
                monotonic=lambda: 0,
            )
            pending = client.begin()
            with self.assertRaises(FleetError) as e:
                client.poll(pending)
            self.assertEqual(str(e.exception), "scope_refused")

    def test_expiration_prevents_token_request(self):
        clock = Mock(side_effect=[0, 900])
        transport = Mock(return_value=self.valid())
        client = AccountClient(transport=transport, monotonic=clock)
        pending = client.begin()
        with self.assertRaises(FleetError):
            client.poll(pending)
        self.assertEqual(transport.call_count, 1)

    def test_authorization_arriving_after_deadline_is_discarded(self):
        clock = Mock(side_effect=[0, 1, 901])
        transport = Mock(
            side_effect=[
                self.valid(),
                dict(
                    status="authorized",
                    purpose="desktop_account",
                    token="darkbloom-at-test-token-123",
                ),
            ]
        )
        client = AccountClient(transport=transport, monotonic=clock)
        pending = client.begin()
        with self.assertRaises(FleetError) as caught:
            client.poll(pending)
        self.assertEqual(caught.exception.reason, "expired")
        self.assertEqual(transport.call_count, 2)

    def test_repeated_slowdown_is_respected_or_polling_ends(self):
        transport = Mock(side_effect=[self.valid()] + [dict(status="slow_down")] * 8)
        client = AccountClient(transport=transport, monotonic=lambda: 0)
        pending = client.begin()
        pending.interval = 25
        self.assertIsNone(client.poll(pending))
        self.assertEqual(pending.interval, 30)
        with self.assertRaises(FleetError):
            client.poll(pending)
        self.assertEqual(transport.call_count, 3)

    def test_no_control_endpoint_or_unscoped_token_can_reach_network(self):
        for method, path in [
            ("POST", "/control/v1/actions"),
            ("GET", "https://evil.test"),
            ("GET", "/v1/me/summary"),
        ]:
            with self.assertRaises(FleetError):
                request(method, path)
        with self.assertRaises(FleetError):
            request("GET", "/v1/me/providers", token="eigeninference-pt-broad")

    def test_deadline_includes_stalled_dns_and_never_starts_parallel_replacements(self):
        release = threading.Event()
        calls = []

        def stalled(*args, **kwargs):
            calls.append(True)
            release.wait(1)
            return {"late": "ignored"}

        transport = BoundedTransport(stalled, timeout=0.03)
        began = time.monotonic()
        try:
            with self.assertRaises(FleetError):
                transport("GET", "/v1/me/providers")
            self.assertLess(time.monotonic() - began, 0.3)
            with self.assertRaises(FleetError):
                transport("GET", "/v1/me/providers")
            self.assertEqual(len(calls), 1)
            self.assertTrue(transport.active.daemon)
        finally:
            release.set()
            transport.active.join(timeout=1)

    def test_json_duplicate_and_nonfinite_rejected_without_raw_error(self):
        for body in [
            b'{"purpose":"desktop_account","purpose":"provider"}',
            b'{"x":NaN}',
            b"raw private failure",
        ]:
            with self.assertRaises(FleetError) as e:
                decode_json(body)
            self.assertEqual(str(e.exception), "invalid_data")
