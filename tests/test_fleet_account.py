import threading
import time
import unittest
from unittest.mock import Mock, patch

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
            with self.assertRaises(FleetError) as caught1:
                transport("GET", "/v1/me/providers")
            self.assertEqual(caught1.exception.reason, "unavailable")
            self.assertLess(time.monotonic() - began, 0.3)
            with self.assertRaises(FleetError) as caught2:
                transport("GET", "/v1/me/providers")
            self.assertEqual(caught2.exception.reason, "unavailable")
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

    def test_http_status_classification_distinguishes_auth_from_transport_failure(self):
        from gargoyl.fleet_account import _request

        token = "darkbloom-at-fixture-token-valid-abc"

        # 401 and 403 map to auth_required
        for status in (401, 403):
            fake_conn = Mock()
            fake_resp = Mock(status=status, read=Mock(return_value=b'{"error": "rejected"}'))
            fake_conn.getresponse.return_value = fake_resp
            with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
                with self.assertRaises(FleetError) as ctx:
                    _request("GET", "/v1/me/providers", token=token)
                self.assertEqual(ctx.exception.reason, "auth_required")

        # 500, 502, 503, 504 and unexpected statuses map to unavailable (transient)
        for status in (500, 502, 503, 504):
            fake_conn = Mock()
            fake_resp = Mock(status=status, read=Mock(return_value=b'{"error": "server error"}'))
            fake_conn.getresponse.return_value = fake_resp
            with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
                with self.assertRaises(FleetError) as ctx:
                    _request("GET", "/v1/me/providers", token=token)
                self.assertEqual(ctx.exception.reason, "unavailable")

        # Socket timeout and OSError map to unavailable (transient transport)
        for err in (TimeoutError("read timed out"), OSError("network unreachable")):
            fake_conn = Mock()
            fake_conn.request.side_effect = err
            with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
                with self.assertRaises(FleetError) as ctx:
                    _request("GET", "/v1/me/providers", token=token)
                self.assertEqual(ctx.exception.reason, "unavailable")

    def test_account_client_with_bounded_transport_classifies_auth_vs_transport(self):
        from gargoyl.fleet_account import _request

        token = "darkbloom-at-fixture-token-valid-abc"

        # 1. 401/403 with BoundedTransport(_request) maps to auth_required
        for status in (401, 403):
            fake_conn = Mock()
            fake_resp = Mock(status=status, read=Mock(return_value=b'{"error": "rejected"}'))
            fake_conn.getresponse.return_value = fake_resp
            with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
                client = AccountClient(transport=BoundedTransport(_request, timeout=1.0))
                with self.assertRaises(FleetError) as ctx:
                    client.providers(token)
                self.assertEqual(ctx.exception.reason, "auth_required")

        # 2. 500 with BoundedTransport(_request) maps to unavailable
        fake_conn = Mock()
        fake_resp = Mock(status=500, read=Mock(return_value=b'{"error": "internal"}'))
        fake_conn.getresponse.return_value = fake_resp
        with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
            client = AccountClient(transport=BoundedTransport(_request, timeout=1.0))
            with self.assertRaises(FleetError) as ctx:
                client.providers(token)
            self.assertEqual(ctx.exception.reason, "unavailable")

        # 3. OSError with BoundedTransport(_request) maps to unavailable
        fake_conn = Mock()
        fake_conn.request.side_effect = OSError("connection reset")
        with patch("gargoyl.fleet_account.http.client.HTTPSConnection", return_value=fake_conn):
            client = AccountClient(transport=BoundedTransport(_request, timeout=1.0))
            with self.assertRaises(FleetError) as ctx:
                client.providers(token)
            self.assertEqual(ctx.exception.reason, "unavailable")

        # 4. Transport deadline/timeout with BoundedTransport(_request) maps to unavailable (not auth_required)
        release = threading.Event()
        try:
            def stalled_request(*args, **kwargs):
                release.wait(1.0)
                return {"late": "ignored"}

            client_timeout = AccountClient(transport=BoundedTransport(stalled_request, timeout=0.03))
            with self.assertRaises(FleetError) as ctx:
                client_timeout.providers(token)
            self.assertEqual(ctx.exception.reason, "unavailable")
        finally:
            release.set()
