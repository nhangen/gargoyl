"""Bounded account-owned fleet reads. No provider credential or control endpoints."""

import http.client
import json
import queue
import re
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

API_HOST = "api.darkbloom.dev"
CONSOLE_URL = "https://console.darkbloom.dev/link"
PURPOSE = "desktop_account"


class FleetError(ValueError):
    """Only fixed safe reasons may cross the native pipe or enter metadata."""

    def __init__(self, reason):
        if reason not in {
            "unavailable",
            "auth_required",
            "scope_refused",
            "invalid_data",
            "expired",
        }:
            reason = "unavailable"
        self.reason = reason
        super().__init__(reason)


def decode_json(payload):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise FleetError("invalid_data")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(FleetError("invalid_data")),
        )
        pending = [(value, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            if depth > 16 or nodes > 50000:
                raise FleetError("invalid_data")
            if type(item) is dict:
                pending.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                pending.extend((v, depth + 1) for v in item)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise FleetError("invalid_data") from None


def token_valid(value):
    return (
        type(value) is str
        and re.fullmatch(r"darkbloom-at-[A-Za-z0-9._~-]{8,2048}", value) is not None
    )


def _request(method, path, *, body=None, token=None):
    """Fixed HTTPS authority, no redirects/cookies/proxies or arbitrary request target."""
    if (method, path) not in {
        ("POST", "/v1/device/code"),
        ("POST", "/v1/device/token"),
        ("GET", "/v1/me/providers"),
    }:
        raise FleetError("scope_refused")
    if token is not None and (path != "/v1/me/providers" or not token_valid(token)):
        raise FleetError("scope_refused")
    if path == "/v1/device/code" and body != {"purpose": PURPOSE}:
        raise FleetError("scope_refused")
    if path == "/v1/device/token" and (
        type(body) is not dict
        or set(body) != {"device_code"}
        or type(body["device_code"]) is not str
        or re.fullmatch(r"desktop-account-[A-Za-z0-9._~-]{4,1024}", body["device_code"])
        is None
    ):
        raise FleetError("scope_refused")
    if path == "/v1/me/providers" and (body is not None or not token_valid(token)):
        raise FleetError("scope_refused")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body, allow_nan=False, separators=(",", ":")).encode()
        if len(body) > 4096:
            raise FleetError("invalid_data")
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    c = http.client.HTTPSConnection(
        API_HOST, 443, timeout=10, context=ssl.create_default_context()
    )
    try:
        c.request(method, path, body=body, headers=headers)
        r = c.getresponse()
        limit = 2_000_000 if path == "/v1/me/providers" else 16384
        payload = r.read(limit + 1)
        if r.status in {401, 403}:
            raise FleetError("auth_required")
        if r.status != 200 or len(payload) > limit:
            raise FleetError("unavailable")
        return decode_json(payload)
    except (OSError, http.client.HTTPException):
        raise FleetError("unavailable") from None
    finally:
        c.close()


class BoundedTransport:
    """Caller deadline includes DNS/body reads. At most one outstanding daemon IO.

    A timed-out operation is never re-used; no replacement starts until it ends.
    The private session process exits on GUI EOF, ending any outstanding daemon.
    """

    def __init__(self, perform=_request, timeout=15):
        self.perform, self.timeout = perform, timeout
        self.lock = threading.Lock()
        self.active = None

    def __call__(self, method, path, **kwargs):
        result = queue.Queue(maxsize=1)

        def run():
            try:
                value = self.perform(method, path, **kwargs)
                result.put((True, value))
            except Exception as error:
                reason = (
                    error.reason if isinstance(error, FleetError) else "unavailable"
                )
                result.put((False, reason))

        with self.lock:
            if self.active is not None and self.active.is_alive():
                raise FleetError("unavailable")
            self.active = threading.Thread(
                target=run, daemon=True, name="Gargoyl account IO"
            )
            worker = self.active
            worker.start()
        try:
            ok, value = result.get(timeout=self.timeout)
        except queue.Empty:
            raise FleetError("unavailable") from None
        worker.join(timeout=0.05)
        if not ok:
            raise FleetError(value)
        return value


request = BoundedTransport()


@dataclass(repr=False)
class PendingLogin:
    device_code: str = field(repr=False)
    user_code: str = field(repr=False)
    deadline: float
    interval: int


class AccountClient:
    def __init__(self, *, transport=request, monotonic=time.monotonic):
        self.transport, self.monotonic = transport, monotonic

    def begin(self):
        began = self.monotonic()
        d = self.transport("POST", "/v1/device/code", body={"purpose": PURPOSE})
        if type(d) is not dict or d.get("purpose") != PURPOSE:
            raise FleetError("scope_refused")
        code, user = d.get("device_code"), d.get("user_code")
        if (
            type(code) is not str
            or re.fullmatch(r"desktop-account-[A-Za-z0-9._~-]{4,1024}", code) is None
            or type(user) is not str
            or re.fullmatch(r"[A-Za-z0-9-]{4,32}", user) is None
        ):
            raise FleetError("scope_refused")
        try:
            u = urlsplit(d.get("verification_uri", ""))
            if (
                u.scheme != "https"
                or u.hostname != "console.darkbloom.dev"
                or u.port not in {None, 443}
                or u.username
                or u.password
                or u.path != "/link"
                or u.fragment
            ):
                raise ValueError
        except (ValueError, TypeError):
            raise FleetError("scope_refused") from None
        expires, interval = d.get("expires_in"), d.get("interval")
        if (
            type(expires) is not int
            or not 1 <= expires <= 900
            or type(interval) is not int
            or not 1 <= interval <= 30
        ):
            raise FleetError("invalid_data")
        # Never return the server URL/query or a token to the native UI.
        return PendingLogin(code, user, began + expires, interval)

    def poll(self, pending):
        if self.monotonic() >= pending.deadline:
            raise FleetError("expired")
        d = self.transport(
            "POST", "/v1/device/token", body={"device_code": pending.device_code}
        )
        if self.monotonic() >= pending.deadline:
            raise FleetError("expired")
        if type(d) is not dict:
            raise FleetError("invalid_data")
        if d.get("purpose") not in {None, PURPOSE}:
            raise FleetError("scope_refused")
        if (
            d.get("status") in {"authorization_pending", "slow_down"}
            and d.get("token") is not None
        ):
            raise FleetError("scope_refused")
        if d.get("status") == "authorization_pending":
            return None
        if d.get("status") == "slow_down":
            if pending.interval >= 30:
                raise FleetError("unavailable")
            pending.interval += 5
            return None
        if (
            d.get("status") != "authorized"
            or d.get("purpose") != PURPOSE
            or not token_valid(d.get("token"))
        ):
            raise FleetError("scope_refused")
        return d["token"]

    def providers(self, token):
        if not token_valid(token):
            raise FleetError("scope_refused")
        return self.transport("GET", "/v1/me/providers", token=token)
