"""Private native session: one scoped grant, bounded metadata, no secret persistence."""

import fcntl
import json
import os
import selectors
import stat
import sys
import time
from contextlib import contextmanager

from gargoyl.fleet_account import AccountClient, FleetError
from gargoyl.fleet_state import _directory, normalize_inventory, utc_now

SESSION_SECONDS = 86400
POLL_SECONDS = 30


@contextmanager
def session_lock(cache):
    directory = _directory(cache.directory, cache.uid, create=True)
    fd = None
    try:
        fd = os.open(
            "session.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        s = os.fstat(fd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != cache.uid
            or s.st_nlink != 1
            or s.st_mode & 0o077
        ):
            raise FleetError("unavailable")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise FleetError("unavailable") from None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class SessionClosed(Exception):
    pass


def private_send(value):
    """Only small bounded native events; no token or device code is ever emitted."""
    payload = json.dumps(value, allow_nan=False, ensure_ascii=False).encode() + b"\n"
    if len(payload) > 4096:
        raise SessionClosed
    try:
        if os.write(sys.stdout.fileno(), payload) != len(payload):
            raise SessionClosed
    except (OSError, ValueError):
        raise SessionClosed from None


def pipe_wait(stream, seconds, owner):
    deadline = time.monotonic() + seconds
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while True:
            if not owner():
                raise SessionClosed
            if selector.select(max(0, min(1, deadline - time.monotonic()))):
                # EOF or any input requests termination. No arbitrary commands/actions.
                os.read(stream.fileno(), 128)
                raise SessionClosed
            if time.monotonic() >= deadline:
                return


def _run_session(
    cache, *, owner, wait, send, client=None, now=utc_now, monotonic=time.monotonic
):
    client = client or AccountClient()
    inventory = None
    token = None
    end = monotonic() + SESSION_SECONDS
    try:
        wait(0)
        if not owner():
            raise SessionClosed
        cache.clear()
        pending = client.begin()
        wait(0)
        send(
            dict(
                kind="fleet-authorization",
                purpose="desktop_account",
                user_code=pending.user_code,
                expires_in=max(0, int(pending.deadline - monotonic())),
            )
        )
        while token is None:
            wait(pending.interval)
            if not owner():
                raise SessionClosed
            token = client.poll(pending)
        # No token crosses a pipe or enters the cache. Browser completion is scoped.
        pending = None
        wait(0)
        send(dict(kind="fleet-connected"))
        failures = 0
        while monotonic() < end:
            wait(0)
            if not owner():
                raise SessionClosed
            try:
                raw = client.providers(token)
                wait(0)
                inventory = normalize_inventory(raw, now())
                cache.write(inventory)
                failures = 0
                send(
                    dict(
                        kind="fleet-updated",
                        count=len(inventory["providers"]),
                        partial=inventory["partial"],
                    )
                )
            except FleetError as e:
                if inventory is not None:
                    inventory = dict(
                        inventory,
                        connection="auth_required"
                        if e.reason == "auth_required"
                        else "unavailable",
                    )
                    cache.write(inventory)
                send(dict(kind="fleet-unavailable", reason=e.reason))
                if e.reason != "unavailable":
                    return
                failures += 1
            wait(
                min(
                    max(0, end - monotonic()), 300, POLL_SECONDS * 2 ** min(failures, 4)
                )
            )
        send(dict(kind="fleet-unavailable", reason="expired"))
    except SessionClosed:
        pass
    except (FleetError, OSError, ValueError) as error:
        try:
            send(
                dict(
                    kind="fleet-unavailable",
                    reason=error.reason
                    if isinstance(error, FleetError)
                    else "unavailable",
                )
            )
        except SessionClosed:
            pass
    finally:
        token = None
        # Read-only cached inventory can remain at most24h, never as a live session.
        if inventory is not None:
            try:
                cache.write(
                    dict(
                        inventory,
                        connection="disconnected"
                        if inventory["connection"] == "connected"
                        else inventory["connection"],
                    )
                )
            except (OSError, ValueError):
                pass


def run_session(cache, **kwargs):
    try:
        with session_lock(cache):
            return _run_session(cache, **kwargs)
    except (FleetError, OSError, ValueError):
        try:
            kwargs["send"](dict(kind="fleet-unavailable", reason="unavailable"))
        except SessionClosed:
            pass
