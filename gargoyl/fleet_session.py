"""Private native session: one scoped grant, bounded metadata, no secret persistence."""

import fcntl
import json
import math
import os
import selectors
import stat
import sys
import time
from contextlib import contextmanager

from gargoyl.fleet_account import AccountClient, FleetError, token_valid
from gargoyl.fleet_state import _directory, normalize_inventory, utc_now

SESSION_SECONDS = 86400
PERSISTENT_SESSION_SECONDS = 30 * 86400
POLL_SECONDS = 30


def current_incarnation():
    try:
        from gargoyl.manual_restart import process_start

        born_us = process_start(os.getpid())
    except Exception:
        born_us = None
    return {"pid": os.getpid(), "born_us": born_us}


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
            raise FleetError("session_busy") from None
        yield
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class SessionClosed(Exception):
    def __init__(self, reason="pipe_eof"):
        super().__init__(reason)
        self.reason = reason


def private_send(value):
    """Bounded private native IPC; opted-in credentials never enter status or HTML."""
    payload = json.dumps(value, allow_nan=False, ensure_ascii=False).encode() + b"\n"
    if len(payload) > 4096:
        raise SessionClosed("pipe_eof")
    try:
        if os.write(sys.stdout.fileno(), payload) != len(payload):
            raise SessionClosed("pipe_eof")
    except (OSError, ValueError):
        raise SessionClosed("pipe_eof") from None


def pipe_wait(stream, seconds, owner):
    deadline = time.monotonic() + seconds
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while True:
            if not owner():
                raise SessionClosed("owner_inactive")
            if selector.select(max(0, min(1, deadline - time.monotonic()))):
                try:
                    payload = os.read(stream.fileno(), 128)
                except OSError:
                    payload = b""
                token = payload.strip().decode("utf-8", errors="replace")
                if token == "disconnect":
                    raise SessionClosed("intentional_disconnect")
                if token == "quit":
                    raise SessionClosed("intentional_quit")
                raise SessionClosed("pipe_eof")
            if time.monotonic() >= deadline:
                return


def _run_session(
    cache,
    *,
    owner,
    wait,
    send,
    client=None,
    now=utc_now,
    monotonic=time.monotonic,
    initial_token=None,
    remember=False,
    session_seconds=SESSION_SECONDS,
    retry_count=0,
    retry_budget=5,
    gui_owner=None,
):
    client = client or AccountClient()
    inventory = None
    token = None
    credential_sent = False
    end = 0
    if gui_owner is None:
        ppid = os.getppid()
        if ppid > 0:
            from gargoyl.manual_restart import process_start

            born = process_start(ppid)
            if born is not None:
                gui_owner = {"pid": ppid, "born_us": born}
    lifecycle_record = {
        "schema": 1,
        "status": "starting",
        "observed_at": now(),
        "owner_uid": cache.uid,
        "incarnation": current_incarnation(),
        "gui_owner": gui_owner,
        "started_at": now(),
        "last_read_at": None,
        "exit_reason": "none",
        "exit_status": None,
        "retry_count": retry_count,
        "retry_budget": retry_budget,
    }
    try:
        cache.write_lifecycle(lifecycle_record)
    except (OSError, ValueError):
        pass
    try:
        wait(0)
        if not owner():
            raise SessionClosed
        if (
            type(session_seconds) not in {int, float}
            or not math.isfinite(session_seconds)
            or not 0 < session_seconds <= PERSISTENT_SESSION_SECONDS
        ):
            raise FleetError("expired")
        end = monotonic() + session_seconds
        if type(remember) is not bool:
            raise FleetError("scope_refused")
        if initial_token is not None and (not token_valid(initial_token) or remember):
            raise FleetError("scope_refused")
        cache.clear()
        token = initial_token
        if token is None:
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
        # Only explicit native Remember mode may transfer a fresh scoped credential
        # over the trusted private pipe, after its first successful fleet read.
        pending = None
        wait(0)
        send(dict(kind="fleet-connected"))
        lifecycle_record["status"] = "running"
        lifecycle_record["observed_at"] = now()
        try:
            cache.write_lifecycle(lifecycle_record)
        except (OSError, ValueError):
            pass
        failures = 0
        while monotonic() < end:
            wait(0)
            if not owner():
                raise SessionClosed
            try:
                raw = client.providers(token)
                wait(0)
                if monotonic() >= end:
                    send(dict(kind="fleet-unavailable", reason="expired"))
                    lifecycle_record["exit_reason"] = "expired"
                    raise SessionClosed
                inventory = normalize_inventory(raw, now())
                cache.write(inventory)
                lifecycle_record["last_read_at"] = now()
                lifecycle_record["observed_at"] = now()
                lifecycle_record["status"] = "running"
                lifecycle_record["exit_reason"] = "none"
                try:
                    cache.write_lifecycle(lifecycle_record)
                except (OSError, ValueError):
                    pass
                if remember and not credential_sent:
                    wait(0)
                    if not owner():
                        raise SessionClosed
                    credential_sent = True
                    send(
                        dict(
                            kind="fleet-credential",
                            purpose="desktop_account",
                            token=token,
                        )
                    )
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
                if e.reason == "unavailable":
                    lifecycle_record["status"] = "transient_failure"
                    lifecycle_record["observed_at"] = now()
                elif e.reason == "auth_required":
                    lifecycle_record["status"] = "stopped"
                    lifecycle_record["exit_reason"] = "auth_required"
                    lifecycle_record["observed_at"] = now()
                elif e.reason in {"scope_refused", "expired"}:
                    lifecycle_record["status"] = "stopped"
                    lifecycle_record["exit_reason"] = e.reason
                    lifecycle_record["observed_at"] = now()
                try:
                    cache.write_lifecycle(lifecycle_record)
                except (OSError, ValueError):
                    pass
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
        lifecycle_record["exit_reason"] = "expired"
    except SessionClosed as closed:
        if not owner():
            lifecycle_record["exit_reason"] = "owner_inactive"
        elif closed.reason in {"intentional_disconnect", "intentional_quit"}:
            lifecycle_record["exit_reason"] = closed.reason
        elif lifecycle_record.get("exit_reason") == "none":
            lifecycle_record["exit_reason"] = "pipe_eof"
    except (FleetError, OSError, ValueError) as error:
        if lifecycle_record.get("exit_reason") == "none":
            if isinstance(error, FleetError):
                lifecycle_record["exit_reason"] = (
                    error.reason if error.reason in {"auth_required", "scope_refused", "expired"} else "unknown"
                )
            else:
                lifecycle_record["exit_reason"] = "unknown"
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
                new_conn = (
                    "disconnected"
                    if inventory.get("connection") in {"connected", "unavailable"}
                    else inventory.get("connection", "disconnected")
                )
                cache.write(dict(inventory, connection=new_conn))
            except (OSError, ValueError):
                pass
        if lifecycle_record is not None:
            try:
                lifecycle_record["observed_at"] = now()
                if lifecycle_record.get("exit_reason") in {"none", None}:
                    lifecycle_record["exit_reason"] = "unknown"
                if (
                    lifecycle_record.get("retry_count", 0)
                    >= lifecycle_record.get("retry_budget", 5)
                    and lifecycle_record.get("exit_reason")
                    not in {"intentional_disconnect", "intentional_quit"}
                ):
                    lifecycle_record["status"] = "terminal_failure"
                    lifecycle_record["exit_reason"] = "retry_exhausted"
                    lifecycle_record["exit_status"] = 1
                else:
                    lifecycle_record["status"] = (
                        "stopped"
                        if lifecycle_record.get("exit_reason")
                        in {
                            "intentional_disconnect",
                            "intentional_quit",
                            "auth_required",
                            "scope_refused",
                            "expired",
                        }
                        else "exited"
                    )
                    if lifecycle_record.get("exit_status") is None:
                        lifecycle_record["exit_status"] = (
                            0
                            if lifecycle_record.get("exit_reason")
                            in {"intentional_disconnect", "intentional_quit"}
                            else 1
                        )
                cache.write_lifecycle(lifecycle_record)
            except (OSError, ValueError):
                pass


def run_session(cache, **kwargs):
    try:
        with session_lock(cache):
            return _run_session(cache, **kwargs)
    except (FleetError, OSError, ValueError) as error:
        reason = (
            error.reason if isinstance(error, FleetError) else "unavailable"
        )
        try:
            kwargs["send"](
                dict(
                    kind="fleet-unavailable",
                    reason=reason,
                )
            )
        except SessionClosed:
            pass
