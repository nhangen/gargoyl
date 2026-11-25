"""Private same-owner native-app worker. No HTTP actions or browser authority.

The trusted native app authenticates owner presence; an inherited pipe binds its
one confirmation to this worker. Same-UID malicious code is outside this boundary.
"""

import ctypes
import hashlib
import http.client
import json
import os
import selectors
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from gargoyl.collector_coordinator_log import validate_log_report
from gargoyl.dashboard import build_dashboard
from gargoyl.manual_restart import (
    ManualJournal,
    executable_stamp,
    installation_preflight,
    invoke_restart,
    observed_target,
    owner_home,
    process_alive,
    read_operation,
    reconciliation_snapshot,
    restart_gate_allows,
)
from gargoyl.manual_restart import run_restart as execute_restart
from gargoyl.pilot_configuration import (
    grant_flags,
    load_pilot_configuration,
    save_pilot_grants,
    validate_grants,
)
from gargoyl.telemetry import timestamp, validate_snapshot

HOST = "00000000-0000-4000-8000-000000000001"
POLICY = "native-manual-installation-v1"


def console_owner():
    if sys.platform != "darwin":
        return False
    try:
        policy = load_pilot_configuration(home=owner_home()).require_local()
    except (OSError, ValueError):
        return False
    sc = ctypes.CDLL(
        "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration"
    )
    cf = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )
    sc.SCDynamicStoreCopyConsoleUser.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    sc.SCDynamicStoreCopyConsoleUser.restype = ctypes.c_void_p
    cf.CFRelease.argtypes = [ctypes.c_void_p]
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    name = sc.SCDynamicStoreCopyConsoleUser(None, ctypes.byref(uid), ctypes.byref(gid))
    if name:
        cf.CFRelease(name)
    return bool(name and uid.value == os.getuid() == policy.owner_uid)


def emit(value):
    """Progress delivery cannot abort an accepted operation when its window closes."""
    try:
        payload = (
            json.dumps(value, allow_nan=False, separators=(",", ":")).encode() + b"\n"
        )
        os.write(sys.stdout.fileno(), payload)
    except (OSError, ValueError):
        pass


def read_confirmation(stream, *, timeout=90, monotonic=time.monotonic, decoder=json.loads):
    deadline = monotonic() + timeout
    payload = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while monotonic() < deadline:
            events = selector.select(max(0, deadline - monotonic()))
            if not events:
                break
            chunk = os.read(stream.fileno(), min(4097 - len(payload), 4096))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > 4096:
                raise ValueError("confirmation too large")
            if b"\n" in payload:
                line, extra = bytes(payload).split(b"\n", 1)
                if extra:
                    raise ValueError("multiple confirmations")
                return decoder(line)
    raise ValueError("confirmation unavailable")


def graphical_restart(
    *,
    journal,
    preflight,
    inspect_target,
    invoke,
    receive,
    owner=console_owner,
    send=emit,
    monotonic=time.monotonic,
    wall_clock=time.time,
):
    """One pending preview, one native confirmation, shared CLI journal semantics."""
    if not owner():
        raise ValueError("inactive owner")
    prior = journal.read()
    if not restart_gate_allows(prior):
        raise ValueError("unresolved operation")
    target, stamp = preflight()
    began_wall = wall_clock()
    request = dict(
        request_id=uuid.uuid4().hex,
        target=target,
        policy=POLICY,
        expires_in_seconds=90,
        expires_at=began_wall + 90,
    )
    digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
    began = monotonic()
    request["preview_digest"] = digest

    def deliver(value):
        try:
            send(value)
        except (OSError, ValueError):
            pass

    def confirm(current):
        deliver(dict(kind="preview", **request))
        reply = receive()
        valid = (
            type(reply) is dict
            and set(reply) == {"request_id", "preview_digest", "approved"}
            and reply["approved"] is True
            and reply["request_id"] == request["request_id"]
            and reply["preview_digest"] == digest
            and 0 <= monotonic() - began <= 90
            and 0 <= wall_clock() - began_wall <= 90
            and owner()
        )
        if not valid:
            return False
        fresh, current_stamp = preflight()
        return (
            current_stamp == stamp
            and fresh["process"] == target["process"]
            and fresh["version"] == target["version"]
        )

    def once():
        if not owner():
            raise ValueError("owner changed")
        fresh, current_stamp = preflight()
        if current_stamp != stamp or fresh["process"] != target["process"]:
            raise ValueError("installation changed")
        return invoke()

    result = execute_restart(
        journal,
        target,
        inspect_target=inspect_target,
        invoke=once,
        confirm=confirm,
        progress=lambda text: deliver(dict(kind="progress", text=text)),
    )
    deliver(dict(kind="result", state=result["state"], reason=result["reason"]))
    return result



def graphical_reconcile(*, journal, inspect_target, receive, owner=console_owner,
                        send=emit, alive=process_alive, clock=None,
                        monotonic=time.monotonic, wall_clock=time.time):
    """One owner-confirmed journal observation; no provider command is available."""
    from gargoyl.dashboard.runtime import utc_now
    clock = clock or utc_now
    if not owner():
        raise ValueError("inactive_owner")
    prior = journal.read()
    if prior is None or prior["state"] not in {"intent", "unknown"}:
        raise ValueError("no_unresolved_operation")
    if prior["target"]["process"]["owner_uid"] != os.getuid():
        raise ValueError("inactive_owner")
    original = json.dumps(prior, sort_keys=True)
    candidate = reconciliation_snapshot(prior, inspect_target=inspect_target, alive=alive, clock=clock)

    def observation(value):
        current = value.get("current")
        return json.dumps(dict(observation=value["observation"], current=None if current is None else
                               dict(process=current["process"], version=current["version"])), sort_keys=True)

    observed = observation(candidate)
    began_wall, began = wall_clock(), monotonic()
    request = dict(request_id=uuid.uuid4().hex, policy="native-readonly-reconciliation-v1",
                   operation_id=prior["operation_id"], target=prior["target"],
                   observation=candidate["observation"], current=candidate.get("current"),
                   expires_at=began_wall+90, expires_in_seconds=90)
    request["preview_digest"] = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
    send(dict(kind="preview", **request))
    reply = receive()
    if not (type(reply) is dict and set(reply) == {"request_id", "preview_digest", "approved"}
            and reply["approved"] is True and reply["request_id"] == request["request_id"]
            and reply["preview_digest"] == request["preview_digest"]
            and 0 <= monotonic()-began <= 90 and 0 <= wall_clock()-began_wall <= 90
            and owner()):
        raise ValueError("confirmation_unavailable")
    if json.dumps(journal.read(), sort_keys=True) != original:
        raise ValueError("operation_changed")
    current = reconciliation_snapshot(journal.read(), inspect_target=inspect_target, alive=alive, clock=clock)
    if observation(current) != observed or not owner():
        raise ValueError("observation_changed")
    journal.write(current)  # Only mutation, after bound native consent and fresh checks.
    try:
        send(dict(kind="reconcile-result", state=current["state"], reason=current["reason"],
                  operation_id=current["operation_id"]))
    except (OSError, ValueError):
        pass  # A broken window cannot undo or repeat a committed observation.
    return current

def monitor_configuration():
    import plistlib

    home = owner_home()
    policy = load_pilot_configuration(home=home).require_local()
    executable_stamp(policy.monitor_executable)
    path = home / "Library/LaunchAgents/dev.gargoyl.monitor.plist"
    if str(path.resolve(strict=True)) != str(path):
        raise ValueError("monitor configuration unavailable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid != policy.owner_uid
            or s.st_nlink != 1
            or s.st_mode & 0o022
        ):
            raise ValueError("monitor ownership unavailable")
        payload = os.read(fd, 65537)
        if len(payload) > 65536:
            raise ValueError("monitor configuration limit")
    finally:
        os.close(fd)
    value = plistlib.loads(payload)
    expected = [
        policy.monitor_executable,
        "monitor",
        "--input",
        str(home / ".darkbloom/daemon-state.json"),
        "--owner-uid",
        str(policy.owner_uid),
        "--host",
        policy.host_id,
        "--interval",
        "5",
        "--port",
        "8766",
    ]
    # Granted capabilities map 1:1 to their CLI flags; revocation is the empty tuple.
    from gargoyl.pilot_configuration import grant_flags

    expected += list(grant_flags(policy.grants, policy.provider_executable))
    if (
        value.get("Label") != "dev.gargoyl.monitor"
        or value.get("ProgramArguments") != expected
    ):
        raise ValueError("monitor configuration differs")
    return path


def update_monitor_plist(*, home, policy):
    """Ensure dev.gargoyl.monitor.plist matches the configured grants."""
    import plistlib
    import tempfile

    from gargoyl.pilot_configuration import grant_flags

    agents_dir = Path(home) / "Library/LaunchAgents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    plist_path = agents_dir / "dev.gargoyl.monitor.plist"
    flags = list(grant_flags(policy.grants, policy.provider_executable))
    args = [
        policy.monitor_executable,
        "monitor",
        "--input",
        str(Path(home) / ".darkbloom/daemon-state.json"),
        "--owner-uid",
        str(policy.owner_uid),
        "--host",
        policy.host_id,
        "--interval",
        "5",
        "--port",
        "8766",
    ] + flags
    payload = plistlib.dumps(
        dict(
            Label="dev.gargoyl.monitor",
            ProgramArguments=args,
            RunAtLoad=False,
            KeepAlive=False,
        )
    )
    handle, temp = tempfile.mkstemp(
        prefix="monitor-", suffix=".plist", dir=str(agents_dir)
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, str(plist_path))
    except Exception:
        if os.path.exists(temp):
            os.unlink(temp)
        raise


def activation_state(*, home=None, python=None):
    """Return the persisted grants and the exact monitor CLI line they imply."""
    home = home or owner_home()
    policy = load_pilot_configuration(home=home).require_local()
    flags = list(grant_flags(policy.grants, policy.provider_executable))
    command = [
        policy.monitor_executable,
        "monitor",
        "--input",
        str(home / ".darkbloom/daemon-state.json"),
        "--owner-uid",
        str(policy.owner_uid),
        "--host",
        policy.host_id,
        "--interval",
        "5",
        "--port",
        "8766",
    ] + flags
    return dict(
        kind="activation",
        grants=list(policy.grants),
        command=command,
        line=" ".join(command),
    )


def set_grants(*, stream, home=None, python=None, timeout=90):
    """Persist one explicit per-capability grant set after a typed confirmation.

    Each capability is an independent, explicit choice: the typed phrase must
    name the exact grant set being stored. Revocation is a fresh empty set
    ("REVOKE ALL"), not a silent drop of any single grant.
    """
    home = home or owner_home()
    request = read_confirmation(stream, timeout=timeout)
    if type(request) is not dict or set(request) != {"grants", "confirm"}:
        raise ValueError("grant request unavailable")
    confirm = request["confirm"]
    if type(confirm) is not str:
        raise ValueError("grant consent unavailable")
    grants = tuple(request["grants"])
    validate_grants(grants)
    expected = " ".join(grants) if grants else "REVOKE ALL"
    if confirm != expected:
        raise ValueError("grant consent unavailable")
    policy = save_pilot_grants(
        home=home,
        python=sys.executable if python is None else python,
        grants=grants,
    )
    update_monitor_plist(home=home, policy=policy)
    return activation_state(home=home, python=python)


def control_monitor(action, *, run=subprocess.run, validate=monitor_configuration):
    """Only Gargoyl's fixed existing job; no PID signals or listener displacement."""
    if action not in {"start-monitor", "stop-monitor"} or not console_owner():
        raise ValueError("monitor action unavailable")
    path = validate()
    label = f"gui/{os.getuid()}/dev.gargoyl.monitor"
    job = run(["/bin/launchctl", "print", label], capture_output=True, timeout=10)
    if action == "stop-monitor":
        if job.returncode == 113:
            return "Monitoring was already stopped."
        if job.returncode != 0:
            raise ValueError("monitor state unknown")
        command = ["/bin/launchctl", "bootout", label]
    else:
        if job.returncode == 0:
            return (
                "Monitoring is already loaded; inspect source freshness in the console."
            )
        if job.returncode != 113:
            raise ValueError("monitor state unknown")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 8766))
        command = ["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)]
    result = run(command, capture_output=True, timeout=10)
    if result.returncode != 0:
        raise ValueError("monitor action outcome requires inspection")
    return "Monitor command accepted. Reload the console to verify availability and source freshness."


def export_evidence():
    c = http.client.HTTPConnection("127.0.0.1", 8766, timeout=6)
    try:
        c.request("GET", "/report.json")
        r = c.getresponse()
        body = r.read(524289)
        if r.status != 200 or len(body) > 524288:
            raise ValueError("export unavailable")
        supplied = json.loads(body)
    finally:
        c.close()
    at = supplied["evaluated_at"]
    timestamp(at)
    raw = supplied["snapshots"]
    if type(raw) is not list or len(raw) > 64:
        raise ValueError("export limit")
    samples = [validate_snapshot(item) for item in raw]
    local_host = load_pilot_configuration(home=owner_home()).host_id
    if any(item["host_id"] != local_host for item in samples):
        raise ValueError("export host differs")
    log = supplied.get("coordinator_log_report")
    if log is not None:
        log = dict(log)
        log.pop("effective_state", None)
        log = validate_log_report(log)
        age = (timestamp(at) - timestamp(log["observed_at"])).total_seconds()
        log["effective_state"] = (
            "unknown"
            if age < 0
            else ("stale" if age > log["freshness_seconds"] else log["state"])
        )
    return dict(
        schema_version=1,
        evaluated_at=at,
        snapshots=samples,
        dashboard=build_dashboard(samples[-1:], [local_host], at),
        coordinator_log_report=log,
        automatic_repair_enabled=False,
        note="Normalized evidence only; reported/stale/unknown values are not independent health proof.",
    )


def native_view(mode):
    from gargoyl.native_views import render_view, valid_view

    view = mode.removeprefix("view-")
    if not valid_view(view):
        raise ValueError("unsupported view")
    try:
        evidence = export_evidence()
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        evidence = None
    record = None
    journal_available = True
    if view == "operation":
        try:
            record = read_operation(str(owner_home() / ".gargoyl-manual-restart"))
        except (OSError, ValueError):
            journal_available = False
    extra = {}
    preview = os.environ.get("GARGOYL_PREVIEW") == "1"
    if view.startswith("fleet") or view == "management":
        from gargoyl.fleet_aliases import AliasStore
        from gargoyl.fleet_identity import pilot_identity
        from gargoyl.fleet_state import FleetCache, effective_lifecycle, utc_now
        home = owner_home()
        at = utc_now()
        cache = FleetCache(home / "Library/Application Support/Gargoyl", os.getuid())
        try:
            extra["inventory"] = cache.read(at)
        except (OSError, ValueError):
            extra["inventory"] = None
        try:
            extra["lifecycle"] = effective_lifecycle(cache, at)
        except (OSError, ValueError):
            extra["lifecycle"] = None
        try:
            extra["local"] = pilot_identity(home, at)
        except (OSError, ValueError):
            extra["local"] = None
        try:
            extra["aliases"] = AliasStore(home / "Library/Application Support/Gargoyl", os.getuid()).read()
        except (OSError, ValueError):
            extra["aliases_available"] = False
        extra["local_alias"] = socket.gethostname()
    local_host_id = load_pilot_configuration(home=owner_home()).host_id
    extra["preview"] = preview
    return dict(kind="view", view=view, local_host_id=local_host_id,
                operation_state=(record["state"] if record is not None else "none") if journal_available else "unavailable",
                html=render_view(
        view, evidence, record, journal_available=journal_available,
        local_host_id=local_host_id, **extra))


def alias_inventory(home, now):
    from gargoyl.fleet_aliases import AliasStore
    from gargoyl.fleet_state import FleetCache
    directory = home / "Library/Application Support/Gargoyl"
    inventory = FleetCache(directory, os.getuid()).read(now)
    if inventory is None:
        raise ValueError("account inventory unavailable")
    aliases = AliasStore(directory, os.getuid()).read()
    return dict(kind="fleet-alias-list", providers=[dict(id=p['id'], name=p['name'], alias=aliases.get(p['id'], '')) for p in inventory['providers']])


def set_local_alias(home, request, now, *, owner=console_owner):
    from gargoyl.fleet_aliases import AliasStore
    from gargoyl.fleet_state import FleetCache
    if not owner() or type(request) is not dict or set(request) != {"provider_id", "alias"}:
        raise ValueError("alias request unavailable")
    directory = home / "Library/Application Support/Gargoyl"
    inventory = FleetCache(directory, os.getuid()).read(now)
    if inventory is None:
        raise ValueError("account inventory unavailable")
    AliasStore(directory, os.getuid()).set(request['provider_id'], request['alias'], inventory)


def main():
    # Only a trusted same-owner native process may use these private pipe modes.
    if len(sys.argv) != 2 or not console_owner():
        return 1
    mode = sys.argv[1]
    try:
        if (
            mode in {"fleet-session", "fleet-session-remember", "fleet-restore"}
            and os.environ.get("GARGOYL_PREVIEW") == "1"
        ):
            raise ValueError("preview mode cannot run a fleet session")
        if mode.startswith("view-"):
            payload = json.dumps(native_view(mode), ensure_ascii=False) + "\n"
            if len(payload.encode()) > 590000:
                raise ValueError("view payload limit")
            sys.stdout.write(payload)
            sys.stdout.flush()
        elif mode in {"start-monitor", "stop-monitor"}:
            emit(dict(kind="status", text=control_monitor(mode)))
        elif mode == "activation":
            # Read-only: list the persisted grants and the exact CLI line they imply.
            sys.stdout.write(json.dumps(activation_state()) + "\n")
            sys.stdout.flush()
        elif mode == "set-grants":
            # One explicit per-capability grant set, bound to a typed confirmation.
            if (
                not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode)
                or not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode)
            ):
                raise ValueError("private pipes required")
            emit(set_grants(stream=sys.stdin.buffer))
        elif mode == "status":
            record = read_operation(str(owner_home() / ".gargoyl-manual-restart"))
            emit(
                dict(
                    kind="status",
                    text="No manual operation recorded."
                    if record is None
                    else "Last manual operation: "
                    + record["state"]
                    + " ("
                    + record["reason"]
                    + "). Unresolved intent/unknown cannot be retried or cleared here.",
                )
            )
        elif mode == "export":
            # Read-only payload can be larger; blocking output is confined to this mode.
            sys.stdout.write(
                json.dumps(dict(kind="export", payload=export_evidence())) + "\n"
            )
            sys.stdout.flush()
        elif mode in {"fleet-alias-list", "fleet-alias-set"}:
            from gargoyl.fleet_state import utc_now
            if not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode) or not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
                raise ValueError("private pipes required")
            if mode == "fleet-alias-list":
                emit(alias_inventory(owner_home(), utc_now()))
            else:
                set_local_alias(owner_home(), read_confirmation(sys.stdin.buffer), utc_now())
                emit(dict(kind="status", text="Local alias saved. Source names, actual IDs and provider settings are unchanged."))
        elif mode in {"fleet-session", "fleet-session-remember", "fleet-restore"}:
            from gargoyl.fleet_session import (
                PERSISTENT_SESSION_SECONDS,
                SESSION_SECONDS,
                pipe_wait,
                private_send,
                run_session,
            )
            from gargoyl.fleet_state import FleetCache
            if not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode) or not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
                raise ValueError("private pipes required")
            restored = None
            duration = PERSISTENT_SESSION_SECONDS if mode == "fleet-session-remember" else SESSION_SECONDS
            retry_count = 0
            if mode == "fleet-restore":
                from gargoyl.fleet_account import decode_json, token_valid

                request = read_confirmation(
                    sys.stdin.buffer, timeout=15, decoder=decode_json
                )
                keys = set(request) if type(request) is dict else set()
                if (
                    type(request) is not dict
                    or keys
                    not in (
                        {"purpose", "token", "valid_until"},
                        {"purpose", "token", "valid_until", "retry_count"},
                    )
                    or request["purpose"] != "desktop_account"
                    or not token_valid(request["token"])
                ):
                    raise ValueError("saved account scope unavailable")
                if "retry_count" in request:
                    rc = request["retry_count"]
                    if type(rc) is not int or not 0 <= rc <= 5:
                        raise ValueError("invalid retry count")
                    retry_count = rc
                import math
                import time

                until = request["valid_until"]
                if type(until) not in {int, float} or not math.isfinite(until):
                    raise ValueError("saved account expiry unavailable")
                duration = until - time.time()
                if not 0 < duration <= PERSISTENT_SESSION_SECONDS:
                    raise ValueError("saved account expired")
                restored = request["token"]
            os.set_blocking(sys.stdout.fileno(), False)
            run_session(
                FleetCache(
                    owner_home() / "Library/Application Support/Gargoyl",
                    os.getuid(),
                ),
                owner=console_owner,
                wait=lambda seconds: pipe_wait(
                    sys.stdin.buffer, seconds, console_owner
                ),
                send=private_send,
                initial_token=restored,
                remember=mode == "fleet-session-remember",
                session_seconds=duration,
                retry_count=retry_count,
            )
        elif mode == "reconcile":
            if not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode) or not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
                raise ValueError("private_pipes_required")
            home = owner_home()
            policy = load_pilot_configuration(home=home).require_local()
            directory = str(home / ".gargoyl-manual-restart")
            if read_operation(directory) is None:
                raise ValueError("no_unresolved_operation")
            os.set_blocking(sys.stdout.fileno(), False)
            with ManualJournal(directory) as journal:
                graphical_reconcile(journal=journal,
                                    inspect_target=lambda: observed_target(policy.source, policy.provider_executable, policy.owner_uid),
                                    receive=lambda: read_confirmation(sys.stdin.buffer))
        elif mode == "restart":
            if not stat.S_ISFIFO(
                os.fstat(sys.stdin.fileno()).st_mode
            ) or not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
                raise ValueError("private pipes required")
            os.set_blocking(sys.stdout.fileno(), False)
            home = owner_home()
            policy = load_pilot_configuration(home=home).require_local()
            if "restart" not in policy.grants:
                raise ValueError("restart permission not granted")
            executable, source = policy.provider_executable, policy.source
            target, stamp = installation_preflight(executable, source, policy.owner_uid)

            def inspect():
                if executable_stamp(executable) != stamp:
                    raise ValueError("image changed")
                return observed_target(source, executable, policy.owner_uid)

            with ManualJournal(str(home / ".gargoyl-manual-restart")) as journal:
                graphical_restart(
                    journal=journal,
                    preflight=lambda: installation_preflight(executable, source, policy.owner_uid),
                    inspect_target=inspect,
                    invoke=lambda: invoke_restart(
                        executable,
                        interrupted=type(
                            "NeverInterrupt", (), {"is_set": lambda self: False}
                        )(),
                        progress=lambda text: emit(dict(kind="progress", text=text)),
                    ),
                    receive=lambda: read_confirmation(sys.stdin.buffer),
                )
        else:
            return 1
        return 0
    except BaseException as error:
        reconciliation_reasons = {
            "no_unresolved_operation": "Reconciliation unavailable: no unresolved operation is recorded.",
            "restart_still_running": "Reconciliation unavailable: the prior command is still running. Nothing was recorded.",
            "restart_may_still_be_running": "Reconciliation unavailable: an unidentified prior command may still be running. Wait for the conservative command bound; no retry or force is performed.",
            "operation_changed": "Recorded operation changed. Review it again before confirming; nothing was recorded by this request.",
            "observation_changed": "Provider observation or owner changed. Review again; nothing was recorded by this request.",
            "confirmation_unavailable": "Reconciliation cancelled or confirmation expired. Nothing was recorded.",
        }
        explanation = reconciliation_reasons.get(str(error)) if mode == "reconcile" else None
        emit(
            dict(
                kind="unavailable",
                text=explanation or "Action unavailable, cancelled, or completion unverified. No automatic retry. View operation status; unknown intent remains blocked.",
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
