"""Owner-local explicit operator commands. No credentials, enrollment or automatic repair."""

import json
import os
import signal
import sys

from gargoyl.cli import _Parser, _StopFlag
from gargoyl.collector import collect
from gargoyl.collector_local_diagnostics import LocalDiagnostics
from gargoyl.dashboard.runtime import utc_now
from gargoyl.manual_restart import (
    ManualJournal,
    executable_stamp,
    installation_preflight,
    invoke_restart,
    observed_target,
    owner_home,
    run_restart,
)
from gargoyl.pilot_configuration import load_pilot_configuration


def main(argv):
    parser = _Parser(prog="gargoyl tools", description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    inspect = commands.add_parser(
        "inspect",
        help="Read normalized state/model/connection/native evidence; no provider command.",
    )
    inspect.add_argument("--input", required=True)
    inspect.add_argument("--owner-uid", type=int, required=True)
    inspect.add_argument("--host", required=True)
    inspect.add_argument("--provider-executable", required=True)
    restart = commands.add_parser(
        "restart",
        help="Interactive manual graceful restart of this installation; never automatic.",
        description="Manual restart requires an interactive terminal, explicit installation-scoped confirmation and verified preflight. One graceful no-force invocation; an unknown outcome blocks another attempt. No automatic retry. See docs/manual-operator-tools.md for prerequisites and recovery effects.",
    )
    restart.add_argument("--input", required=True)
    restart.add_argument("--owner-uid", type=int, required=True)
    restart.add_argument("--provider-executable", required=True)
    reconcile = commands.add_parser(
        "reconcile",
        help="Read the last manual operation; --record reopens the gate after an unresolved one.",
        description="Without --record: read-only display, creates nothing. With --record (interactive): "
        "for an unresolved operation whose command is no longer running, record the current read-only "
        "observation and permit a later manual restart. Never invokes the provider or retries.",
    )
    reconcile.add_argument("--record", action="store_true")
    try:
        args = parser.parse_args(argv)
    except ValueError:
        print("Invalid operator configuration.", file=sys.stderr)
        return 2
    directory = str(owner_home() / ".gargoyl-manual-restart")
    try:
        if args.action == "inspect":
            d = LocalDiagnostics(
                executable=args.provider_executable,
                owner_uid=args.owner_uid,
                clock=utc_now,
            )
            item = d.collect(args.input, now=utc_now())
            version = dict(state="unknown", value=None, source="daemon")
            try:
                target = observed_target(
                    args.input, args.provider_executable, args.owner_uid
                )
                version = dict(
                    state="observed",
                    value=target["version"],
                    source="daemon",
                    timestamp=target["observed_at"],
                )
            except Exception:
                pass
            print(
                json.dumps(
                    dict(
                        provider_version=version,
                        snapshot=collect(
                            args.host,
                            item.collected_at,
                            item.result.readings,
                            errors=item.result.errors,
                        ),
                        coordinator_logs="not_requested",
                        automatic_repair_enabled=False,
                    )
                )
            )
            return 0 if not item.result.errors else 1
        if args.action == "reconcile" and args.record:
            from gargoyl.manual_restart import reconcile_operation

            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ValueError("interactive terminal required")
            policy = load_pilot_configuration(home=owner_home()).require_local()
            source, executable = policy.source, policy.provider_executable
            label = "MBP-26" if policy.hostname == "MBP-2026.local" else policy.hostname
            with ManualJournal(directory) as journal:
                record = journal.read()
                if record is None or record["state"] not in {"intent", "unknown"}:
                    print("No unresolved manual restart to reconcile.")
                    return 0
                print("Unresolved manual restart", record["operation_id"], "started", record["started_at"])
                print("Reconciling records the current read-only observation and permits a later manual")
                print("restart. It does not prove what the interrupted command did; check that the provider")
                print("is not left draining with automatic restart disabled. Nothing is invoked or retried.")
                if input(f"Type RECONCILE {label} to record: ") != f"RECONCILE {label}":
                    print("Not recorded.")
                    return 1
                result = reconcile_operation(
                    journal,
                    inspect_target=lambda: observed_target(source, executable, os.getuid()),
                )
                print(json.dumps(dict(operation=result, retry_permitted=False,
                                      later_manual_restart_permitted=True)))
                return 0
        if args.action == "reconcile":
            # No new directory/lock/file is created by this read-only command.
            from gargoyl.manual_restart import read_operation

            record = read_operation(directory)
            current = None
            try:
                current = observed_target(
                    str(owner_home() / ".darkbloom/daemon-state.json"),
                    str(
                        owner_home()
                        / ".darkbloom/Darkbloom.app/Contents/MacOS/darkbloom"
                    ),
                    os.getuid(),
                )
            except Exception:
                pass
            print(
                json.dumps(
                    dict(
                        operation=record,
                        current_process_observation=current,
                        observation_is_not_terminal_reconciliation=True,
                        retry_permitted=False,
                        note="Read-only history, not proof that an interrupted upstream request cannot still act. No automatic retry. After checking the provider, `gargoyl tools reconcile --record` records a reconciliation that permits a later manual restart.",
                    )
                )
            )
            return 0
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError("interactive terminal required")
        executable, source, uid = args.provider_executable, args.input, args.owner_uid
        target, stamp = installation_preflight(executable, source, uid)
        policy = load_pilot_configuration(home=owner_home()).require_local(uid)
        label = "MBP-26" if policy.hostname == "MBP-2026.local" else policy.hostname

        def inspect_target():
            if executable_stamp(executable) != stamp:
                raise ValueError("installation changed")
            return observed_target(source, executable, uid)

        def confirm(value):
            print(f"MANUAL RESTART — current provider of this {label} installation")
            print("Executable:", executable, "UID:", uid)
            print(
                "Observed current PID:",
                value["process"]["pid"],
                "birth microseconds:",
                value["process"]["born_us"],
            )
            print("Command: restart --timeout 600 --startup-timeout 180 (no force).")
            print(
                "Accepted work drains before interruption; new work is refused. Existing model/settings are reused by Darkbloom."
            )
            print(
                "The installation current at execution is authorized, not an atomic lock to the displayed PID."
            )
            print(
                "Darkbloom temporarily disables startup/watchdog, changes termination allowance and restores configured recovery; timeout may leave it draining/disabled."
            )
            print(
                "Replacement can resume configured coordinator traffic/authorization and existing startup/update behavior. No new credentials or configuration are supplied."
            )
            print(
                "Budget: up to 840s plus CLI cleanup; unknown outcome blocks another attempt. This is not an unattended 30-second repair."
            )
            return input(f"Type RESTART {label} to invoke once: ") == f"RESTART {label}"

        stop = _StopFlag()
        previous = {}
        with ManualJournal(directory) as journal:
            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous[sig] = signal.signal(
                        sig, lambda *unused: setattr(stop, "requested", True)
                    )

                def invoke(record_child):
                    # Revalidate installation/recovery immediately before invoking.
                    fresh, current_stamp = installation_preflight(
                        executable, source, uid
                    )
                    if (
                        stop.is_set()
                        or fresh["process"] != target["process"]
                        or current_stamp != stamp
                    ):
                        raise ValueError("target changed or interrupted")
                    return invoke_restart(executable, interrupted=stop, progress=print,
                                          started=record_child)

                run_restart(
                    journal,
                    target,
                    inspect_target=inspect_target,
                    invoke=invoke,
                    confirm=confirm,
                    progress=print,
                    invoke_with_child=True,
                )
                return 0
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
    except (Exception, KeyboardInterrupt) as error:
        if str(error) == "existing_watchdog_required":
            print(
                "Manual restart blocked: the existing provider watchdog is not verified running. Gargoyl will not newly enable unattended recovery.",
                file=sys.stderr,
            )
        print(
            "Operator action unavailable, refused, or outcome unknown. No automatic retry. Inspect tools reconcile and current read-only evidence.",
            file=sys.stderr,
        )
        return 1
