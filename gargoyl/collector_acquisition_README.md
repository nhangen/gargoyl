# Trusted producer acquisition

This module is integration code for an explicitly trusted POSIX producer. It does
not discover or download executables, load credentials, install services, invoke
upstream commands during tests, or provide an OS sandbox. No production host has
been validated. Operator-selected executable, environment and working directory
are required before calling it; a source commit is not proof of installed-binary
identity or trust in that binary's helper programs/imports.

## Upstream behavior and later host authorization

The pinned [Darkbloom source](https://github.com/darkbloomdev/darkbloom/blob/a6f7f483ab88806c633e37e00339c13e37ab62f4/provider/src/main.rs)
performs a network update check before both commands. Status reads the provider
log, configuration/account state and model inventory, invokes security checks and
fetches a catalog. Doctor invokes helper programs, imports installed Python
packages, reads existing Secure Enclave-backed key material and contacts coordinator
health. The fixed invocations are `executable status` and `executable doctor`;
there is no verified flag in this interface to suppress all those side effects.
Real invocation needs later target-specific authorization and operator trust in
those dependencies. No arbitrary arguments, shell, inherited environment or
configuration repair path is supported. The explicitly supplied environment can
influence upstream dependency resolution; its selection is a trust decision.

## API and bounds

`BoundedAcquirer(executable, *, environment, cwd, wall_clock, monotonic_clock,
total_timeout_seconds=5.0, cleanup_grace_seconds=1.0, max_output_bytes=65536)`
requires absolute executable/cwd strings and a copied explicit environment mapping.
Budgets are finite numbers (not booleans): `0 < grace < total <= 30` seconds and
`1 <= max_output_bytes <= 65536`. Default successful observations have TTL 60.
Invalid configuration or prelaunch clock values raise generic `PolicyError`.
Trusted clock callbacks must return promptly; this is not a hard real-time system.

`acquire(source_kind, *, stop_event)` supports only `darkbloom_status_text_v1` and
`darkbloom_doctor_text_v1`. It returns the frozen dataclass:

    AcquisitionResult(source_kind, observed_at, completed_at,
                      result: AdapterResult, cleanup_complete: bool)

The UTC start time is the conservative observation timestamp. The UTC completion
time is operational metadata, not a replacement for evidence time. No raw text,
paths, exception strings or command output are returned or logged. The contained
readings are revalidated by the runtime; frozen dataclasses do not imply nested
mapping immutability.

At most one acquisition runs per instance. The child has closed stdin, its own
POSIX session/process group, and separate nonblocking output pipes. Both output
streams count toward one byte budget. Stderr is counted and discarded; stdout is
retained in bounded memory only until parsing. Overflow discards partial evidence.
A monotonic execution deadline reserves cleanup grace from the total budget; an
independent real elapsed guard prevents a frozen injected clock from extending it.
Defaults allow four seconds of execution and reserve one second for cleanup.
Process creation and OS scheduling cannot be preempted by Python; if they consume
the budget, cleanup is attempted immediately and incomplete cleanup is explicit.

On completion/failure/cancellation, pipes are closed without unbounded draining.
The owned group receives TERM, then KILL after half the available cleanup grace
if necessary. The direct child is polled/reaped without an unbounded wait.
`cleanup_complete` requires a reaped direct child and confirmed disappearance of
its process group. Inaccessible groups, unreaped descendants/zombies or exhausted
grace yield false. This halts subsequent acquisition on that instance and must
stop the caller's foreground lifecycle. It cannot guarantee cleanup of descendants
that escape the group, or process/resource containment of malicious code. It does
not impose an OS-wide process-count limit.

## Fixed failure semantics

| Condition | Adapter result |
| --- | --- |
| Execution deadline | No readings, `timeout` |
| Launch permission failure | No readings, `permission_denied` |
| Missing executable, nonzero/signal exit, overflow, cancellation, invalid running clock or other execution failure | No readings, `unavailable` |
| Successful complete execution but malformed text | No readings, `invalid_state` |
| Cleanup cannot be confirmed | No readings, existing failure or `unavailable`; `cleanup_complete=False` |

Pre-set cancellation starts no child. The scheduler also checks its stop event to
avoid committing shutdown-only samples or starting another acquisition. A valid
looking partial status line before timeout or failed exit is never accepted.

`CollectorRuntime.collect_acquired(results)` takes a dictionary keyed by source
kind and returns one persisted v1 snapshot. There is no cadence gate: foreground
scheduling owns it. Each result's kind, cleanup flag, allowed metric/source,
60-second TTL, exact timestamp and complete telemetry metadata are validated
before persistence. Acquisition failure cannot accompany readings. Successful
independent sources remain available when another fails; missing sources become
unknown. The v1 wire format has only its existing aggregate error code, no invented
per-source attribution. Multiple errors have deterministic source-kind ordering.

Future-relative observations after wall-clock rollback are validated and then
withheld with `invalid_state`, never redated. Other source timestamps remain intact
and age normally. Incomplete cleanup raises a generic policy error before any
snapshot is persisted. The original bytes-based `collect_tick` remains compatible.

## Verification

Use `python -m ruff check .` and `python -m unittest discover -s tests -v` in the
project virtual environment. Acquisition tests create and execute only their own
short synthetic Python fixture under a temporary directory. They cover fixed
arguments/environment, byte boundaries, floods, invalid UTF-8, nonzero/signal exit,
hangs, child-held pipes, cancellation, invalid clocks and incomplete cleanup. The
runtime tests verify ownership/privacy rejection, independent failures, stale and
future observations and no timestamp refresh. These are synthetic POSIX tests,
not live Darkbloom/macOS compatibility, host permission or production acceptance.
