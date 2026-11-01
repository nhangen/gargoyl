# Operator console tools

`gargoyl monitor` can serve a private operator console, an admin panel for this
Mac's provider, next to the read-only dashboard.
They're off by default. The public `http://127.0.0.1:<port>/` page and `/report.json`
are unchanged: read-only, no forms, no actions, and they keep their original strict
headers (`Referrer-Policy: no-referrer`, `form-action 'none'`) even with tools enabled. Manual restart in the console is the
same operation as `gargoyl tools restart`; its policy, preflight and guarantees are in
[manual operator tools](manual-operator-tools.md).

## Run

```sh
.venv/bin/gargoyl monitor \
  --input /Users/nhangen/.darkbloom/daemon-state.json \
  --owner-uid 501 \
  --host 00000000-0000-4000-8000-000000000001 \
  --interval 5 --port 8765 \
  --provider-executable /Users/nhangen/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom \
  --operator-tools \
  --enable-restart
```

- `--operator-tools` (requires `--provider-executable`, so macOS) enables the read-only tools.
- `--enable-restart` (requires `--operator-tools`) adds manual restart in the console.
  There is no journal-path option: the console uses the CLI's fixed
  `~/.gargoyl-manual-restart` journal, lock and gate.

Startup prints the public link and a private one, `http://127.0.0.1:8765/s/<token>/`,
with a new token each start. Keep it private; anyone with it can use the tools. It's
never stored in a cookie (browsers share `127.0.0.1` cookies across ports) and never
appears on the public page. Under a LaunchAgent it's written to the standard output log.

## Capability inventory

| Tool | Effect | Status |
|---|---|---|
| Refresh diagnostics now | Read-only | Immediate collection through the poll loop |
| Provider version and build | Read-only, runs `darkbloom --version` | Also hashes the executable against the recorded 0.10.5/0.10.6 builds (shown, not a restart condition) |
| Daemon status | Read-only, runs `darkbloom status` (network update check) | Keeps only the daemon running/stopped line |
| Doctor checks | Read-only, runs `darkbloom doctor` with no flags (network) | Keeps pass/warn/fail/info counts and the short names of failed and warning checks (up to 12 each); details are discarded; never `--clear-backend-guard` |
| Health, model and connection evidence | Read-only | Dashboard per-source evidence; model names withheld |
| Traffic and normalized history | Read-only | Last 64 in-memory observations |
| Export redacted diagnostics | Read-only | The monitor's `/report.json` |
| Local details | Read-only | Files, executable, version, digest, journal location |
| Manual provider restart | Changes service state | With `--enable-restart`; shares the CLI gate |
| Coordinator protocol compatibility | — | Unsupported: no evidence source in 0.10.5/0.10.6 |
| Raw log export or streaming | — | Unsupported by design (prompts, identifiers, keys) |
| Earnings or payout verification | — | Unsupported: counters aren't settlement evidence |
| Stop/start, forced restart, clear backend guard, update | Changes service state | Proposed only, not implemented |

The tools page lists each tool as a card marked read-only or changes service
state; tools that aren't available on this run are collapsed under a disclosure
with the reason (for example, restart without `--enable-restart`).

Checks that run Darkbloom use fixed arguments, a minimal environment, a deadline with
verified cleanup (5 s, 20 s, 45 s), a 64 KiB output cap and one check at a time. Raw
output is parsed in memory and discarded. They may read Darkbloom configuration and use
the network; this isn't a sandbox.

## Manual restart in the console

The page runs the CLI's installation preflight (pilot only: macOS, UID 501,
MBP-2026.local, canonical paths, plain launchd provider job, running watchdog, fresh
kernel-confirmed state, matching `--version`) and shows the target PID and start time,
version, executable, the exact command `darkbloom restart --timeout 600
--startup-timeout 180`, the expected interruption and what isn't guaranteed. If
preflight fails it says so and offers nothing.

To restart, type the first 8 characters of the host ID. The form carries the process
the page showed; a different current process is refused. Each form has a single-use
nonce, so a double click or replay never starts a second attempt. Then the console:

1. Takes the shared journal lock. If `gargoyl tools restart` holds it, the console refuses.
2. Calls `run_restart`: durable fsynced intent, revalidated preflight, one
   `invoke_restart`, then verification (exit 0 **and** a different kernel-confirmed
   process with fresh matching state).
3. Records the child's PID and start time (the CLI does too), and sends Darkbloom's
   output to a private file in the journal directory. The status page always shows
   elapsed time against the 14-minute bound. Phases (draining, requests remaining,
   awaiting acknowledgement, relaunched, authorized) are parsed from Darkbloom's fixed
   messages, but Darkbloom may only write its output when the command finishes, so
   phases can lag or appear only at the end. The file is deleted when the attempt
   ends; if the monitor stopped mid-restart it's removed on reconcile or the next attempt.

The status page refreshes every 2 seconds while running and then shows **Verified
restart** with the replacement process, or **Unresolved** with the reason when known
(drain incomplete, relaunch unconfirmed, refused, unrecognised) and numbered
"What to do next" steps leading to reconcile. Stopping the monitor doesn't stop the restart:
the record stays unresolved and the next monitor shows it.

### Reconcile

Every outcome except verified blocks the next restart, in the console and the CLI.
**Reconcile** (console form with the typed host prefix, or `gargoyl tools reconcile
--record` with `RECONCILE MBP-26`) is read-only. It refuses while the recorded command
is still running (same PID and start time; if the start time couldn't be read, while
any process holds that PID), and for 15 minutes after the attempt started when no child
was recorded at all (a crash between spawn and the record write). Otherwise it reads
the current kernel-confirmed provider state, records the observation and reopens the
gate. It never invokes Darkbloom and never retries. It records the present; it doesn't
prove what happened during the attempt, so check the dashboard first, especially for a
provider left draining with automatic restart disabled.

## Request protection

Private routes live under `/s/<token>/` (constant-time comparison; a wrong token is a
404). Every POST needs the exact `Host` and `Origin`, `Sec-Fetch-Site: same-origin`
when sent, `application/x-www-form-urlencoded` up to 2 KiB, and an unexpired
single-use nonce (pooled per form, so tool forms can't evict an open restart form; a
used or expired form says so and starts nothing). The body has its own 5-second read
deadline. Private pages use `Referrer-Policy: same-origin` (under `no-referrer`
browsers send `Origin: null` on POST) and `form-action 'self'`, and load nothing
external. The confirmation page never auto-refreshes.

The token protects against other local users and web pages. Any process running as the
same user can already run Darkbloom directly.

## Testing

`tests/test_operator_tools.py` drives the real `ManualJournal`, `run_restart`,
`invoke_restart`, `observed_target` and `reconcile_operation` with a self-authored fake
`darkbloom` that prints the exact 0.10.5/0.10.6 messages and rewrites a private state
file. Only the pilot-host preflight and the macOS kernel check are substituted. It
covers the verified path, each uncertain outcome blocking until reconcile, kernel
rejection, a changed target, the CLI holding the lock, concurrency, live progress,
reconcile refusing while a recorded child is alive, unsafe record permissions and the
HTTP guards, typed reconcile confirmation, outcome text bound to its operation, and
strict public headers. No test contacts or restarts a real provider. A real restart on the pilot
Mac has not been run.
