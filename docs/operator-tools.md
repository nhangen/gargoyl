# Operator tools and manual restart

`gargoyl monitor` can serve private operator tools next to the read-only dashboard.
They are off by default. The public `http://127.0.0.1:<port>/` page is unchanged:
read-only, no forms, no actions.

## Run

Operator tools need the same explicit Darkbloom image used for native diagnostics
(macOS only). Manual restart is a second, separate opt-in with its own private
record directory:

```sh
mkdir -m 700 -p "$HOME/Library/Application Support/Gargoyl/restart"
.venv/bin/gargoyl monitor \
  --input /Users/nhangen/.darkbloom/daemon-state.json \
  --owner-uid 501 \
  --host 00000000-0000-4000-8000-000000000001 \
  --interval 5 --port 8765 \
  --provider-executable /Users/nhangen/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom \
  --operator-tools \
  --enable-restart \
  --restart-state-dir "$HOME/Library/Application Support/Gargoyl/restart"
```

Startup prints two links. The first is the public dashboard. The second,
`http://127.0.0.1:8765/s/<token>/`, is the private operator area; a new token is
generated each time the monitor starts. Keep it private: anyone with the link can
run the tools. It is never stored in a cookie (browsers share `127.0.0.1` cookies
across ports) and is never shown on the public page. If the monitor runs as a
LaunchAgent, the link is written to its standard output log.

`--operator-tools` alone enables the read-only tools. `--enable-restart` requires
`--operator-tools` and `--restart-state-dir`. Omitting `--enable-restart` leaves the
restart page absent and the inventory row shows "not enabled". Nothing enables
unattended repair; there is no automatic restart, retry or schedule.

## Capability inventory

| Tool | Effect | Status |
|---|---|---|
| Refresh diagnostics now | Read-only | Collects immediately via the existing poll loop |
| Provider version and build | Read-only, runs `darkbloom --version` | Also compares the executable's SHA-256 with the recorded 0.10.5/0.10.6 builds |
| Daemon status | Read-only, runs `darkbloom status` (network update check) | Keeps only the daemon running/stopped line |
| Doctor checks | Read-only, runs `darkbloom doctor` with no flags (network) | Keeps only pass/warn/fail/info counts and the exit status |
| Health, model and connection evidence | Read-only | Dashboard per-source evidence; model names withheld |
| Traffic and normalized history | Read-only | Last 64 in-memory observations |
| Export redacted diagnostics | Read-only | JSON: normalized observations, tool summaries, restart outcomes; no raw output, paths, model names or logs |
| Local details | Read-only | Configured files, executable, version, digest, record location |
| Manual provider restart | Changes service state | Available with `--enable-restart` |
| Coordinator protocol compatibility | — | Unsupported: no evidence source in 0.10.5/0.10.6 |
| Raw log export or streaming | — | Unsupported by design: raw logs can hold prompts, identifiers and keys |
| Earnings or payout verification | — | Unsupported: counters aren't settlement evidence |
| Stop/start, forced restart, clear backend guard, update | Changes service state | Proposed only, not implemented; each needs a separate decision |

Checks that run Darkbloom use fixed argument vectors, a minimal explicit
environment (`HOME`, `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `LANG=C`, `NO_COLOR`,
`TERM=dumb`, `USER`), a deadline with verified cleanup (5 s, 20 s, 45 s) and a
64 KiB output cap. One check runs at a time. Raw output is parsed in memory and
discarded. These commands may read Darkbloom configuration and use the network;
this is not a sandbox.

## Manual restart

The restart page shows the exact target and command before anything runs:

- Host, provider PID and process start time (from the fresh state file),
  confirmed by the kernel (`libproc`) on macOS; Darkbloom version and trust status.
- Command: `darkbloom restart --timeout 600 --startup-timeout 180` (Darkbloom's
  own defaults, stated explicitly). `--force` is never passed.
- Expected interruption: new work refused when the drain starts; accepted
  requests may finish for up to 10 minutes and the coordinator must acknowledge;
  the provider stops and relaunches with its existing configuration and model,
  and doesn't serve until freshly authorized (up to 3 minutes). If the drain
  doesn't finish, nothing is restarted but Darkbloom leaves the provider draining
  with automatic restart disabled.

Restart is offered only when all of these hold; otherwise the page says which failed:
installed version is 0.10.5 or 0.10.6 **and** its SHA-256 is the recorded release
build; the executable file hasn't changed since the monitor inspected it; the
state file is fresh (≤ 60 s), reports the same version and a process identity;
the kernel confirms that process; no earlier attempt is unresolved.

Submitting requires typing the first 8 characters of the host ID. The form carries
the target the page showed; if the provider process changed since, the request is
refused. Each form has a single-use nonce, so a double click or a replayed
submission never starts a second attempt.

### Durability, progress and outcome

1. The attempt is written to `restart.json` in the private record directory
   (mode 0600, fsync, atomic rename) **before** Darkbloom runs. The directory is
   locked, so two monitors can't share it.
2. Darkbloom runs in its own session with output to a private file in that
   directory, not a pipe. Stopping the monitor neither signals it nor breaks its
   output. Gargoyl never kills it: interrupting Darkbloom mid-drain is not a rollback.
3. Progress comes from Darkbloom's fixed messages (draining, requests remaining,
   awaiting acknowledgement, relaunched, authorized). Unrecognised lines are only
   counted. The output file is deleted once the outcome is recorded.
4. **Verified** means: Darkbloom reported a relaunch and fresh authorization with
   exit status 0, *and* a fresh state file then names a different process that the
   kernel confirms. Anything less is recorded but not verified.

### Uncertain outcomes and reconciliation

Every outcome other than verified keeps restart blocked: drain incomplete,
relaunched but unconfirmed, refused by Darkbloom, an unexpected forced
lifecycle, unrecognised output, or a monitor stopped mid-restart (the next
monitor finds the claim, watches a still-running command by PID and start time,
and records the outcome as unknown). Gargoyl never retries.

**Reconcile** is a read-only action: it refuses while the command still runs,
reads the current state (process identity, kernel confirmation, trust status),
records what it saw and reopens the gate. It does not prove what happened during
the attempt; check the dashboard and Darkbloom first, especially for a provider
left draining with automatic restart disabled.

### Guarantees, honestly

- Guaranteed: durable claim before execution; one attempt at a time per record
  directory; no duplicate submission; no automatic retry; uncertain outcomes stay
  blocked until an explicit read-only reconciliation.
- **Not** guaranteed: durable exactly-once execution. A crash after the command
  starts but before its PID is recorded leaves an unknown outcome. Darkbloom 0.10.x
  keeps no durable cross-restart request ledger, and its lifecycle lease is released
  before fresh-authorization confirmation (see
  [restart evidence](darkbloom-restart-evidence.md)). Separate record directories
  or someone running `darkbloom restart` directly bypass this monitor's gate.
- Not authenticated per person: the private link and same-user OS boundary are
  the access control. Any process running as this user can already run Darkbloom.

## Request protection

Private routes live under `/s/<token>/`. The token is compared in constant time;
a wrong token is a 404. Every POST must carry the exact `Host` and `Origin`,
`Sec-Fetch-Site: same-origin` when present, `application/x-www-form-urlencoded`
at most 2 KiB, and an unexpired single-use nonce for that form. Private pages use
`Referrer-Policy: same-origin` (under `no-referrer`, browsers send `Origin: null`
on POST) and `form-action 'self'`; they load no external resources. The
confirmation page never auto-refreshes; the status page refreshes every 2 s only
while a restart runs.

## Testing

`tests/test_operator_tools.py` runs a self-authored fake `darkbloom` that prints
the exact 0.10.5/0.10.6 messages and rewrites a private state file. It covers every
outcome class and the verified path, kernel rejection, changed targets,
unsupported/unrecorded/replaced builds, stale state, concurrency, a monitor
restarting mid-attempt with the command still running, a claim without a recorded
child, record-directory permissions and locking, and real HTTP guards (Origin,
fetch metadata, type, size, token, nonce replay, double submit, redaction). No
test runs or contacts a real provider. Browser QA used the same fake behind a real
monitor at 1440 and 390 px.

Not tested here: a real Darkbloom restart on macOS. Run one deliberately, once,
when you're ready to accept a provider interruption.
