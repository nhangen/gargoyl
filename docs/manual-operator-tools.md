# Explicit local operator tools

Automatic Gargoyl repair remains disabled. Its existing launchd KeepAlive restarts
Gargoyl itself, not Darkbloom. These tools are distinct from the signed unattended
pre-drained restart protocol. They do not require new keys or enrollment. Installation
never invokes a provider action. The opt-in monitor console (`--operator-tools
--enable-restart`) offers the same manual restart in a browser, using this journal,
lock, gate, preflight and invocation; see [operator console tools](operator-tools.md).

## Useful supported tools

| Tool | Implemented behavior and limit |
| --- | --- |
| `gargoyl status --port 8766` | Local viewer response only; not proof of source health. |
| `gargoyl tools inspect` | Explicit protected state-file/native-process collection: normalized counters, model residency claim, connection and eligibility where supported, and daemon-reported pinned version. No status/doctor command, credential/config loading or additional log query. |
| Live console refresh | Browser refresh or automatic 2-second refresh evaluates current stored memory. It does not force a source poll or restart a provider. Source timestamp/TTL remain visible. |
| `/report.json` on local monitor | Bounded normalized 64-sample memory history, dashboard projection and scoped redacted log metadata. Query evidence retains original timestamps and separate effective freshness. No raw logs, model names, credentials or executable paths. Export grants no action authority. |
| `gargoyl tools restart` | Interactive installation-scoped manual graceful restart, described below. No HTTP button or unattended action. |
| `gargoyl tools reconcile` | Read-only last-operation history and current native-process observation. Creates nothing and clears nothing. |
| `gargoyl tools reconcile --record` | Interactive (`RECONCILE MBP-26`). For an unresolved operation whose recorded command is no longer running, records the current read-only observation and reopens the gate for a later manual restart. Never invokes the provider or retries; does not prove what the interrupted request did. |
| Existing `inspect state/status/doctor` | Parses explicitly supplied bytes. `capture status/doctor` is separate opt-in command acquisition: upstream may read keys/config, use network/helpers and perform diagnostic side effects. These are not automatically run by this tool set. |

Example read-only inspection:

```sh
gargoyl tools inspect --input "$HOME/.darkbloom/daemon-state.json" \
  --owner-uid 501 --host 00000000-0000-4000-8000-000000000001 \
  --provider-executable "$HOME/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom"
```

Inspect output keeps native observations separate from daemon reports and unknown,
stale or unsupported evidence. It never treats low traffic as failure or error
counts as a root cause. Exports are local operator files; inspect them before
sharing. The daily log-review automation's scope is unchanged.

## Manual restart policy and consent

The supported production CLI in inspected Darkbloom 0.10.5/0.10.6 implements
`restart --timeout 600 --startup-timeout 180`. It refuses new work, drains accepted
work with matching acknowledgements, then reloads the installed service and checks
startup authorization. Gargoyl invokes exactly this command once, without `--force`,
configuration overrides, shell expansion or retry. The source evidence is
`RestartCommand.swift`, `ServiceDrain.swift`, `ServiceDrain+Recovery.swift` and
`LaunchAgent.swift` in the matching upstream tag. This is a manual supported
operation, not the stricter cleanup-inclusive 30-second unattended policy.

```sh
gargoyl tools restart --input "$HOME/.darkbloom/daemon-state.json" \
  --owner-uid 501 \
  --provider-executable "$HOME/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom"
```

This pilot command is limited to UID501 on MBP-2026.local, the canonical production
installation and its protected fresh source. It requires the matching ordinary
provider launchd job, no custom-config/local-endpoint/cluster/supervisor arguments,
and an already-running provider watchdog. If recovery is not already running,
Gargoyl refuses rather than newly enabling it. Unsupported configurations require
a separate policy/access review; no setting is rewritten to pass preflight.

The interactive confirmation shows the executable, UID, current PID/birth and exact
command. The operator must type `RESTART MBP-26`. Consent is for this installation's
**current provider at execution**, not a compare-and-swap promise to the displayed
PID: upstream selects the current provider internally. Gargoyl revalidates before
invocation, but cannot make that race atomic. Existing installed model/configuration
arguments are reused by upstream, not independently attested by Gargoyl.

The interruption/recovery effects are explicit: Darkbloom temporarily disables
startup/watchdog, removes prior recovery history, updates termination allowance,
reloads the service and restores configured recovery. Drain/startup timeouts can
leave it draining or disabled. Replacement resumes existing coordinator traffic,
authorization and configured startup/update behavior. No new credentials are
supplied, and Gargoyl does not read credential files. This implementation does not
invoke or test a restart against the live provider.

## Durable intent, progress and unknown outcomes

The manual CLI uses a fixed private `~/.gargoyl-manual-restart` directory, exclusive
installation-wide lock and atomic fsync-before-invocation last-operation record, including syncing the parent directory on first use.
It records only normalized identity, version, phase/times and outcome. A second
process cannot submit while the first holds the lock. An unresolved durable intent
or unknown outcome blocks all later invocations, from the CLI and the console, until a
read-only reconciliation is recorded; changing arguments cannot select a different
journal to bypass that gate. There is no reset that skips reconciliation. After the
command starts, its PID and kernel start time are added to the record so reconciliation
refuses while that exact command is still running.
The bounded record retains the last operation, not a complete audit history.

Progress says what is known: intent saved, upstream command running, verification,
and terminal/unknown outcome. The CLI discards raw child output, so detailed
upstream phase and accepted-work counts are unknown there. The console sends output to a
private file in the journal directory, shows normalized progress from Darkbloom's fixed
messages, and deletes the file afterwards. CLI exit 0 alone is insufficient:
Gargoyl also requires a different native PID/birth, unchanged pinned version and fresh matching daemon state.
It reports upstream CLI success plus independently observed replacement, not an
independent protocol/earnings verdict or an exactly-once guarantee.

The wrapper waits up to 840 seconds, then sends TERM only to its own CLI child and
waits up to 2 seconds. Interrupting/killing a CLI does not cancel accepted upstream
work. No provider/process-group SIGKILL, restart retry or blind unfencing occurs.
On interruption, nonzero exit, timeout, changed target or failed verification, the
record is unknown and the repeat gate remains. Reconciliation (console button or
`tools reconcile --record`) is the owner's explicit decision to reopen it after checking
the provider: it records the current observation (original process, different process,
or unobservable) but cannot prove a permanent no-pending outcome across an upstream
crash. Deleting the journal is not a supported remedy. The console never interrupts a
running restart when the monitor stops; the record then stays unresolved.

Tests use synthetic files, mocks and adversarial lifecycle outcomes. No real
provider restart, drain, watchdog update, credential access or unattended repair
activation is part of acceptance verification.
