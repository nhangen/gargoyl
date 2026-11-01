# Continuous single-host read-only monitor

Install into an isolated virtual environment (Python 3.11 or newer):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install /absolute/path/to/gargoyl-0.1.0-py3-none-any.whl
```

Choose a stable opaque UUID for this host. It is an inventory label, not a key,
credential or enrollment grant. Explicitly provide the owner UID and canonical
absolute source path. Never use sudo or relax source permissions to make a read
succeed. On macOS `/var` and `/tmp` are symlinks; canonicalize paths before use.

Start in a terminal (MBP-26 pilot example, already authorized owner-local source):

```sh
.venv/bin/gargoyl monitor \
  --input /Users/nhangen/.darkbloom/daemon-state.json \
  --owner-uid 501 \
  --host 00000000-0000-4000-8000-000000000001 \
  --interval 5 --port 8765
```

Open `http://127.0.0.1:8765/`. The first poll is immediate, subsequent polls use a
monotonic schedule (1–60 seconds, default 5). Missed intervals are skipped rather
than replayed. HTTP serving runs independently of polling. The browser reloads
every two seconds, including error responses. The existing bounded header reads,
Host/Origin checks, CSP and no-store policy apply. Only numeric IPv4 loopback is
bound; no remote interface option exists. A busy port fails without replacing or
signaling an existing process. The monitor enables `SO_REUSEADDR` to restart
its same loopback port after prior HTTP connections enter `TIME_WAIT`;
`SO_REUSEPORT` remains disabled, and an active listener cannot be displaced.
`--port 0` chooses an ephemeral port printed at startup.

In another terminal:

```sh
.venv/bin/gargoyl status --port 8765
```

Status exits 0 when the local Gargoyl viewer answers successfully, 1 when it is
unavailable. It does not establish producer freshness, collection cadence or host
health; check poll count, source timestamps, errors and evidence states in the page.
No remote request, credential or PID file is involved. Stop with Ctrl-C in the
owning terminal, or send SIGTERM to that known foreground process. Both stop
polling, finish any active bounded HTTP request, join the viewer and close the
listener. Repeated signals request the same graceful stop. Restart by running the
same command. Configuration is explicit CLI arguments; nothing is auto-discovered.

## Evidence and privacy

Every poll uses the shared strict owner-local state reader unchanged: private
owner-matched parent, owned regular single-link file, no symlink traversal, bounded
64 KiB input and strict schema validation. No producer command runs and no repair
module is constructed. Only allowlisted metrics, fixed errors and timestamps reach
the UI. Raw source data, model names, identities and exception strings are omitted.

Current evidence uses the latest poll exclusively. Missing, malformed, oversized,
future or permission-denied source evidence becomes unknown with a fixed read
error; a previous good sample cannot supply current counters. A stale source keeps
its original timestamp and stale state even while the collector heartbeat is
current. Empty valid sources remain unknown. Repeated values are cumulative
observations, not usage deltas, earnings, daemon liveness or proof of inference.
Detailed evidence is evaluated against the current clock on every browser request.

`clock_skew_seconds` stays unknown in this monitor: no independent reference
time is configured. A fresh collector timestamp does not prove clock agreement.

The last 64 normalized samples remain in process memory for recent traffic
inspection. Nothing is persisted to disk or delivered to another service; no keys
are generated or loaded. Restart clears history. This local runtime deliberately
does not activate encrypted durable fleet spooling, mTLS delivery, registry grants
or multi-host ingestion. Those existing APIs require separately supplied keys and
explicit deployment configuration. This avoids introducing credentials to the
read-only pilot. Collection/storage failures stop the process with exit 1 and a
fixed error; source read failures keep polling for recovery. Invalid caller
configuration exits 2 before opening the source or binding the listener. The source
path must be an absolute UTF-8 string of at most 4096 characters with no empty,
`.` or `..` components or NUL characters; the expected UID must be an integer
from 0 through 2^32−2. Filesystem operations are not forcibly time-bounded.

## Optional user-level persistence (not activated)

A service manager can execute the exact absolute `.venv/bin/gargoyl monitor ...`
argument vector above with the same ordinary user, owner UID, canonical path,
interval and port. Use a private user-owned service file and a trusted local source.
No environment variables or credentials are required. A macOS LaunchAgent may use
`ProgramArguments` for that vector, `RunAtLoad` and `KeepAlive` only after an explicit
choice to enable login persistence; remove/unload it to disable persistence.
Gargoyl neither installs nor enables any service. Do not add OS grants or change
security settings without separate approval. Foreground start/stop/status is fully
implemented; no login/boot service is running as a result of installation.

## Verification

`python -m unittest discover -s tests -p test_monitor.py -v` checks real loopback
requests, independent repeated polling, Host rejection, missing/malformed recovery,
stale/future timestamps, ownership protection, bounded history, restart and actual
SIGINT/SIGTERM shutdown. Fixtures contain synthetic private text that must never
appear in HTML. Real HTTP/socket regressions also verify immediate same-port
restart, refusal to displace an active listener, preserved Host/Origin rejection,
and disabled `SO_REUSEPORT`. These tests do not read the real daemon or execute repairs.

A prepared, inactive [LaunchAgent example](examples/dev.gargoyl.monitor.plist)
contains the MBP-26 arguments. Replace its absolute venv placeholder before any
use. Both persistence flags are false. It is documentation only and has not been
copied into `~/Library/LaunchAgents`, loaded or enabled.

## Operator console tools (opt-in)

`--operator-tools` (and `--enable-restart`) add private read-only checks and the
confirmed manual restart to this monitor; see [operator console tools](operator-tools.md).
Without those flags everything below still applies.

## Why provider restart is unavailable by default

The source dashboard explains target, accepted-work drain, repeated/interrupted
request safety and per-action authorization separately. This is a statement of
the read-only monitor composition, not a runtime probe of Darkbloom capabilities
or credentials. Healthy counters and source-supplied drain flags never enable a
repair. No action routes or controls are added. See the
[verified Darkbloom 0.10.5 assessment](darkbloom-restart-evidence.md) for existing
safeguards, missing guarantees and unverified installed/live behavior. Source
changes do not update an already installed service.

## Interpreting diagnostic confidence

The dashboard separates local process/eligibility reports, coordinator/protocol
confidence, and model/memory evidence. This collector does not obtain provider
liveness, eligibility, coordinator errors or protocol compatibility, so these
remain unknown even while counters and collection are current. A source-read
error is not a coordinator protocol error. No raw-log collection is added.
Normalized coordinator errors supplied by other supported evidence paths remain
warnings, not restart triggers. Low or zero traffic alone is not failure. See
[diagnostic confidence](diagnostic-confidence.md) for evidence and limitations.

## Optional read-only diagnostic sources

[Owner-local diagnostic collection](local-diagnostic-collection.md) adds explicit
`--provider-executable` and `--coordinator-errors` options. Native process evidence,
selected daemon status claims and bounded coordinator Error/Fault record counts
are collected without invoking provider status/doctor or reading credentials.
This opt-in mode preserves original source/trust times and may show stale
eligibility alongside current liveness. Unknown or redacted causes remain unknown.
Repairs remain disabled; no raw logs are retained or exported.
