# Gargoyl

Private-first network health, usage monitoring, and guided repair for inference provider fleets. Darkbloom is the first integration.

## Goal

Within one view, identify each host's real traffic, model residency, verification freshness, routing blockers, and the safe next repair action with evidence.

## Pilot scope

The first pilot targets MBP26, `studio64-1`, and `studio64-2`:

- Read-only host telemetry with a local encrypted spool.
- A fleet view that correlates local daemon state with coordinator and earnings evidence.
- Explicit state labels: observed, stale, unknown, and blocked.
- Versioned repair runbooks that require a per-host user confirmation.

## Current coverage

The installed runtime monitors only `MBP-2026.local`. The three-machine pilot above
is a target, not delivered fleet coverage. Its internal pilot UUID is not a
Darkbloom provider ID. An authenticated read-only account inventory connection is
in progress; actual account provider names/IDs and coordinator reports are not yet
collected. See the [fleet-manager foundation and acceptance status](docs/fleet-manager.md).

## Safety and privacy

- No prompts, completions, credentials, API keys, raw logs, customer identifiers, or IP addresses leave a host by default.
- Local collection access and repair authorization are separate capabilities.
- Repairs are allowlisted, preflighted, target-specific, and never autonomous.
- The pilot does not download or switch models, rewrite configuration, rotate credentials, or perform destructive cleanup.

## Roadmap

The next core delivery is the graphical read-only account fleet manager: verify
actual owned inventory, preserve source IDs/names, distinguish local observations
from coordinator reports, and expose inventory/filter/detail views. It remains
incomplete until real account acceptance passes; no fake fleet entries substitute
for it. This advances identity epic#1 and fleet evidence epic#3. Durable normalized
history remains separate epic#2 work.

The GitHub epics define the implementation sequence: privacy and identity foundation, collector, evidence dashboard, controlled repair runbooks, then pilot hardening.

## Development foundation

Python 3.11+; create and activate a virtual environment with
`python -m venv .venv` and `source .venv/bin/activate`, install with
`python -m pip install -e ".[dev]"`, then run
`python -m ruff check .` and `python -m unittest discover -s tests -v`.
PRs and pushes to main run both checks on Python 3.11 and 3.12 in GitHub Actions. See [the v1 contract](docs/contract.md)
for schema, privacy rules, collector/dashboard integration and security boundaries.
For a runnable single-host collector and live loopback dashboard, see
[continuous local monitoring](docs/local-monitor.md). It polls an explicitly supplied
owner-local daemon-state file, keeps bounded memory history, displays recent fresh
counter changes, and offers foreground start/stop/status. Counter changes do not
establish earnings or reliably detect every reset. Repairs remain disabled. No host
enrollment or persistent service is enabled by installation.
Opt-in operator tools (`gargoyl monitor --operator-tools [--enable-restart]`) add
private read-only checks and a confirmed manual Darkbloom restart in the browser,
sharing one journal and gate with `gargoyl tools restart`; see
[operator console tools](docs/operator-tools.md) and
[manual operator tools](docs/manual-operator-tools.md). Unattended repair stays disabled.


The [native Mac operator application](docs/native-operator-app.md) provides a
graphical console, monitor controls, normalized export and a manual restart
review with Mac owner confirmation. The public HTTP dashboard stays read-only;
the opt-in private operator console above is the browser's admin panel and shares
the same restart gate. Automatic provider repair remains disabled.
