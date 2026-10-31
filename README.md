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

## Safety and privacy

- No prompts, completions, credentials, API keys, raw logs, customer identifiers, or IP addresses leave a host by default.
- Local collection access and repair authorization are separate capabilities.
- Repairs are allowlisted, preflighted, target-specific, and never autonomous.
- The pilot does not download or switch models, rewrite configuration, rotate credentials, or perform destructive cleanup.

## Roadmap

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
