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
