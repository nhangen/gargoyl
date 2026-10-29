# Fleet evidence dashboard

This read-only Python projection and self-contained HTML renderer consume foundation
v1 snapshots. There is no host access, repair execution, server, credential handling,
or plaintext spool adapter. Validate all complete snapshots before use.

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m gargoyl.dashboard --host 00000000-0000-4000-8000-000000000001 \
  --now 2026-01-01T00:00:00Z > /tmp/gargoyl-dashboard.html
# Append paths to synthetic v1 JSON snapshots to populate evidence.
```

Open the HTML in a browser. An expected host without reports has unknown values and
a missing-heartbeat incident. Expected inventory is essential: a host absent from
both inventory and reports cannot be discovered. CLI errors emit no partial report.
An explicitly empty `--now` is invalid; only omission selects the current clock.
Snapshots are limited to 64 KiB each and input values cannot supply arbitrary HTML.

`build_dashboard(snapshots, expected_hosts, now)` returns a detached projection;
`render_dashboard(...)` returns HTML. Keep sources separate and preserve source and
collection timestamps, read-time state, and TTL for every displayed observation.
The newest source timestamp wins per metric/source regardless of arrival order;
contradictory observations at the same timestamp become unknown. The view displays
the original conflicting values, source and observation/collection timestamps with
an explicit explanation; no conflicting report becomes authoritative. Future collection
times become unknown. History contains the supplied observations only; callers own
bounded retention, authenticated ingestion, and encrypted storage.

Fresh local/coordinator daemon, routing, attestation and model observations are
compared immediately on every invocation. Missing, blocked, stale or conflicting
counterparts cannot establish agreement. A fresh observed local/coordinator pair
that disagrees still establishes a mismatch when other local sources are stale,
unknown or blocked. Invoke after each collection and at least
once per minute to meet the five-minute detection target and refresh stale states.
The static HTML is explicitly an as-of report: it does not fetch or auto-refresh.
Live scheduling and collector wiring are outstanding integration work, so synthetic
tests do not demonstrate live fleet detection latency.

Heartbeat age includes elapsed time since its source timestamp. Missing or noncurrent
collector heartbeat is an incident. Availability is represented by daemon/launchd
and heartbeat evidence, not an invented overall healthy label. Failure history shows
bounded error codes with timestamps, never raw logs. Explicit blocked observations
show blocked; v1 carries no free-text blocker reason, so operators inspect associated
routing, attestation, model, memory and error-code evidence. No unsupported explanation
is inferred.

Local cumulative request/token history is distinct from coordinator/console usage
and console-reported paid microunits. Counter resets are shown without invented deltas.
The contract lacks request windows, currency and settlement receipts: comparisons
of usage totals and independent payment verification remain unavailable. Console
provenance alone is not proof of payment. No synthetic fixture establishes live
fleet integration or verified earnings.
