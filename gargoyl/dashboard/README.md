# Fleet evidence dashboard

This read-only Python projection and self-contained HTML renderer consume foundation
v1 snapshots. The optional loopback viewer below reads a supplied evidence store.
There is no host access, repair execution, credential handling, or plaintext spool adapter. Validate all complete snapshots before use.

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
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
their original reported states and TTL, and an explicit explanation; no conflicting
report becomes authoritative. Displayed states also show read-time freshness. Future collection
times become unknown. History contains the supplied observations only; callers own
bounded retention, authenticated ingestion, and encrypted storage.

Fresh local/coordinator daemon, routing, attestation and model observations are
compared immediately on every invocation. Missing, blocked, stale or conflicting
counterparts cannot establish agreement. A fresh observed local/coordinator pair
that disagrees still establishes a mismatch when other local sources are stale,
unknown, blocked, future-dated or internally conflicting. Invoke after each collection and at least
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


## Loopback evidence viewer

`gargoyl.dashboard.runtime.EvidenceViewer(reader, expected_hosts, *, clock=utc_now,
port=0, refresh_seconds=30)` binds only numeric IPv4 `127.0.0.1`. `reader` implements
`snapshots(*, now) -> list[dict]`: a bounded, transactionally consistent detached
read across configured hosts, raising on storage/authentication/corruption failure.
The viewer never reads collector pending queues or acknowledges deliveries. Supply
expected opaque host IDs separately so unreported hosts remain visible.

The foundation `EvidenceStore` supports ingestion and viewer threads sharing one
instance through an internal transaction lock. The caller drives
`viewer.serve_forever()` or `handle_request()` and owns listener threads; the viewer
starts no worker thread. Stop and join all listeners before closing the shared
store. Other structural readers must obey their own thread-safety contract. The
viewer does not provision keys/certificates or open a store itself. The existing
file-to-HTML CLI remains available.

Use `http://127.0.0.1:<viewer.server_port>/` on the same machine. GET and HEAD are
read-only. Other paths/methods, unexpected Host headers and cross-origin Origin
headers are rejected before reading evidence. Header reads have a five-second
absolute deadline from handler setup, so continued byte delivery cannot reset it.
The synchronous viewer still serves one request at a time; store evaluation has
no forced timeout and must use the store's bounded read contract. Response writes
have a five-second socket inactivity timeout. Responses forbid caching and framing,
load no external resources or scripts, and suppress request/exception logs. This
is a local operator viewer, not authentication between local OS users. No remote
binding, reverse proxy, production deployment or browser access changes are included.

Each request obtains a fresh clock and store read, validates all evidence, and
recomputes freshness/conflicts. HTML requests refresh every 30 seconds by default,
configurable only within 1–60 seconds. If storage or evaluation fails the response
is HTTP 503 with an explicit unknown/unavailable state and automatic retry; no
previous healthy report or partial fleet is served. A failed HTTP connection may
leave the browser showing its previous page: its evaluation timestamp remains the
as-of boundary. Browser suspension, network failure and scheduling delays prevent
claiming a real fleet latency guarantee from the refresh interval alone.

Runtime tests use real local HTTP requests with synthetic structural readers and
injected clocks. They establish on-request updates and the configured refresh bound,
not live host integration or a browser's actual scheduling. `tests/test_dashboard_integration.py` additionally uses ephemeral synthetic PKI
and actual local mTLS ingestion into EvidenceStore, then HTTP viewer requests. It
covers durable restart/readback, duplicate replay, conflicting/future/stale evidence,
missing expected hosts, and real ciphertext corruption followed by restored-fixture
recovery. Corruption recovery is test fixture restoration, not an operator repair API.
These checks integrate foundation via main commit `6eca704b615a87743cbc74edc2de19d4cb084d57`;
they do not demonstrate live host acceptance or browser refresh scheduling.
All existing usage-window/currency/payment verification limitations still apply.
