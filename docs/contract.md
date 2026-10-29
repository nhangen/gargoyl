# Foundation contract v1

Python >=3.11; package `gargoyl`; install `python -m pip install -e .`.
Run `python -m unittest discover -s tests -v`. No host command is executed by the foundation.
Collector owns `gargoyl/collector*`, dashboard owns `gargoyl/dashboard*` and their tests.
Do not create a second scaffold. Import `gargoyl.telemetry`.

Wire object (JSON, UTF-8): exactly `schema_version: 1`, `host_id: <canonical UUID>`,
`collected_at: <UTC ISO8601>`, `fields: {<metric>: <observation>}`.
An observation has exactly `value`, `source`, `timestamp`, `freshness_seconds`,
`state`, `sensitivity`. Source is daemon/doctor/launchd/host/coordinator/console/collector;
state is observed/stale/unknown/blocked; unknown and blocked require null values.
Sensitivity must be safe. UTC timestamps are timezone aware and cannot exceed collected_at.
TTL is 1..86400 seconds. Metric enums and numeric bounds are defined in `METRICS`.
No model name, hostname, customer identifier, arbitrary string, error text, raw command
output, or address is allowed. Identity is an assigned opaque UUID, never a hostname hash.
Each field has its own provenance; aggregate counters do not imply earnings.
`confirmed_paid_microunits` requires console provenance; currency interpretation remains
out of scope until an explicit currency contract is added.

`validate_snapshot(dict)` returns a detached copy or raises safe `PolicyError`;
`encode_snapshot(dict) -> bytes` validates at every export/persistence boundary;
`decode_snapshot(bytes) -> dict` rejects oversized payloads and duplicate keys;
`effective_state(field, now_utc_string)` computes read-time staleness and future-clock unknown.
Consumers must validate complete snapshots before reading fields. Missing fields mean
unknown, never zero/healthy. Missing heartbeat is a consumer incident decision.

Classes of data: safe = listed enum/aggregate observations; sensitive = local host labels,
model names and operational detail (not accepted in this contract); prohibited = prompts,
completions, credentials/API keys, raw logs, customer identifiers and IP addresses.
Reject unknown keys rather than attempt regex redaction. Validate before persistence and
transmission. Extensions require a reviewed schema version; never add a generic details bag.

Security adapters will live in `gargoyl.security`: host-bound authenticated encryption,
TLS client certificate transport configuration and deny-by-default capability checks.
Collector integration must not use plaintext fallback while awaiting a configured key.
Production enrollment, credential storage, revocation, transport server and host validation
are separate integration work. No fixture demonstrates production provisioning.
