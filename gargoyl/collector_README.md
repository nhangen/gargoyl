# Collector library integration

This is a read-only library, not an installed host daemon. It executes no host
commands. `collector.collect` accepts complete v1 observations for its fixed
SOURCES metrics; source adapters must map command-specific enums locally and
never pass raw output, labels, model names or error messages. Missing observations
become unknown. Invalid/extra fields are rejected rather than silently exported.
Errors are limited to 32 fixed codes per collection; the current schema retains
only the latest code, not an event timeline. Source timestamps and staleness are
preserved. Clock skew is unknown unless a trusted reference time is supplied.

Supply a separately provisioned CollectionIdentity and SpoolCipher and a
RetentionPolicy to `collector_history.EncryptedHistory(directory, cipher, policy,
now)`. Use a private application-owned directory under a trusted parent. The
single-writer SQLite history contains encrypted payloads and local sequence/ack
metadata only. Startup, append and pending reads enforce age/count retention in
transactions. Storage retention removes records older than the age limit and
keeps only the newest max_records, counting future-relative records within that
same cap. A clock rollback quarantines authenticated future-relative ciphertext;
it does not delete it merely because it is not yet exportable. Pending/export
withholds such records until the wall clock catches up. Normal age/count eviction
still applies, so quarantine does not provide unlimited storage. Failed writes
roll back; corrupt ciphertext and wrong keys fail
closed. No key or plaintext snapshot is written by this library. Pruning is not
a guarantee of forensic secure erasure; expired ciphertext may remain in backups
or filesystem snapshots. The store must have a single collector owner; no
multi-process scheduler or directory replacement by another actor is supported.

Call collect and history.append on a regular independent collection schedule.
Call deliver_pending separately with an injected monotonic clock and RetrySchedule;
it attempts at most one retained snapshot, backs off on failure, and marks a
record delivered only after success. Delivered history remains until retention
expires. Collection continues while delivery waits or fails. Call history.close
on shutdown. Retention can evict undelivered data during long outages; delivery is
at-least-once and the receiver must deduplicate replay after an acknowledgement
crash. Retry state resets on process restart. No background threads are started.

OutboundHTTPS uses the foundation TransportConfig TLS context and collection
identity, revalidates immediately before POST, rejects redirects and treats only
200/201/204 as acknowledgements. The receiver contract must make these statuses
mean durable acceptance, enforce certificate-to-host binding and revocation, and
deduplicate snapshots. It must not use 202 as durable acknowledgement. No response
body or exception text is collected. Tests mock network I/O; they do not prove a
live mTLS handshake. A missing or expired collector heartbeat is an incident via
collector.heartbeat_incident, even when other metrics appear healthy.

Outstanding integration: actual Darkbloom/macOS read-only source adapters, host
service scheduling, secure key/certificate enrollment and storage, receiver
implementation, crash/power-loss testing on the target filesystem, and explicit
three-host validation. Do not close issue #2 based on synthetic library tests.

Run from the worktree:

    python -m venv --system-site-packages /workspace/collector-venv
    /workspace/collector-venv/bin/python -m pip install -e ".[dev]"
    /workspace/collector-venv/bin/python -m ruff check .
    /workspace/collector-venv/bin/python -m unittest discover -s tests -v

## Runtime ticks and pinned source adapters

`collector_adapters.parse_observations(source_kind, payload, observed_at=..., ttl=60)`
accepts at most 65,536 bytes of strict UTF-8 in memory. Supported source kinds are
`darkbloom_status_text_v1` and `darkbloom_doctor_text_v1`, independently checked
against [Darkbloom provider source at a6f7f483](https://github.com/darkbloomdev/darkbloom/blob/a6f7f483ab88806c633e37e00339c13e37ab62f4/provider/src/main.rs).
The adapter returns `AdapterResult(readings, errors)` containing only fixed state
observations, never captured prose. Invalid text returns empty readings and
`invalid_state`; invalid kind, timestamp or TTL raises a safe policy error.
Status maps only the running/stopped process observation: its serving label is
log-derived and does not establish model residency. Doctor requires the eight
ordered checks, consistent passed count and matching footer marker. Missing or
truncated check/summary evidence, duplicate or contradictory checks, unsupported
formats and control-character output fail closed. For a failed report, the
`Issues to fix:` marker is required but the following advice may be incomplete
or absent: advice supplies no telemetry evidence and cannot turn failure into
success. The two
non-macOS skips count as passed exactly as the pinned producer does. Punctuation
or version formats outside the supported grammar require a reviewed adapter
change, not a fallback parser. Numbered repair advice is discarded, never acted on.

`CollectorRuntime(identity, history, transport, wall_clock=..., monotonic_clock=...,
interval_seconds=30, ttl=60)` exposes independent `collect_tick(payloads)` and
`deliver_tick()` methods. Supply freshly acquired bytes keyed by supported source
kind, or `SourceFailure('timeout'|'unavailable'|'permission_denied')`. Acquisition
must independently enforce read-size and execution-time limits; this module does
not run a process or fetch host data. A collection tick timestamps those fresh
inputs using the injected UTC clock, parses at most two sources, fills absent
metrics as unknown and appends the validated snapshot to encrypted history. Do not
supply cached text as freshly observed evidence. The parser can also be used
separately with the actual acquisition timestamp when normalizing captured data.
Collection cadence uses a monotonic clock and skips early ticks; storage failure
does not advance the deadline. Delivery uses its own retry schedule and sends one
pending snapshot. Failure does not disable subsequent collection. Ticks are
single-owner synchronous calls; this is not a background service or a promise of
parallel acquisition while a send blocks. Callers must schedule them appropriately
and retain the existing bounded transport timeout. No credentials are loaded or
provisioned by the runtime.

The configured outbound endpoint for runtime ingestion is `/v1/snapshots`. The
receiver returns 204 only after durable acceptance and deduplicates canonical
identical snapshots for acknowledgement-loss replay. Its certificate principal
must authorize the host and every emitted metric/source pair, including unknown
placeholders from `collector.SOURCES` and collector heartbeat, skew and error
fields. An authorized source parser does not grant receiver authority. Integration
with the foundation ingestion implementation and real local TLS is checked after
its pinned handoff; current runtime tests use a synthetic transport double.

The runtime does not yet acquire launchd, model residency, pressure, attestation,
usage, routing or independent coordinator observations. The two text parsers must
not infer these from unrelated status/doctor details. Live acquisition, scheduling,
key/certificate custody and target-host acceptance remain outstanding for issue #2.
