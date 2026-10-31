# Owner-local read-only diagnostic collection

The optional monitor collector adds native provider liveness, selected structured
status claims, and visible coordinator-error record counts. It never calls a
provider command, changes the provider, or authorizes repair. Default counter-only
monitoring is unchanged until explicitly configured.

## Source verification

Inspected Darkbloom release sources:

- 0.10.5: `d3bbcd064ea290fbeb500e5c51c7870e3695741c`.
- 0.10.6: `84ddfdba6bb704bf1c68f97c7060289079380ceb`.

The relevant `DaemonStateFile`, `DaemonState+Coding`, `ProcessIdentity`,
`ServingReadiness`, `LogsCommand`, `ProviderLogger` and build-identity source files
are unchanged between these tags. The installed binary changed independently from
0.10.5 to 0.10.6 during investigation; its observed SHA-256 at that point was
`4474b0605343b502f58c45e7e696dba575d4802eb56cd30802ab9b526371c7c3`.
This is version/source-format evidence, not a reproducible-build proof. Unknown
versions fail closed for the added diagnostics; counters retain their existing policy.

Source links at the latter release:
[daemon state coding](https://github.com/Layr-Labs/d-inference/blob/84ddfdba6bb704bf1c68f97c7060289079380ceb/provider-swift/Sources/ProviderCore/Service/DaemonState+Coding.swift),
[readiness rules](https://github.com/Layr-Labs/d-inference/blob/84ddfdba6bb704bf1c68f97c7060289079380ceb/provider-swift/Sources/ProviderCore/Diagnostics/ServingReadiness.swift),
[log interface](https://github.com/Layr-Labs/d-inference/blob/84ddfdba6bb704bf1c68f97c7060289079380ceb/provider-swift/Sources/darkbloom/LogsCommand.swift),
[private-by-default logger](https://github.com/Layr-Labs/d-inference/blob/84ddfdba6bb704bf1c68f97c7060289079380ceb/provider-swift/Sources/ProviderCore/ProviderLogger.swift).

`status` and `logs` execute an update-banner network check; `status` also loads
configuration/helper/hardware state. The collector does not invoke either, or
`doctor`, and does not inspect credentials/configuration files. Instead it consumes
the already-authorized state file and a fixed OS structured-log query. No new
upstream capability is required.

## Explicit configuration

Keep the existing monitor arguments and append:

```sh
--provider-executable /Users/nhangen/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom \
--coordinator-errors
```

The canonical absolute provider image enables native/structured diagnostics.
`--coordinator-errors` separately opts into the fixed log query and requires that
image. There is no arbitrary command, log path, predicate, subsystem, category,
credential, remote-host or external-interface option. The native path is explicit,
not discovered. The owner UID must be the current user, and this mode requires macOS.
Installation alone enables nothing; a reviewed deployment may append only these
arguments to the existing Gargoyl LaunchAgent. Other configuration remains unchanged.

## Provenance and freshness

The same atomic, at-most 64KiB source read supplies both counters and diagnostics.
The shared reader's owner/private-directory, regular single-link file,
no-symlink traversal, permission, size, strict JSON, duplicate-key, depth and
finite/timestamp checks remain in force. No raw state is retained.

The state PID and kernel birth timestamp must match an independent native query
for the configured image and current UID, checked before and after log acquisition.
A PID alone cannot establish identity. This is kernel birth/UID/image-path evidence,
not code-signing attestation, coordinator authorization or repair authority. Missing,
reused, denied or mismatched identities are unknown, not proof of a stopped provider.

| Indicator | Provenance and timestamp |
|---|---|
| `daemon_state=running` | Independently checked native process; `host` source at completion. |
| `model_state=resident` | Current process's warm/current-model presence claim, `daemon` source at original write time. Names are dropped; no memory/engine attestation is inferred. |
| `coordinator_reachable` | Daemon's structured `coordinator_connection.connected` claim, `daemon` source at original write time, not independent remote confirmation. |
| `routing_eligible` | Conservative readiness subset: disconnected or explicit offline/untrusted report, or connected online/serving with legacy authorization/protocol 1 or hardware trust without an authorization object. Uses original trust receipt time, never refreshed by a new state write or native liveness check. |

Positive eligibility is withheld during lifecycle drain or add-on holds, including
unrecognized hold metadata. Missing, malformed, pre-connection or unsupported authorization evidence stays
unknown. App Attest/self-route and other readiness paths are deliberately not
inferred by this subset. Session/machine identifiers, attestation keys, reasons,
model names and tokens are not used as output or authorization. Old eligibility
can remain **stale** while independently observed liveness is current. TTL is 60s.
No low-traffic threshold, root-cause inference or automatic action exists.

## Narrow OS log query

Only root-owned, non-symlink, non-group/world-writable `/usr/bin/log` is run.
It receives a fixed `show --style ndjson --last 5m` request, filtering exactly
`dev.darkbloom.provider`, category `coordinator`, the verified provider PID,
and Error/Fault severity. The child gets a minimal noncredential environment,
null stdin and captured pipes. It never invokes the provider or signals its PID.

- At most one query per 30s for a stable process binding; cached evidence keeps
  its original timestamp and becomes stale after 45s.
- Combined stdout/stderr cap 64KiB, per-record cap 16KiB, maximum 512 records.
  Execution budget 2s plus 1s owned-reader cleanup; only that reader child can be
  terminated/reaped. Kernel/process-creation/filesystem delays cannot be forcibly
  bounded by Python; no hard realtime guarantee is claimed.
- Strict metadata scope: PID and owner UID, category/subsystem, severity, source
  timestamp within the process lifetime/window, and bounded numeric event metadata.
  A final count/finished marker and successful child exit are required. Loss,
  malformed, incomplete, oversized or wrong-scope evidence is unknown.
- Identical timestamp/mach/thread/trace metadata is deduplicated inside one query.
  Successive overlapping windows replace counts; they are never summed. No file
  offsets or raw-log history are persisted. OS store rotation/retention can reduce
  visible coverage; truncation/loss is not silently converted to zero. A missing
  marker or output limit fails closed. A new process binding discards old cache;
  records before its birth cannot be attributed to it.
- Raw messages, format strings, backtraces, image paths/UUIDs, activity identifiers
  and arbitrary extra fields never reach a report, fixture or persistence. Message
  text is inspected only for the `<private>` marker, producing a redacted-record
  count, then discarded. Record counts/latest source timestamp/window bounds and
  fixed state/reason labels remain in process memory only.
- Query denial, incomplete cleanup or unsupported output halts further log queries
  in that monitor process. There is no permission change, fallback file reader or
  automatic retry around a denial. Operator inspection is required before a newly
  authorized restart/reconfiguration; other collection continues with unknown logs.

Observed means **visible matching records returned by the bounded query**, not
complete logging coverage or distinct request/error episodes. Zero visible records
is not proof of an error-free connection. Redacted messages cannot establish causes,
protocol compatibility or routing impact. Positive counts are diagnostic warnings
only, separate from collector-read errors and model/memory evidence. The existing
v1 wire schema is unchanged; log aggregates are a validated local-only report.

## Operational and test limits

Controlled fixtures cover target mismatch/PID reuse, missing/stale/future metadata,
source protections, redaction and sensitive-marker omission, fixed scope, duplicate
records, missing completion/rotation-like truncation, cancellation, timeout/output
bounds, denied-query no-retry behavior and cache aging. No live provider restart,
credential setup or raw-log fixture capture is part of testing. Source capability,
installed configuration and observed live results must be reported separately.

Daily log automation is not modified. Safe review remains Gargoyl stdout/stderr,
scoped Gargoyl status and its read-only loopback dashboard, which now may display
these normalized aggregates. This implementation does not grant the reviewer broad
provider/watchdog log access or permission to run repairs.
