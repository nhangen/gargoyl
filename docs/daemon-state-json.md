# Explicit local daemon-state JSON reader

Pinned producer: [DaemonStateFile.swift](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/ProviderCore/Service/DaemonStateFile.swift)
and [DaemonState+Coding.swift](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/ProviderCore/Service/DaemonState%2BCoding.swift).
Schema 1 uses snake_case, epoch timestamps and atomic replacement. This reader
observes reported state, not process liveness, health, attestation or earnings.

## Public API (CLI handoff)

```python
from gargoyl.collector_state_file import DaemonStateResult, read_daemon_state
result = read_daemon_state(
    absolute_path, expected_owner_uid=uid, now=utc_timestamp,
    ttl=60, max_bytes=65536,
)
# result.observed_at: str | None
# result.result: AdapterResult(readings: dict, errors: tuple)
```

The frozen wrapper carries a detached result, not raw input. A valid envelope
retains its UTC `written_at` in observed_at even when there are no selected
readings. Failed reads/validation return observed_at=None and no readings.
Invalid caller configuration raises generic PolicyError before file access.
Consumers must still validate normalized data at persistence boundaries; frozen
wrappers do not make nested dictionaries immutable or establish authenticity.

TTL 1..86400 seconds and max_bytes 1..65536 are Gargoyl limits, not upstream
format/SLA guarantees. Defaults are TTL 60 and 64 KiB. `now` is validation/aging
time, never an observation-time override. Repeated reads preserve written_at;
old values remain stale. Future written_at, negative/nonfinite timestamps or
started_at after written_at reject the complete result as invalid_state.

The required schema-1 envelope validates schema, positive Int32 pid, bounded
version string, written_at/started_at, inference_active boolean, warm_models
string array and stats object. Optional current_model and selected counters may
be absent/null; missing evidence is unknown, never zero/absent/healthy. Duplicate
JSON keys, invalid UTF-8, unpaired surrogates, nonfinite numbers and nesting over
16 levels reject the result. Unselected/additive fields are bounded and parsed
but discarded; this is a projection, not complete validation of every upstream
optional structure. No raw identity/key/model/address/error text is returned.

## Mappings and persistence

- stats.requests_served -> requests_total, source daemon.
- stats.tokens_generated -> tokens_total, source daemon.
- Nonempty warm_models or current_model -> model_state=resident, source daemon.
  Empty/missing current selection does not prove absence; no failed/loading inference.

Counters are nonboolean integers 0..2^53-1; overflow rejects rather than clamps.
All readings use written_at and the selected TTL. Other fields remain unknown.
The two counter metrics already exist in telemetry v1; collector's source allowlist
now accepts daemon provenance for them. No new wire schema or arbitrary details bag.

Use existing `collect(host_id, collected_at, result.result.readings,
errors=result.result.errors)` and validated encrypted history/EvidenceStore APIs
when explicitly persisting. Inspection itself never writes state or contacts a
receiver. The collector heartbeat describes collection, not producer liveness.
The JSON reader remains separate from process-executing repair adapters and
text acquisition. There is no automatic text-command fallback on JSON failure.

## File protection and error semantics

Callers provide an absolute string path and explicit integer expected_owner_uid.
No home-directory discovery, environment expansion, token/config lookup, process
probe or executable runs. POSIX path components are opened without following
symlinks. The immediate parent must belong to that UID, have owner read/search,
and have no group/other permissions. The file must be regular, single-link,
owned by that UID, owner-readable and not group/other writable. A 0644 file under
a private directory is accepted; this matches protection through its directory.
No permissions are changed. Ancestor directories are not claimed to be a sandbox.

The descriptor is opened nonblocking to reject FIFOs/devices without waiting for
a producer. File size is checked before reading at most max_bytes+1; same-descriptor
identity/size/mtime/ctime/owner/mode/link changes reject in-place modification.
An atomic replacement can yield a complete previous generation or a safe failure;
it never authorizes timestamp refresh. A trusted owner can manipulate content or
metadata, and filesystem syscalls can stall: this is not tamper-proof storage,
a signature check, or a forcibly bounded filesystem deadline.

Missing/I/O/symlink failures -> unavailable; permission/ownership/protection failures
-> permission_denied; malformed JSON, unsafe file kind/link count, size or concurrent
change -> invalid_state. Errors never include raw content or filesystem paths.

Tests use temporary synthetic files and ephemeral encryption keys only. No real
host files, credentials, endpoints, services, settings or Darkbloom commands are
accessed. Live compatibility and production owner/path configuration remain pending.
