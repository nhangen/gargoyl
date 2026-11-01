# Foundation contract v1

Python >=3.11; package `gargoyl`; create/activate a virtual environment and install
`python -m pip install -e ".[dev]"`. Run `python -m ruff check .` (pinned Ruff 0.14.3)
and `python -m unittest discover -s tests -v`. CI runs these on PRs and main pushes
with Python 3.11 and 3.12. No host command is executed by the foundation.
Collector owns `gargoyl/collector*`, dashboard owns `gargoyl/dashboard*` and their tests.
Do not create a second scaffold. Import `gargoyl.telemetry`.

Wire object (JSON, UTF-8): exactly `schema_version: 1`, `host_id: <canonical UUID>`,
`collected_at: <UTC ISO8601>`, `fields: {<metric>: <observation>}`.
An observation has exactly `value`, `source`, `timestamp`, `freshness_seconds`,
`state`, `sensitivity`. Source is daemon/doctor/launchd/host/coordinator/console/collector;
state is observed/stale/unknown/blocked; unknown and blocked require null values.
Sensitivity must be safe. UTC timestamps are timezone aware and cannot exceed collected_at. Every timestamp
input is limited to 32 ASCII characters. The exact accepted grammar is
`YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+00:00)`, with 1–6 fractional digits when present.
Calendar dates/times must also be valid. Only literal uppercase T and Z and ASCII
digits are accepted; whitespace, arbitrary separators, surrogates, nonzero offsets
and excessive fractional precision are rejected as safe `PolicyError` messages.
TTL is 1..86400 seconds. Metric enums and numeric bounds are defined in `METRICS`.
No model name, hostname, customer identifier, arbitrary string, error text, raw command
output, or address is allowed. Identity is an assigned opaque UUID, never a hostname hash.
Each field has its own provenance; aggregate counters do not imply earnings.
`confirmed_paid_microunits` requires console provenance; currency interpretation remains
out of scope until an explicit currency contract is added.

`validate_snapshot(dict)` returns a detached copy or raises safe `PolicyError`;
`encode_snapshot(dict) -> bytes` validates at every export/persistence boundary;
`decode_snapshot(bytes) -> dict` rejects oversized payloads and duplicate keys;
`MAX_PAYLOAD_BYTES = 65536` is the shared UTF-8 serialized-size limit. Validation and
encoding enforce it before outbound persistence/transmission, as does decoding on
inbound bytes (including whitespace). Encrypted records add exactly 32 bytes of
header/nonce/tag overhead, so their maximum is 65568 bytes.
`effective_state(field, now_utc_string)` computes read-time staleness and future-clock unknown.
Consumers must validate complete snapshots before reading fields. Missing fields mean
unknown, never zero/healthy. Missing heartbeat is a consumer incident decision.

Classes of data: safe = listed enum/aggregate observations; sensitive = local host labels,
model names and operational detail (not accepted in this contract); prohibited = prompts,
completions, credentials/API keys, raw logs, customer identifiers and IP addresses.
Reject unknown keys rather than attempt regex redaction. Validate before persistence and
transmission. Extensions require a reviewed schema version; never add a generic details bag.

Security adapters live in `gargoyl.security`: host-bound authenticated encryption,
TLS client certificate transport configuration and deny-by-default capability checks.
Collector integration must not use plaintext fallback while awaiting a configured key.
Production enrollment, credential storage, revocation, transport server and host validation
are separate integration work. No fixture demonstrates production provisioning.

## Security adapter interfaces

- `CollectionIdentity(host_id).authorize(action, target)` permits only
  `telemetry:write` for that host. This is a local guard, not a remote credential.
- `SpoolCipher(identity, key: bytes)` requires a separately provisioned 32-byte key.
  `seal(snapshot) -> bytes`, `open(ciphertext) -> dict` use AES-256-GCM with a random
  96-bit nonce and authenticated host/version context. Format: `GSP1` + 12-byte nonce
  + ciphertext/tag. Validation runs before encryption and after authenticated decryption.
- `RetentionPolicy(max_age_seconds=86400, max_records=1000).select(snapshots, now)`
  validates all input and keeps newest nonfuture records within age/count limits.
  Maximum configurable retention: seven days and 10,000 records. Collector must prune
  encrypted files atomically on startup and write, including while offline. This helper
  does not delete files or guarantee secure disk erasure.
- `export_batch(snapshots, now, policy=None) -> list[bytes]` applies the same validation
  and retention; there is no sensitive-data export override.
- `TransportConfig(endpoint, ca_file, certificate_file, private_key_file).ssl_context()`
  requires HTTPS, explicit CA, host client certificate/key, verified server hostname,
  and TLS >=1.2. Missing trust/key files fail closed. A caller must use this context,
  forbid redirects/downgrades, and avoid logging request data or credential paths.
- `prepare_transmission(snapshot, identity) -> bytes` validates and binds the envelope
  to the local identity. The receiver must independently bind the verified certificate
  identity to the envelope, enforce revocation, and reject cross-host submissions.

The target deployment contract requires separate OS/service identities and
credentials for collection and repair; repair endpoints must never trust
collection certificates. This is not enforced by the current same-user local
pilot. The foundation APIs described here do not provision credentials or
privileged operations. The package also contains a separate owner-confirmed
manual restart implementation used by the native app; it does not use the signed
runbook contracts. See [current deployment](pilot-acceptance.md).
Production certificate enrollment/revocation, secure OS key storage/rotation, receiver
implementation, separate process permissions, retention enforcement in a real spool,
and three-host deployment verification remain unmet integration acceptance work.
Unit tests prove policy behavior and crypto tamper rejection using synthetic data;
mocked TLS configuration is not evidence of a deployed mTLS handshake.


## Size-limit regression verification

`tests/test_size_limits.py` covers oversized fractions in both collected_at and field
timestamps through validation, encoding/decoding, sealing/opening, retention/export,
and transmission preparation, with safe errors. Supported 32-character timestamps
round-trip. Inbound JSON at 65535/65536 bytes (using whitespace padding) and its
authenticated ciphertext succeed; 65537-byte plaintext/65569-byte ciphertext fail.
Because bounded v1 fields naturally serialize well below 64KiB, a lowered central
limit tests exact outbound acceptance/rejection without expanding the schema.
