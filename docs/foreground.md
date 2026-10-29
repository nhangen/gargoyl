# Foreground composition and lifecycle

This is a single-thread Python foreground API, not an installed host service.
It uses explicitly supplied acquisition, transport, identity and spool cipher
objects. It neither discovers nor loads executables, environment settings, keys,
certificates, credentials, endpoints or deployment configuration. In particular,
upstream Darkbloom status/doctor commands have filesystem/network/key side effects:
constructing an acquisition object is not authorization to run them on a host.
Tests use synthetic producers/fakes only. Real invocation needs separate authority.

## Non-secret configuration

```json
{
  "version": 1,
  "host_id": "00000000-0000-4000-8000-000000000001",
  "sources": ["darkbloom_status_text_v1", "darkbloom_doctor_text_v1"],
  "interval_seconds": 30
}
```

`ForegroundConfig.from_mapping(mapping)` accepts exactly those keys. Version must
be integer 1, host_id a canonical opaque UUID, sources one or two distinct supported
kinds, and interval a finite number from 1 through 60 seconds (not a boolean).
The source order is execution order. TTL is fixed at 60 seconds for this acquisition
slice; there is no misleading configurable TTL. Retention remains a separately
supplied existing `RetentionPolicy`, defaulting to its existing limits.

Optional CLI:

```sh
python -m gargoyl.foreground --check-config settings.json
```

This reads at most 4096 bytes, rejects duplicate keys, invalid UTF-8, extra fields
and invalid values, and exits 0 for valid configuration or 2 for invalid/unavailable
input, including integers too large for floating-point conversion. Output is fixed text. It does not echo configuration, load credentials,
open a spool, construct a runtime, acquire observations, or connect to a service.
There is intentionally no operational command-line credential loader.

## Supplied object interfaces

```python
run_foreground(config, *, runtime, acquisition, monotonic_clock, stop_event)

run_configured(
    config, *, identity, cipher, transport, acquisition, spool_directory,
    wall_clock, monotonic_clock, stop_event, policy=None,
)
```

Both return `ForegroundOutcome(status, reason, collections, deliveries, retries)`.
Status is `stopped`, `failed` or `incomplete_shutdown`. Counts are process-local
successful collection calls, acknowledged delivery ticks, and retry outcomes;
they are not request/token/earnings metrics. No captured source output or exception
text is returned or logged. Invalid configuration/dependency objects raise safe
`PolicyError` before work; operational failures return fixed reason codes.

`run_foreground` borrows an already constructed runtime and acquisition object:

- runtime has matching `identity.host_id`, fixed `ttl == 60`, `transport`,
  `collect_acquired(results) -> dict` and `deliver_tick() -> idle|sent|retry`.
- acquisition has a finite positive `total_timeout_seconds` that includes cleanup,
  and `acquire(source_kind, stop_event=...) -> AcquisitionResult`.
- each acquisition result contains source_kind, observed_at, completed_at,
  normalized AdapterResult and cleanup_complete. Only cleanup_complete exactly
  True permits proceeding. Runtime owns normalized-result validation and source
  timestamps; foreground passes each returned result unchanged, never redating it.
- transport has `send(snapshot)` and a finite positive `total_timeout_seconds` at
  most 30 seconds, matching the bounded outbound transport contract.
- monotonic_clock is callable; stop_event provides `is_set()` and interruptible
  `wait(seconds)` (for example `threading.Event`). Runtime owns the UTC wall clock.

These are trusted structural boundaries, allowing deterministic synthetic fakes
in tests. Merely adding a budget attribute to arbitrary blocking callbacks does
not make them bounded. Use the reviewed bounded acquisition/transport implementations
for operational wiring; the scheduler cannot preempt a lying callback or constrain
unbounded filesystem latency without a separate execution boundary.

`run_configured` validates dependencies and identity/cipher agreement, checks startup
clocks, then constructs `EncryptedHistory` and `CollectorRuntime` on the calling
thread. It supplies interval and TTL 60 and delegates to `run_foreground`. It fails
before opening storage when the normalized `collect_acquired` runtime dependency
is unavailable. Spool paths and objects are supplied through the API, not parsed
from configuration. It closes its own history after execution returns, even when
runtime initialization or collection fails. It never closes borrowed acquisition,
transport, identity or cipher objects. `run_foreground` closes none of its borrowed
objects. Callers retain lifetime and cleanup responsibility for those capabilities.

## Cadence, cancellation and failures

First collection is immediate. Sources are acquired serially in configured order,
then one combined normalized snapshot is persisted. Failed sources are handled by
the runtime as unknown/error observations without discarding an independent good
source. A missing/false cleanup receipt or exception escaping acquisition stops
with `incomplete_shutdown`; no incomplete batch is persisted and no containment
claim is made. Incomplete cleanup takes precedence even if stop was also requested.

After a completed collection/delivery cycle, advance to the first future monotonic
collection slot. Missed slots are skipped, never replayed in a catch-up storm.
Between collections the scheduler attempts delivery at most once per loop and
waits at most one second or until the next due collection, whichever is sooner.
`deliver_tick` retains its independent retry backoff. A retry does not disable
later collection. A delivery spanning the next slot can make one collection late;
there is no uninterrupted-cadence promise while bounded synchronous work is active.
Monotonic rollback/nonfinite values fail closed rather than spin.

Stop is checked before each acquisition, before persistence, before delivery and
after delivery. A stopped partial batch does not refresh the collector heartbeat.
An active send may finish within its remaining total budget; acquisition receives
the stop event and must honor its own cleanup-inclusive deadline. No further work
starts after cancellation. Local filesystem operations and the supplied clock/stop
callbacks are outside network/process timing guarantees. The scheduler installs
no signal handlers; callers can set the event, and a normal KeyboardInterrupt
outside acquisition stops the loop. An interrupt escaping acquisition has unknown
cleanup and is reported as incomplete shutdown.

Collection/storage errors stop the loop with `collection_failed`; delivery state
errors stop with `delivery_state_failed`. Ordinary network failure is the runtime's
`retry`, not a scheduler failure. History construction or close failure is explicit;
close failure, including KeyboardInterrupt during owned-history cleanup, produces
incomplete shutdown. Operators must not automatically retry
an incomplete shutdown as though producer cleanup had succeeded.

## Verification and remaining scope

```sh
python -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m ruff check .
.venv/bin/python -m unittest discover -s tests -v
```

Scheduler tests use deterministic clocks and supplied fakes to cover owner-thread
calls, cadence/overruns, independent delivery retries, cancellation boundaries,
unchanged acquisition timestamps, incomplete cleanup, safe failures and borrowed
resource ownership. Lifecycle tests also construct and close real encrypted local
history in temporary directories. Composed integration tests use locally authored
synthetic executable processes, real encrypted collector/receiver storage, and
actual loopback mutual TLS. They cover observation-start preservation, future
observations after clock rollback, independent good-source survival of a timeout,
retained pending evidence after transport timeout and durable replay, cancellation
with process reaping, and skipped scheduler slots using a controlled scheduler
clock while process/network deadlines remain real. Fake behavior alone does not
prove producer containment or network deadlines. No live host commands,
production credentials, service installation, permissions, DNS or access policy
are changed. Epics remain open for live-host and production acceptance.
