"""Independent ticks over externally acquired bounded source payloads.

No subprocess, host probing, credential provisioning, loop or thread is started.
Acquisition is outside this API: callers must bound reads and execution time before
supplying results. A tick parses at most the two pinned source kinds. Runtime
instances and their SQLite history have one owner; invoke ticks on that owner.
"""
import math
from dataclasses import dataclass

from gargoyl.collector import ERROR_CODES, RetrySchedule, collect
from gargoyl.collector_acquisition import AcquisitionResult
from gargoyl.collector_adapters import (
    SOURCE_KINDS,
    AdapterResult,
    execution_failure,
    parse_observations,
)
from gargoyl.collector_history import deliver_pending
from gargoyl.telemetry import PolicyError, timestamp


@dataclass(frozen=True)
class SourceFailure:
    code: str

    def __post_init__(self):
        execution_failure(self.code)


class CollectorRuntime:
    def __init__(self, identity, history, transport, *, wall_clock, monotonic_clock,
                 interval_seconds=30, ttl=60):
        if (type(interval_seconds) not in (int, float)
                or not math.isfinite(interval_seconds) or not 1 <= interval_seconds <= 60):
            raise PolicyError("invalid collection interval")
        if type(ttl) is not int or not interval_seconds <= ttl <= 86400:
            raise PolicyError("invalid collection freshness")
        self.identity, self.history, self.transport = identity, history, transport
        self.wall_clock, self.monotonic_clock = wall_clock, monotonic_clock
        self.interval_seconds, self.ttl = interval_seconds, ttl
        self.retry = RetrySchedule()
        self._next_collection = 0
        self._last_collection_clock = 0

    def collect_tick(self, payloads):
        """Persist one snapshot when due; missing/failed sources remain unknown.

        payloads maps source kind to bytes or SourceFailure. Never retains input
        bytes in runtime state. Raises safe policy errors for invalid configuration
        and propagates storage failure; neither advances the collection deadline.
        """
        if type(payloads) is not dict or not set(payloads) <= SOURCE_KINDS:
            raise PolicyError("invalid collection sources")
        monotonic = self.monotonic_clock()
        if (type(monotonic) not in (int, float) or not math.isfinite(monotonic)
                or monotonic < self._last_collection_clock):
            raise PolicyError("invalid collection clock")
        self._last_collection_clock = monotonic
        if monotonic < self._next_collection:
            return None
        now = self.wall_clock()
        timestamp(now)
        readings, errors = {}, []
        for kind, payload in payloads.items():
            result = (execution_failure(payload.code) if isinstance(payload, SourceFailure)
                      else parse_observations(kind, payload, observed_at=now, ttl=self.ttl))
            readings.update(result.readings)
            errors.extend(result.errors)
        snapshot = collect(self.identity.host_id, now, readings, errors=errors, ttl=self.ttl)
        self.history.append(snapshot, now)
        self._next_collection = monotonic + self.interval_seconds
        return snapshot

    def collect_acquired(self, results):
        """Persist normalized acquisitions without a cadence gate or redating.

        Foreground scheduling owns cadence. The result's observation time must
        match each field; default acquisition TTL is fixed at 60 seconds. Future
        relative observations after clock rollback are omitted, not refreshed.
        """
        if type(results) is not dict or not set(results) <= SOURCE_KINDS:
            raise PolicyError("invalid acquired sources")
        try:
            now = self.wall_clock()
            current = timestamp(now)
        except Exception:
            raise PolicyError("invalid collection clock") from None
        readings, errors = {}, []
        ownership = {"darkbloom_status_text_v1": ("daemon_state", "daemon"),
                     "darkbloom_doctor_text_v1": ("doctor_state", "doctor")}
        for kind in sorted(results):
            acquired = results[kind]
            if (type(acquired) is not AcquisitionResult or acquired.source_kind != kind
                    or type(acquired.cleanup_complete) is not bool):
                raise PolicyError("invalid acquisition result")
            if not acquired.cleanup_complete:
                raise PolicyError("acquisition cleanup incomplete")
            observed = timestamp(acquired.observed_at)
            timestamp(acquired.completed_at)  # rollback can legitimately precede start
            result = acquired.result
            if (type(result) is not AdapterResult or type(result.readings) is not dict
                    or type(result.errors) is not tuple or len(result.errors) > 1
                    or any(type(code) is not str or code not in ERROR_CODES for code in result.errors)
                    or (result.errors and result.readings)):
                raise PolicyError("invalid acquired observations")
            metric, source = ownership[kind]
            if set(result.readings) not in (set(), {metric}):
                raise PolicyError("invalid acquired provenance")
            if not result.errors and not result.readings:
                raise PolicyError("empty acquisition result")
            if result.readings:
                field = result.readings[metric]
                if (type(field) is not dict or field.get("source") != source
                        or field.get("timestamp") != acquired.observed_at
                        or type(field.get("freshness_seconds")) is not int
                        or field["freshness_seconds"] != 60 or field.get("state") != "observed"):
                    raise PolicyError("invalid acquired provenance")
                # Validate even future observations before deciding to withhold them.
                detached = collect(self.identity.host_id, acquired.observed_at,
                                   result.readings)["fields"][metric]
                if observed > current:
                    errors.append("invalid_state")
                else:
                    readings[metric] = detached
            errors.extend(result.errors)
        snapshot = collect(self.identity.host_id, now, readings, errors=errors, ttl=60)
        self.history.append(snapshot, now)
        return snapshot

    def deliver_tick(self):
        """Attempt one pending delivery using an independent backoff schedule."""
        return deliver_pending(self.history, self.transport, self.retry,
                               now=self.wall_clock(), monotonic_now=self.monotonic_clock())
