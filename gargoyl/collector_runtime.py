"""Independent ticks over externally acquired bounded source payloads.

No subprocess, host probing, credential provisioning, loop or thread is started.
Acquisition is outside this API: callers must bound reads and execution time before
supplying results. A tick parses at most the two pinned source kinds. Runtime
instances and their SQLite history have one owner; invoke ticks on that owner.
"""
import math
from dataclasses import dataclass

from gargoyl.collector import RetrySchedule, collect
from gargoyl.collector_adapters import (
    SOURCE_KINDS,
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

    def deliver_tick(self):
        """Attempt one pending delivery using an independent backoff schedule."""
        return deliver_pending(self.history, self.transport, self.retry,
                               now=self.wall_clock(), monotonic_now=self.monotonic_clock())
