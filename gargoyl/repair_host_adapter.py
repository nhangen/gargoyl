"""Explicit local status refresh; no automatic repairs or production enrollment."""

import math
import threading
import time

from gargoyl.collector import collect
from gargoyl.collector_acquisition import AcquisitionResult, BoundedAcquirer
from gargoyl.collector_adapters import AdapterResult
from gargoyl.ingestion import EvidenceStore
from gargoyl.repair_contract import OperationResult, RepairPlan, require
from gargoyl.telemetry import PolicyError, host_id, timestamp

_KIND = "darkbloom_status_text_v1"


def _budget(value):
    require(type(value) in (int, float) and 0 < value <= 30 and math.isfinite(value))
    return float(value)


class StatusRefreshAdapter:
    """Borrowed acquirer/store remain caller-owned; invoke through RepairRuntime.

    Dependencies are trusted in-process objects, not wire-provided capabilities.
    Local filesystem latency cannot be forcibly bounded; late acceptance is unknown.
    """

    supported_operations = frozenset({"status_refresh"})

    def __init__(self, target_host, *, acquirer, store, wall_clock,
                 monotonic_clock=time.monotonic, total_timeout_seconds=6.0):
        host_id(target_host)
        require(type(acquirer) is BoundedAcquirer and type(store) is EvidenceStore)
        budget = _budget(total_timeout_seconds)
        require(acquirer.total_timeout_seconds <= budget)
        require(target_host in store.configured_hosts)
        require(callable(wall_clock) and callable(monotonic_clock))
        self._host, self._acquirer, self._store = target_host, acquirer, store
        self._wall_clock, self._clock = wall_clock, monotonic_clock
        self._total = budget
        self._lock = threading.Lock()
        self._halted = False

    @property
    def total_timeout_seconds(self):
        return self._total

    def execute(self, plan, *, stop_event):
        require(type(plan) is RepairPlan)
        value = RepairPlan(plan.payload).as_dict()
        manifest = value["runbook"]["manifest"]
        require(value["target_host"] == self._host and not value["blocked"]
                and manifest["operation"] == "status_refresh"
                and manifest["runbook_id"] == "status_refresh"
                and self._total <= manifest["timeout_seconds"])
        require(callable(getattr(stop_event, "is_set", None)))
        if not self._lock.acquire(blocking=False):
            raise PolicyError("status refresh already active")
        try:
            require(not self._halted)
            return self._execute(stop_event)
        finally:
            self._lock.release()

    def _execute(self, stop_event):
        def result(outcome, reason, clean=True):
            return OperationResult(outcome, reason, clean).validate()

        real_start = time.monotonic()
        try:
            logical_start = self._clock()
            require(type(logical_start) in (int, float) and 0 <= logical_start <= 2**53
                    and math.isfinite(logical_start))
        except Exception:
            raise PolicyError("invalid status refresh clock") from None
        previous = logical_start

        def late():
            nonlocal previous
            current = self._clock()
            require(type(current) in (int, float) and previous <= current <= 2**53
                    and math.isfinite(current))
            previous = current
            return max(current - logical_start, time.monotonic() - real_start) >= self._total

        if stop_event.is_set():
            return result("cancelled", "cancelled")
        try:
            started_at = self._wall_clock()
            timestamp(started_at)
        except Exception:
            raise PolicyError("invalid status refresh clock") from None
        try:
            acquired = self._acquirer.acquire(_KIND, stop_event=stop_event)
        except BaseException:
            self._halted = True
            return result("outcome_unknown", "interrupted", False)
        if type(acquired) is not AcquisitionResult or type(acquired.cleanup_complete) is not bool:
            self._halted = True
            return result("outcome_unknown", "invalid_result", False)
        if not acquired.cleanup_complete:
            self._halted = True
            return result("outcome_unknown", "cleanup_incomplete", False)
        try:
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("outcome_unknown", "cancelled")
            require(acquired.source_kind == _KIND and type(acquired.result) is AdapterResult)
            observed = timestamp(acquired.observed_at)
            completed = timestamp(acquired.completed_at)
            if not timestamp(started_at) <= observed <= completed:
                return result("outcome_unknown", "clock_invalid")
            readings, errors = acquired.result.readings, acquired.result.errors
            require(type(readings) is dict and type(errors) is tuple)
            if errors:
                require(not readings and len(errors) == 1 and errors[0] in
                        {"timeout", "unavailable", "permission_denied", "invalid_state"})
                return (result("outcome_unknown", "deadline_exceeded") if errors == ("timeout",)
                        else result("failed", "operation_failed"))
            require(set(readings) == {"daemon_state"})
            field = readings["daemon_state"]
            require(type(field) is dict and field.get("timestamp") == acquired.observed_at
                    and field.get("source") == "daemon" and field.get("state") == "observed"
                    and type(field.get("freshness_seconds")) is int
                    and field["freshness_seconds"] == 60)
            now = self._wall_clock()
            if timestamp(now) < completed:
                return result("outcome_unknown", "clock_invalid")
            snapshot = collect(self._host, now, readings)
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("outcome_unknown", "cancelled")
        except Exception:
            return result("outcome_unknown", "invalid_result")
        try:
            accepted = self._store.accept(snapshot, now=now)
            if accepted is not True:
                return result("outcome_unknown", "audit_unavailable")
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("outcome_unknown", "cancelled")
            if timestamp(self._wall_clock()) < timestamp(now):
                return result("outcome_unknown", "clock_invalid")
        except BaseException:
            return result("outcome_unknown", "audit_unavailable")
        return result("succeeded", "completed")
