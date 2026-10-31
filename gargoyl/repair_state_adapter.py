"""Owner-local JSON status refresh through the existing authenticated repair runtime.

No producer commands, source writes, identity enrollment, key loading or network.
Caller supplies the encrypted destination and separate runtime authorization/audit.
"""

import math
import threading
import time

from gargoyl.collector import collect
from gargoyl.collector_adapters import AdapterResult
from gargoyl.collector_state_file import (
    DaemonStateResult,
    read_daemon_state,
    validate_daemon_state_source,
)
from gargoyl.ingestion import EvidenceStore
from gargoyl.repair_contract import OperationResult, RepairPlan, require
from gargoyl.telemetry import PolicyError, effective_state, host_id, timestamp


class DaemonStateRefreshAdapter:
    """Borrow a real encrypted store; invoke only through RepairRuntime.

    Successful refresh means fresh normalized evidence was durably accepted, not
    daemon liveness or successful provider repair. Filesystem calls are not forcibly
    time-bounded; late or uncertain publication is outcome_unknown, never retried.
    """

    supported_operations = frozenset({"status_refresh"})

    def __init__(
        self,
        target_host,
        *,
        source_path,
        expected_owner_uid,
        store,
        wall_clock,
        monotonic_clock=time.monotonic,
        total_timeout_seconds=6,
    ):
        host_id(target_host)
        validate_daemon_state_source(source_path, expected_owner_uid)
        require(type(store) is EvidenceStore and target_host in store.configured_hosts)
        require(callable(wall_clock) and callable(monotonic_clock))
        require(
            type(total_timeout_seconds) in (int, float)
            and 0 < total_timeout_seconds <= 30
            and math.isfinite(total_timeout_seconds)
        )
        self._host, self._path, self._uid = target_host, source_path, expected_owner_uid
        self._store, self._wall_clock, self._clock = store, wall_clock, monotonic_clock
        self._total = float(total_timeout_seconds)
        self._lock = threading.Lock()

    @property
    def total_timeout_seconds(self):
        return self._total

    def execute(self, plan, *, stop_event):
        require(type(plan) is RepairPlan)
        value = RepairPlan(plan.payload).as_dict()
        manifest = value["runbook"]["manifest"]
        require(
            value["target_host"] == self._host
            and not value["blocked"]
            and manifest["operation"] == manifest["runbook_id"] == "status_refresh"
            and self._total <= manifest["timeout_seconds"]
        )
        require(callable(getattr(stop_event, "is_set", None)))
        if not self._lock.acquire(blocking=False):
            raise PolicyError("host observation already active")
        try:
            return self._execute(stop_event)
        finally:
            self._lock.release()

    def _execute(self, stop_event):
        def result(outcome, reason):
            # This adapter starts no child process. No producer cleanup is claimed.
            return OperationResult(outcome, reason, True).validate()

        if stop_event.is_set():
            return result("cancelled", "cancelled")
        real_start, logical_start = time.monotonic(), self._clock()
        require(
            type(logical_start) in (int, float)
            and 0 <= logical_start <= 2**53
            and math.isfinite(logical_start)
        )
        previous = logical_start

        def late():
            nonlocal previous
            now = self._clock()
            require(
                type(now) in (int, float)
                and previous <= now <= 2**53
                and math.isfinite(now)
            )
            previous = now
            return (
                max(now - logical_start, time.monotonic() - real_start) >= self._total
            )

        try:
            started_at = self._wall_clock()
            timestamp(started_at)
        except Exception:
            return result("outcome_unknown", "clock_invalid")
        try:
            state = read_daemon_state(
                self._path, expected_owner_uid=self._uid, now=started_at, ttl=60
            )
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("cancelled", "cancelled")
            require(
                type(state) is DaemonStateResult and type(state.result) is AdapterResult
            )
            require(
                type(state.result.errors) is tuple
                and type(state.result.readings) is dict
            )
            if (
                state.result.errors
                or not state.result.readings
                or state.observed_at is None
            ):
                return result("failed", "operation_failed")
            require(
                set(state.result.readings)
                <= {"requests_total", "tokens_total", "model_state"}
            )
            observed = timestamp(state.observed_at)
            for field in state.result.readings.values():
                require(
                    type(field) is dict
                    and field.get("source") == "daemon"
                    and field.get("timestamp") == state.observed_at
                    and type(field.get("freshness_seconds")) is int
                    and field["freshness_seconds"] == 60
                )
            published_at = self._wall_clock()
            if timestamp(published_at) < timestamp(started_at):
                return result("outcome_unknown", "clock_invalid")
            require(observed <= timestamp(started_at))
            # Reevaluate at publication; a read that aged past TTL cannot succeed.
            if any(
                effective_state(field, published_at) != "observed"
                for field in state.result.readings.values()
            ):
                return result("failed", "operation_failed")
            snapshot = collect(self._host, published_at, state.result.readings)
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("cancelled", "cancelled")
        except (KeyboardInterrupt, SystemExit):
            return result("outcome_unknown", "interrupted")
        except Exception:
            return result("outcome_unknown", "invalid_result")
        try:
            accepted = self._store.accept(snapshot, now=published_at)
            if accepted is not True:
                return result("outcome_unknown", "audit_unavailable")
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if stop_event.is_set():
                return result("outcome_unknown", "cancelled")
            try:
                finished_at = self._wall_clock()
                if timestamp(finished_at) < timestamp(published_at):
                    return result("outcome_unknown", "clock_invalid")
            except Exception:
                return result("outcome_unknown", "clock_invalid")
            if late():
                return result("outcome_unknown", "deadline_exceeded")
            if any(
                effective_state(field, finished_at) != "observed"
                for field in state.result.readings.values()
            ):
                # The write may already be durable, but fresh-success is no
                # longer established. Retain it and the consumed audit claim.
                return result("outcome_unknown", "invalid_result")
        except BaseException:
            # An accept/clock failure can follow a commit: no rollback or retry.
            return result("outcome_unknown", "audit_unavailable")
        return result("succeeded", "completed")
