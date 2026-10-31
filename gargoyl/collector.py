"""Read-only collector core; no commands, storage, network, or repair authority.

Adapters supply normalized observations, never raw command output. Missing evidence
is unknown. Persistence and delivery must use foundation security adapters; this
module deliberately has no plaintext fallback or production entry point.
"""
import math
from dataclasses import dataclass

from gargoyl.telemetry import (
    SCHEMA_VERSION,
    PolicyError,
    effective_state,
    encode_snapshot,
    host_id,
    timestamp,
    validate_snapshot,
)

SOURCES = {
    "daemon_state": "daemon", "doctor_state": "doctor",
    "launchd_state": "launchd", "model_state": "daemon",
    "memory_pressure": "host", "thermal_pressure": "host",
    "memory_headroom_bytes": "host", "attestation_state": "daemon",
    "attestation_age_seconds": "daemon", "coordinator_reachable": "coordinator",
    "requests_total": "daemon", "tokens_total": "daemon", "routing_eligible": "daemon",
}
ERROR_CODES = frozenset({"timeout", "unavailable", "invalid_state", "permission_denied"})


def _observation(value, source, now, ttl, state="observed"):
    return dict(value=value, source=source, timestamp=now,
                freshness_seconds=ttl, state=state, sensitivity="safe")


def collect(identity, now, readings, *, errors=(), reference_time=None, ttl=60):
    """Build a validated v1 snapshot from a bounded set of normalized evidence.

    readings maps the metrics in SOURCES to complete foundation observations.
    Reject unknown keys/values rather than stripping potentially sensitive input.
    Errors are at most 32 fixed codes; v1 carries only the latest code. Wall-clock
    skew is local minus trusted reference seconds, or unknown without a reference.
    """
    host_id(identity)
    local = timestamp(now)
    if type(readings) is not dict or not set(readings) <= SOURCES.keys():
        raise PolicyError("collector readings rejected")
    if type(errors) not in (list, tuple) or len(errors) > 32:
        raise PolicyError("collector events rejected")
    if any(type(code) is not str or code not in ERROR_CODES for code in errors):
        raise PolicyError("collector events rejected")
    fields = {}
    for metric, source in SOURCES.items():
        if metric not in readings:
            fields[metric] = _observation(None, source, now, ttl, "unknown")
        else:
            field = readings[metric]
            allowed = {source}
            if metric == "daemon_state":
                allowed.add("host")
            if metric == "coordinator_reachable":
                allowed.add("daemon")
            if type(field) is not dict or field.get("source") not in allowed:
                raise PolicyError("collector provenance rejected")
            fields[metric] = field
    fields["heartbeat_age_seconds"] = _observation(0, "collector", now, ttl)
    fields["error_code"] = _observation(errors[-1] if errors else "none", "collector", now, ttl)
    skew = None if reference_time is None else int((local - timestamp(reference_time)).total_seconds())
    fields["clock_skew_seconds"] = _observation(
        skew, "collector", now, ttl, "unknown" if skew is None else "observed")
    snapshot = validate_snapshot(dict(schema_version=SCHEMA_VERSION, host_id=identity,
                                      collected_at=now, fields=fields))
    # Preserve source timestamps; age evidence at collection, not only on display.
    for field in snapshot["fields"].values():
        if field["state"] not in {"unknown", "blocked"}:
            field["state"] = effective_state(field, now)
    return validate_snapshot(snapshot)


def boundary_payload(snapshot, identity):
    """Revalidate immediately before handing data to a security adapter.

    Returned bytes are not an encrypted spool record or transport envelope.
    Callers must never write these bytes directly to disk or a socket.
    """
    validated = validate_snapshot(snapshot)
    if validated["host_id"] != host_id(identity):
        raise PolicyError("collector identity mismatch")
    return encode_snapshot(validated)


def heartbeat_incident(snapshot, now):
    """A missing/stale/future/blocked heartbeat is an incident, never healthy silence."""
    timestamp(now)
    if snapshot is None:
        return True
    validated = validate_snapshot(snapshot)
    field = validated["fields"].get("heartbeat_age_seconds")
    return (field is None or effective_state(field, now) != "observed"
            or field["value"] + max(0, (timestamp(now) - timestamp(field["timestamp"])).total_seconds())
            > field["freshness_seconds"])


@dataclass
class RetrySchedule:
    """Bounded exponential retry state driven by an injected monotonic clock.

    This schedules delivery only: collection must continue independently. State
    is process-local; persistence and acknowledgement belong to security wiring.
    """
    initial_seconds: float = 1
    maximum_seconds: float = 300

    def __post_init__(self):
        for value in (self.initial_seconds, self.maximum_seconds):
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("invalid retry bounds")
        if self.initial_seconds > self.maximum_seconds:
            raise ValueError("invalid retry bounds")
        self._delay = self.initial_seconds
        self._due = 0.0
        self._last = 0.0

    def _clock(self, now):
        if type(now) not in (int, float) or not math.isfinite(now) or now < self._last:
            raise ValueError("invalid monotonic clock")
        self._last = now

    def ready(self, now):
        self._clock(now)
        return now >= self._due

    def failed(self, now):
        self._clock(now)
        due = now + self._delay
        if not math.isfinite(due):
            raise ValueError("retry deadline overflow")
        self._due = due
        self._delay = min(self.maximum_seconds, self._delay * 2)
        return self._due

    def succeeded(self, now):
        self._clock(now)
        self._delay = self.initial_seconds
        self._due = now
