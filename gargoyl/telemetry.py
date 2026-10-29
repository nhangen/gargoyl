"""Version 1 wire contract. Validation fails closed without echoing input."""
import json
from datetime import datetime
from uuid import UUID

SCHEMA_VERSION = 1
SOURCES = {"daemon", "doctor", "launchd", "host", "coordinator", "console", "collector"}
STATES = {"observed", "stale", "unknown", "blocked"}
# Each metric is a fixed enum or bounded numeric aggregate; never arbitrary text.
METRICS = {
    "daemon_state": {"running", "stopped", "degraded"},
    "doctor_state": {"passed", "failed"},
    "launchd_state": {"running", "stopped", "missing"},
    "model_state": {"resident", "loading", "absent", "failed"},
    "memory_pressure": {"normal", "warning", "critical"},
    "thermal_pressure": {"normal", "warning", "critical"},
    "coordinator_reachable": {"reachable", "unreachable"},
    "routing_eligible": {"eligible", "ineligible"},
    "attestation_state": {"valid", "expired", "missing"},
    "error_code": {"none", "timeout", "unavailable", "invalid_state", "permission_denied"},
    "competing_runtimes": "count",
    "requests_total": "count", "tokens_total": "count",
    "memory_headroom_bytes": "count", "attestation_age_seconds": "count",
    "heartbeat_age_seconds": "count", "clock_skew_seconds": "signed",
    "confirmed_paid_microunits": "count",
}

class PolicyError(ValueError):
    """Safe-to-log error: rejected data is never included."""


def _require(ok):
    if not ok:
        raise PolicyError("telemetry rejected by v1 policy")


def timestamp(value):
    _require(type(value) is str)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        _require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0)
        return parsed
    except (ValueError, OverflowError):
        raise PolicyError("invalid UTC timestamp") from None


def host_id(value):
    try:
        _require(type(value) is str and str(UUID(value)) == value)
    except (ValueError, AttributeError):
        raise PolicyError("invalid opaque host identity") from None
    return value


def validate_snapshot(snapshot):
    """Return a detached allowlisted copy suitable for encrypted storage/export."""
    _require(type(snapshot) is dict and set(snapshot) == {"schema_version", "host_id", "collected_at", "fields"})
    _require(type(snapshot["schema_version"]) is int and snapshot["schema_version"] == SCHEMA_VERSION)
    host_id(snapshot["host_id"])
    collected = timestamp(snapshot["collected_at"])
    fields = snapshot["fields"]
    _require(type(fields) is dict and 0 < len(fields) <= len(METRICS))
    for name, field in fields.items():
        _require(name in METRICS and type(field) is dict)
        _require(set(field) == {"value", "source", "timestamp", "freshness_seconds", "state", "sensitivity"})
        _require(type(field["source"]) is str and field["source"] in SOURCES)
        _require(type(field["state"]) is str and field["state"] in STATES)
        _require(field["sensitivity"] == "safe")
        _require(timestamp(field["timestamp"]) <= collected)
        ttl = field["freshness_seconds"]
        _require(type(ttl) is int and 1 <= ttl <= 86400)
        value, rule = field["value"], METRICS[name]
        if field["state"] in {"unknown", "blocked"}:
            _require(value is None)
        elif isinstance(rule, set):
            _require(type(value) is str and value in rule)
        else:
            _require(type(value) is int and abs(value) <= 2**53 - 1)
            _require(rule == "signed" or value >= 0)
        if name == "confirmed_paid_microunits":
            _require(field["source"] == "console")
    return json.loads(json.dumps(snapshot, allow_nan=False))


def encode_snapshot(snapshot):
    return json.dumps(validate_snapshot(snapshot), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode_snapshot(payload):
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                _require(key not in result)
                result[key] = value
            return result
        _require(type(payload) is bytes and len(payload) <= 65536)
        return validate_snapshot(json.loads(payload, object_pairs_hook=unique))
    except (ValueError, UnicodeError, RecursionError):
        raise PolicyError("invalid telemetry payload") from None


def effective_state(field, now):
    """Use read time, not a producer's healthy label, to determine staleness."""
    observed = timestamp(field["timestamp"])
    current = timestamp(now)
    if observed > current:
        return "unknown"
    if (current - observed).total_seconds() > field["freshness_seconds"]:
        return "stale"
    return field["state"]
