"""Owner-local schema-1 daemon snapshot reader. No process or network operations."""

import json
import math
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone

from gargoyl.collector_adapters import AdapterResult
from gargoyl.telemetry import PolicyError, effective_state, timestamp

MAX_STATE_BYTES = 65536
_MAX_COUNT = 2**53 - 1


@dataclass(frozen=True)
class DaemonStateResult:
    observed_at: str | None
    result: AdapterResult


def _require(ok):
    if not ok:
        raise PolicyError("invalid daemon state")


def _epoch(value):
    _require(type(value) in (int, float) and 0 <= value <= 253402300799
             and math.isfinite(value))
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def _tree(value, depth=0):
    _require(depth <= 16)
    if type(value) is dict:
        for key, item in value.items():
            key.encode("utf-8", "strict")
            _tree(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _tree(item, depth + 1)
    elif type(value) is str:
        value.encode("utf-8", "strict")
    elif type(value) is float:
        _require(math.isfinite(value))


def _parse(payload, now, ttl):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    data = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=lambda value: _require(False))
    _tree(data)
    _require(type(data) is dict and type(data.get("schema")) is int and data["schema"] == 1)
    _require(type(data.get("pid")) is int and 1 <= data["pid"] <= 2**31 - 1)
    _require(type(data.get("version")) is str and 1 <= len(data["version"]) <= 128)
    observed = _epoch(data.get("written_at"))
    started = _epoch(data.get("started_at"))
    _require(timestamp(started) <= timestamp(observed) <= timestamp(now))
    _require(type(data.get("inference_active")) is bool)
    warm = data.get("warm_models")
    _require(type(warm) is list and len(warm) <= 256
             and all(type(name) is str and 0 < len(name) <= 4096 for name in warm))
    current = data.get("current_model")
    _require(current is None or (type(current) is str and len(current) <= 4096))
    stats = data.get("stats")
    _require(type(stats) is dict)
    readings = {}

    def add(metric, value):
        field = dict(value=value, source="daemon", timestamp=observed,
                     freshness_seconds=ttl, state="observed", sensitivity="safe")
        field["state"] = effective_state(field, now)
        readings[metric] = field

    for source, metric in (("requests_served", "requests_total"),
                           ("tokens_generated", "tokens_total")):
        value = stats.get(source)
        if value is not None:
            _require(type(value) is int and 0 <= value <= _MAX_COUNT)
            add(metric, value)
    if warm or current:
        add("model_state", "resident")
    return DaemonStateResult(observed, AdapterResult(readings, ()))


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_mode, info.st_nlink)


def _read(path, uid, limit):
    directory = descriptor = None
    try:
        # Resolve components without following symlinks. Only the immediate
        # containing directory is required to be private and owned; no sandbox claim.
        parts = path.split("/")[1:]
        _require(parts and all(part and part not in {".", ".."} for part in parts))
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        parent = os.fstat(directory)
        if parent.st_uid != uid or parent.st_mode & 0o077 or parent.st_mode & 0o500 != 0o500:
            raise PermissionError
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        if before.st_uid != uid or before.st_mode & 0o022 or not before.st_mode & 0o400:
            raise PermissionError
        _require(0 < before.st_size <= limit)
        output = bytearray()
        while len(output) <= limit:
            chunk = os.read(descriptor, min(4096, limit + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
        _require(len(output) <= limit and len(output) == before.st_size
                 and _signature(before) == _signature(os.fstat(descriptor)))
        return bytes(output)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def validate_daemon_state_source(path, expected_owner_uid):
    """Validate caller-owned source configuration without opening any path."""
    _require(os.name == "posix" and type(path) is str and path.startswith("/")
             and len(path) <= 4096 and "\0" not in path)
    _require(type(expected_owner_uid) is int and 0 <= expected_owner_uid < 2**32 - 1)
    try:
        path.encode("utf-8", "strict")
        _require(all(part and part not in {".", ".."} for part in path.split("/")[1:]))
    except UnicodeError:
        raise PolicyError("invalid daemon state path") from None


def read_daemon_state(path, *, expected_owner_uid, now, ttl=60, max_bytes=MAX_STATE_BYTES):
    """Return DaemonStateResult(observed_at, result: AdapterResult); data/access failures have fixed codes.

    path: explicit absolute string, no discovery or environment expansion.
    now: UTC telemetry timestamp; ttl 1..86400; max_bytes 1..65536.
    Invalid caller configuration raises safe PolicyError before opening anything.
    No raw JSON, identifiers, paths or error strings are returned or retained.
    """
    validate_daemon_state_source(path, expected_owner_uid)
    _require(type(ttl) is int and 1 <= ttl <= 86400)
    _require(type(max_bytes) is int and 1 <= max_bytes <= MAX_STATE_BYTES)
    timestamp(now)
    try:
        return _parse(_read(path, expected_owner_uid, max_bytes), now, ttl)
    except PermissionError:
        return DaemonStateResult(None, AdapterResult({}, ("permission_denied",)))
    except OSError:
        return DaemonStateResult(None, AdapterResult({}, ("unavailable",)))
    except (ValueError, TypeError, OverflowError, RecursionError):
        return DaemonStateResult(None, AdapterResult({}, ("invalid_state",)))
