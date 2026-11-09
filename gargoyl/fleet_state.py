"""Allowlisted account inventory metadata; no credentials, raw payloads or control."""

import hashlib
import json
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from gargoyl.collector_state_file import _read
from gargoyl.fleet_account import FleetError
from gargoyl.telemetry import timestamp

LIMIT = 524288
LIFECYCLE_LIMIT = 4096
LIFECYCLE_SCHEMA = 1
MAX_PROVIDERS = 256
RETENTION = 86400
TTL = 120
SOURCE = "https://api.darkbloom.dev/v1/me/providers"

READER_STATUSES = {
    "idle",
    "starting",
    "running",
    "transient_failure",
    "session_busy",
    "stopped",
    "exited",
    "terminal_failure",
}
READER_EXIT_REASONS = {
    "none",
    "pipe_eof",
    "intentional_disconnect",
    "intentional_quit",
    "owner_inactive",
    "auth_required",
    "scope_refused",
    "expired",
    "retry_exhausted",
    "unknown",
}


def text(value, limit=128):
    if (
        type(value) is not str
        or not 0 < len(value) <= limit
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        return None
    try:
        value.encode("utf-8", "strict")
    except UnicodeError:
        return None
    return value


def instant(value):
    try:
        return timestamp(value).isoformat() if type(value) is str else None
    except (ValueError, TypeError):
        return None


def heartbeat(raw):
    """Fleet API ISO-8601 evidence; never guesses numeric timestamp units."""
    field = "last_heartbeat" if raw.get("last_heartbeat") is not None else "last_seen"
    value = raw.get(field)
    if value is None:
        return None, "not_reported", "none", None
    if type(value) is not str:
        return None, "unsupported_type", field, None
    pattern = r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})"
    match = re.fullmatch(pattern, value) if len(value) <= 64 else None
    if match is None:
        return None, "invalid_timestamp", field, None
    if match[3] != "Z" and (int(match[3][1:3]) > 23 or int(match[3][4:6]) > 59):
        return None, "invalid_timestamp", field, None
    precision = len(match[2] or "")
    canonical = match[1] + (("." + match[2][:6]) if precision else "") + match[3]
    try:
        parsed = datetime.fromisoformat(canonical.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
        normalized = parsed.isoformat()
        timestamp(normalized)
        return normalized, "reported", field, precision
    except (ValueError, OverflowError):
        return None, "invalid_timestamp", field, precision


def provider_key(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_inventory(value, fetched_at):
    timestamp(fetched_at)
    if (
        type(value) is not dict
        or type(value.get("providers")) is not list
        or len(value["providers"]) > MAX_PROVIDERS
    ):
        raise FleetError("invalid_data")
    rows, seen, rejected = [], set(), 0
    for raw in value["providers"]:
        if type(raw) is not dict or text(raw.get("id")) is None:
            rejected += 1
            continue
        identity = raw["id"]
        if identity in seen:
            raise FleetError("invalid_data")
        seen.add(identity)
        hardware = raw.get("hardware") if type(raw.get("hardware")) is dict else {}
        name = text(raw.get("name")) or text(raw.get("provider_name"))
        label = name or text(hardware.get("machine_model"))
        label_kind = (
            "source_name" if name else ("hardware_label" if label else "provider_id")
        )
        key = text(raw.get("se_public_key"), 4096)
        heartbeat_at, heartbeat_reason, heartbeat_source, heartbeat_precision = (
            heartbeat(raw)
        )
        rows.append(
            dict(
                id=identity,
                name=label or identity,
                name_kind=label_kind,
                reported_status=text(raw.get("status"), 64),
                heartbeat_at=heartbeat_at,
                heartbeat_reason=heartbeat_reason,
                heartbeat_source=heartbeat_source,
                heartbeat_precision=heartbeat_precision,
                version=text(raw.get("version"), 64),
                identity_digest=provider_key(key) if key else None,
            )
        )
    total = value.get("total_count", value.get("total"))
    if total is not None and (
        type(total) is not int or not len(rows) <= total <= 100000
    ):
        raise FleetError("invalid_data")
    partial = bool(
        rejected
        or value.get("has_more")
        or value.get("next_cursor")
        or value.get("next")
        or (total is not None and total > len(rows))
    )
    return dict(
        schema=2,
        source=SOURCE,
        fetched_at=fetched_at,
        connection="connected",
        partial=partial,
        reported_total=total,
        rejected_records=rejected,
        providers=sorted(rows, key=lambda row: (row["name"].casefold(), row["id"])),
    )


def validate_inventory(value):
    keys = {
        "schema",
        "source",
        "fetched_at",
        "connection",
        "partial",
        "reported_total",
        "rejected_records",
        "providers",
    }
    if (
        type(value) is not dict
        or set(value) != keys
        or type(value["schema"]) is not int
        or value["schema"] not in {1, 2}
        or value["source"] != SOURCE
        or value["connection"]
        not in {"connected", "unavailable", "auth_required", "disconnected"}
        or type(value["partial"]) is not bool
        or type(value["rejected_records"]) is not int
        or not 0 <= value["rejected_records"] <= MAX_PROVIDERS
        or type(value["providers"]) is not list
        or len(value["providers"]) > MAX_PROVIDERS
    ):
        raise FleetError("invalid_data")
    timestamp(value["fetched_at"])
    seen = set()
    row_keys = {
        "id",
        "name",
        "name_kind",
        "reported_status",
        "heartbeat_at",
        "version",
        "identity_digest",
    }
    if value["schema"] == 2:
        row_keys |= {"heartbeat_reason", "heartbeat_source", "heartbeat_precision"}
    for row in value["providers"]:
        if (
            type(row) is not dict
            or set(row) != row_keys
            or text(row["id"]) is None
            or row["id"] in seen
            or text(row["name"]) is None
            or row["name_kind"] not in {"source_name", "hardware_label", "provider_id"}
            or (
                row["reported_status"] is not None
                and text(row["reported_status"], 64) is None
            )
            or (row["version"] is not None and text(row["version"], 64) is None)
            or (
                row["heartbeat_at"] is not None and instant(row["heartbeat_at"]) is None
            )
            or (
                row["identity_digest"] is not None
                and (
                    type(row["identity_digest"]) is not str
                    or re.fullmatch("[a-f0-9]{64}", row["identity_digest"]) is None
                )
            )
        ):
            raise FleetError("invalid_data")
        if value["schema"] == 2:
            if row["heartbeat_reason"] not in {
                "reported",
                "not_reported",
                "unsupported_type",
                "invalid_timestamp",
            } or row["heartbeat_source"] not in {"last_heartbeat", "last_seen", "none"}:
                raise FleetError("invalid_data")
            precision = row["heartbeat_precision"]
            if precision is not None and (
                type(precision) is not int or not 0 <= precision <= 9
            ):
                raise FleetError("invalid_data")
            if (row["heartbeat_at"] is not None) != (
                row["heartbeat_reason"] == "reported"
            ):
                raise FleetError("invalid_data")
            if (
                row["heartbeat_source"] == "none"
                and row["heartbeat_reason"] != "not_reported"
            ):
                raise FleetError("invalid_data")
        seen.add(row["id"])
    total = value["reported_total"]
    if total is not None and (
        type(total) is not int or not len(seen) <= total <= 100000
    ):
        raise FleetError("invalid_data")
    return value


def evidence_state(inventory, row, now):
    """Fetch freshness and heartbeat freshness are distinct from reported status."""
    fetch_age = (timestamp(now) - timestamp(inventory["fetched_at"])).total_seconds()
    report = (
        "unknown"
        if fetch_age < 0
        else (
            "current"
            if fetch_age <= TTL and inventory["connection"] == "connected"
            else "stale"
        )
    )
    heartbeat = "unknown"
    if row["heartbeat_at"] is not None:
        age = (timestamp(now) - timestamp(row["heartbeat_at"])).total_seconds()
        heartbeat = "unknown" if age < 0 else ("recent" if age <= TTL else "older")
    return report, heartbeat


def _directory(path, uid, create=False):
    path = Path(path)
    if not path.is_absolute() or any(
        p in {".", ".."} for p in str(path).split("/")[1:]
    ):
        raise FleetError("invalid_data")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = str(path).split("/")[1:]
        for index, part in enumerate(parts):
            if create and index == len(parts) - 1:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        s = os.fstat(fd)
        if s.st_uid != uid or s.st_mode & 0o077:
            raise FleetError("unavailable")
        return fd
    except BaseException:
        os.close(fd)
        raise


class FleetCache:
    def __init__(self, directory, uid):
        self.directory, self.uid = str(directory), uid

    def read(self, now):
        timestamp(now)
        try:
            raw = _read(str(Path(self.directory) / "fleet.json"), self.uid, LIMIT)
        except FileNotFoundError:
            return None
        from gargoyl.fleet_account import decode_json

        value = validate_inventory(decode_json(raw))
        age = (timestamp(now) - timestamp(value["fetched_at"])).total_seconds()
        if age < 0 or age > RETENTION:
            self.clear()
            return None
        return value

    def clear(self):
        try:
            directory = _directory(self.directory, self.uid)
        except FileNotFoundError:
            return
        try:
            try:
                s = os.stat("fleet.json", dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(s.st_mode)
                or s.st_uid != self.uid
                or s.st_nlink != 1
                or s.st_mode & 0o077
            ):
                raise FleetError("unavailable")
            os.unlink("fleet.json", dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)

    def write(self, value):
        validate_inventory(value)
        body = json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(body) > LIMIT:
            raise FleetError("invalid_data")
        directory = _directory(self.directory, self.uid, create=True)
        temporary = ".fleet-" + uuid.uuid4().hex
        try:
            try:
                s = os.stat("fleet.json", dir_fd=directory, follow_symlinks=False)
                if (
                    not stat.S_ISREG(s.st_mode)
                    or s.st_uid != self.uid
                    or s.st_nlink != 1
                    or s.st_mode & 0o077
                ):
                    raise FleetError("unavailable")
            except FileNotFoundError:
                pass
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                view = memoryview(body)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise FleetError("unavailable")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(
                temporary, "fleet.json", src_dir_fd=directory, dst_dir_fd=directory
            )
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    def read_lifecycle(self, now=None):
        if now is not None:
            timestamp(now)
        try:
            raw = _read(
                str(Path(self.directory) / "reader_lifecycle.json"),
                self.uid,
                LIFECYCLE_LIMIT,
            )
        except FileNotFoundError:
            return None
        from gargoyl.fleet_account import decode_json

        value = validate_reader_lifecycle(decode_json(raw))
        if now is not None:
            age = (timestamp(now) - timestamp(value["observed_at"])).total_seconds()
            if age < 0 or age > RETENTION:
                return None
        return value

    def clear_lifecycle(self):
        try:
            directory = _directory(self.directory, self.uid)
        except FileNotFoundError:
            return
        try:
            try:
                s = os.stat(
                    "reader_lifecycle.json", dir_fd=directory, follow_symlinks=False
                )
            except FileNotFoundError:
                return
            if (
                not stat.S_ISREG(s.st_mode)
                or s.st_uid != self.uid
                or s.st_nlink != 1
                or s.st_mode & 0o077
            ):
                raise FleetError("unavailable")
            os.unlink("reader_lifecycle.json", dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)

    def write_lifecycle(self, value):
        validate_reader_lifecycle(value)
        body = json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode()
        if len(body) > LIFECYCLE_LIMIT:
            raise FleetError("invalid_data")
        directory = _directory(self.directory, self.uid, create=True)
        temporary = ".lifecycle-" + uuid.uuid4().hex
        try:
            try:
                s = os.stat(
                    "reader_lifecycle.json", dir_fd=directory, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(s.st_mode)
                    or s.st_uid != self.uid
                    or s.st_nlink != 1
                    or s.st_mode & 0o077
                ):
                    raise FleetError("unavailable")
            except FileNotFoundError:
                pass
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                view = memoryview(body)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise FleetError("unavailable")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(
                temporary,
                "reader_lifecycle.json",
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)


def validate_reader_lifecycle(value):
    keys = {
        "schema",
        "status",
        "observed_at",
        "owner_uid",
        "incarnation",
        "started_at",
        "last_read_at",
        "exit_reason",
        "exit_status",
        "retry_count",
        "retry_budget",
    }
    if type(value) is dict and "gui_owner" in value:
        keys.add("gui_owner")
    if (
        type(value) is not dict
        or set(value) != keys
        or value["schema"] != LIFECYCLE_SCHEMA
        or value["status"] not in READER_STATUSES
        or instant(value["observed_at"]) is None
        or type(value["owner_uid"]) is not int
        or value["owner_uid"] < 0
        or (value["started_at"] is not None and instant(value["started_at"]) is None)
        or (
            value["last_read_at"] is not None
            and instant(value["last_read_at"]) is None
        )
        or value["exit_reason"] not in READER_EXIT_REASONS
        or (
            value["exit_status"] is not None
            and type(value["exit_status"]) is not int
        )
        or type(value["retry_count"]) is not int
        or not 0 <= value["retry_count"] <= 1000
        or type(value["retry_budget"]) is not int
        or not 0 <= value["retry_budget"] <= 1000
    ):
        raise FleetError("invalid_data")
    incarnation = value["incarnation"]
    if incarnation is not None:
        if (
            type(incarnation) is not dict
            or set(incarnation) != {"pid", "born_us"}
            or type(incarnation["pid"]) is not int
            or incarnation["pid"] <= 0
            or (
                incarnation["born_us"] is not None
                and (
                    type(incarnation["born_us"]) is not int
                    or incarnation["born_us"] < 0
                )
            )
        ):
            raise FleetError("invalid_data")
    if "gui_owner" in value and value["gui_owner"] is not None:
        gui_owner = value["gui_owner"]
        if (
            type(gui_owner) is not dict
            or set(gui_owner) != {"pid", "born_us"}
            or type(gui_owner["pid"]) is not int
            or gui_owner["pid"] <= 0
            or (
                gui_owner["born_us"] is not None
                and (
                    type(gui_owner["born_us"]) is not int
                    or gui_owner["born_us"] < 0
                )
            )
        ):
            raise FleetError("invalid_data")
    return value


def reader_process_alive(incarnation):
    """Verify reader process identity against kernel process reality.

    Unlike manual_restart's conservative restart behavior, unread start time
    (born_us is None) is never assumed to be the same process.
    """
    if type(incarnation) is not dict:
        return False
    born_us = incarnation.get("born_us")
    if born_us is None:
        return False
    from gargoyl.manual_restart import process_start

    return process_start(incarnation.get("pid")) == born_us


def effective_lifecycle(cache, now, alive=None):
    """Resolve reader lifecycle against kernel process reality.

    If status is recorded as running/transient_failure but the process is no longer
    alive (or PID was reused), mark as exited with unknown reason rather than
    speculating or assuming credential rejection.
    """
    timestamp(now)
    record = cache.read_lifecycle(now)
    if record is None:
        return None
    if record.get("owner_uid") != cache.uid:
        return dict(
            record,
            status="exited",
            exit_reason="owner_inactive",
            observed_at=now,
        )
    if record["status"] in {"running", "transient_failure", "starting"}:
        incarnation = record.get("incarnation")
        is_alive = False
        if incarnation is not None and incarnation.get("born_us") is not None:
            if alive is not None:
                is_alive = alive(incarnation)
            else:
                is_alive = reader_process_alive(incarnation)
        if not is_alive:
            reason = record.get("exit_reason")
            if reason in {None, "none"}:
                reason = "unknown"
            return dict(
                record,
                status="exited",
                exit_reason=reason,
                observed_at=now,
            )
    return record


def utc_now():
    return datetime.now(timezone.utc).isoformat()
