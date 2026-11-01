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
MAX_PROVIDERS = 256
RETENTION = 86400
TTL = 120
SOURCE = "https://api.darkbloom.dev/v1/me/providers"


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
        heartbeat = instant(
            raw.get("last_heartbeat")
            if raw.get("last_heartbeat") is not None
            else raw.get("last_seen")
        )
        rows.append(
            dict(
                id=identity,
                name=label or identity,
                name_kind=label_kind,
                reported_status=text(raw.get("status"), 64),
                heartbeat_at=heartbeat,
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
        schema=1,
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
        or value["schema"] != 1
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
    for row in value["providers"]:
        if (
            type(row) is not dict
            or set(row)
            != {
                "id",
                "name",
                "name_kind",
                "reported_status",
                "heartbeat_at",
                "version",
                "identity_digest",
            }
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


def utc_now():
    return datetime.now(timezone.utc).isoformat()
