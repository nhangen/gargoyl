"""Read-only public identity association; never grants repair or remote authority."""

import json
import os
import re
import socket
from urllib.parse import urlsplit

from gargoyl.collector_state_file import _parse, _read, validate_daemon_state_source
from gargoyl.fleet_state import provider_key, text
from gargoyl.manual_restart import observed_target
from gargoyl.telemetry import timestamp


def local_identity(source, executable, uid, now, *, verifier=None):
    validate_daemon_state_source(source, uid)
    before = observed_target(source, executable, uid, now=now, verifier=verifier)
    payload = _read(source, uid, 65536)
    parsed = _parse(payload, now, 60)
    data = json.loads(payload)
    after = observed_target(source, executable, uid, now=now, verifier=verifier)
    process = data.get("process_identity")
    if (
        before["process"] != after["process"]
        or before["version"] != after["version"]
        or type(process) is not dict
        or process.get("pid") != after["process"]["pid"]
        or process.get("start_time_micros") != after["process"]["born_us"]
        or data["version"] != after["version"]
        or not 0
        <= (timestamp(now) - timestamp(parsed.observed_at)).total_seconds()
        <= 60
    ):
        raise ValueError("local identity unavailable")
    key = text(data.get("attestation_public_key"), 4096)
    u = urlsplit(data.get("coordinator_url") or "")
    if (
        key is None
        or u.scheme not in {"wss", "https"}
        or u.hostname != "api.darkbloom.dev"
        or u.port not in {None, 443}
        or u.username
        or u.password
        or u.query
        or u.fragment
    ):
        raise ValueError("local identity unavailable")
    return dict(
        identity_digest=provider_key(key),
        observed_at=parsed.observed_at,
        local_alias=socket.gethostname(),
        source="protected daemon public identity + native process",
    )


def matching_provider(inventory, local, now):
    if (
        inventory is None
        or type(local) is not dict
        or inventory["connection"] != "connected"
    ):
        return None
    digest = local.get("identity_digest")
    if type(digest) is not str or re.fullmatch("[a-f0-9]{64}", digest) is None:
        return None
    if (
        not 0
        <= (timestamp(now) - timestamp(inventory["fetched_at"])).total_seconds()
        <= 120
    ):
        return None
    if (
        not 0
        <= (timestamp(now) - timestamp(local["observed_at"])).total_seconds()
        <= 60
    ):
        return None
    rows = [
        row
        for row in inventory["providers"]
        if row["identity_digest"] == local["identity_digest"]
    ]
    return rows[0]["id"] if len(rows) == 1 else None


def pilot_identity(home, now):
    return local_identity(
        str(home / ".darkbloom/daemon-state.json"),
        str(home / ".darkbloom/Darkbloom.app/Contents/MacOS/darkbloom"),
        os.getuid(),
        now,
    )
