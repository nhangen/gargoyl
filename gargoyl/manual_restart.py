"""Explicit owner-local manual restart. No automatic actions.

The CLI (`gargoyl tools restart`) and the opt-in operator console share this one
journal, lock and gate. An unresolved outcome blocks both until a read-only
reconciliation records current observations (`reconcile_operation`).
"""

import fcntl
import json
import os
import pwd
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path

from gargoyl.collector_coordinator_log import process_birth
from gargoyl.collector_state_file import (
    _parse,
    _read,
    _require,
    validate_daemon_state_source,
)
from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.dashboard.runtime import utc_now
from gargoyl.pilot_configuration import load_pilot_configuration
from gargoyl.repair_process_identity import MacOSProcessVerifier
from gargoyl.telemetry import timestamp


def owner_home():
    return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)


class ManualJournal:
    """Single private slot: durable unresolved intent blocks every later invocation.

    Same-user local tampering is outside this custody boundary. No reset command,
    secrets, child output, credential loading or exactly-once claim is provided.
    """

    def __init__(self, directory):
        p = Path(directory)
        _require(
            p.is_absolute() and str(p) == str(p.parent.resolve(strict=True) / p.name)
        )
        if not p.exists():
            p.mkdir(mode=0o700)
        # Establish the directory entry itself durably, including first use.
        parent = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            owner = os.fstat(parent)
            _require(owner.st_uid == os.getuid() and not owner.st_mode & 0o022)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.lock = None
        try:
            s = os.fstat(self.fd)
            _require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700)
            self.lock = os.open(
                "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.fd
            )
            self._private(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _private(fd):
        s = os.fstat(fd)
        _require(
            stat.S_ISREG(s.st_mode)
            and s.st_uid == os.getuid()
            and s.st_nlink == 1
            and stat.S_IMODE(s.st_mode) == 0o600
        )

    def read(self):
        try:
            fd = os.open("operation.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            self._private(fd)
            payload = os.read(fd, 16385)
            _require(len(payload) <= 16384)

            def unique(pairs):
                result = {}
                for key, value in pairs:
                    _require(key not in result)
                    result[key] = value
                return result

            return validate_record(json.loads(payload, object_pairs_hook=unique))
        finally:
            os.close(fd)

    def write(self, record):
        validate_record(record)
        payload = json.dumps(record, sort_keys=True, allow_nan=False).encode()
        _require(len(payload) <= 16384)
        name = "pending-" + uuid.uuid4().hex
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )
        try:
            self._private(fd)
            view = memoryview(payload)
            while view:
                n = os.write(fd, view)
                _require(n > 0)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(name, "operation.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if getattr(self, "fd", None) is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def observed_target(source, executable, uid, *, now=None, verifier=None):
    """Source bytes are bounded/owner-checked; only identity and pinned version leave."""
    now = now or utc_now()
    _require(uid == os.getuid())
    validate_daemon_state_source(source, uid)
    payload = _read(source, uid, 65536)
    parsed = _parse(payload, now, 60)
    _require((timestamp(now) - timestamp(parsed.observed_at)).total_seconds() <= 60)
    data = json.loads(payload)
    _require(data["version"] in SUPPORTED_VERSIONS)
    identity = data.get("process_identity")
    _require(
        type(identity) is dict
        and set(identity) == {"pid", "start_time_micros"}
        and type(identity["pid"]) is int
        and identity["pid"] == data["pid"]
        and type(identity["start_time_micros"]) is int
    )
    process = dict(
        pid=identity["pid"], born_us=identity["start_time_micros"], owner_uid=uid
    )
    _require(timestamp(parsed.observed_at) >= process_birth(process))
    check = verifier or MacOSProcessVerifier(
        expected_owner_uid=uid, expected_executable=executable
    )
    _require(check(process))
    return dict(
        process=process, version=data["version"], observed_at=parsed.observed_at
    )


def executable_stamp(executable):
    p = Path(executable)
    _require(p.is_absolute() and str(p.resolve(strict=True)) == str(p))
    s = p.stat()
    _require(
        stat.S_ISREG(s.st_mode)
        and s.st_uid == os.getuid()
        and not s.st_mode & 0o022
        and os.access(p, os.X_OK)
    )
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)


def restart_gate_allows(record):
    """Shared admission only; callers still lock, validate and confirm each attempt.

    Reconciled records mean an explicit read-only observation was recorded after
    the prior command stopped, not that its historical outcome is now known.
    Nothing here retries an operation or bypasses fresh target/owner checks.
    """
    return record is None or (type(record) is dict and record.get("state") in
                              {"completed", "reconciled"})


def run_restart(
    journal, target, *, inspect_target, invoke, confirm, progress, clock=utc_now,
    invoke_with_child=False,
):
    """Installation-scoped consent, one invocation, conservative terminal evidence.

    Structural dependencies are internal test seams, never CLI-provided plugins.
    A failed/abandoned invocation is never automatically retried or cleared.
    """
    prior = journal.read()
    _require(restart_gate_allows(prior))
    _require(confirm(target) is True)
    current = inspect_target()
    _require(
        current["process"] == target["process"]
        and current["version"] == target["version"]
    )
    record = dict(
        schema=1,
        operation_id=uuid.uuid4().hex,
        state="intent",
        started_at=clock(),
        target=target,
        reason="invocation_not_confirmed",
    )
    journal.write(record)  # fsync BEFORE the first potentially mutating call
    progress("Intent saved. One graceful manual restart requested; no automatic retry.")
    def record_child(pid):
        # Lets reconciliation refuse while this exact command is still running.
        record["child"] = dict(pid=pid, born_us=process_start(pid))
        journal.write(record)

    try:
        code = invoke(record_child) if invoke_with_child else invoke()
        progress(
            "Command finished. Checking replacement evidence; exit status alone is not success."
        )
        replacement = inspect_target()
        _require(
            code == 0
            and replacement["process"] != target["process"]
            and replacement["version"] == target["version"]
        )
        record.update(
            state="completed",
            reason="cli_success_and_replacement_observed",
            finished_at=clock(),
            replacement=replacement,
        )
        journal.write(record)
        progress(
            "CLI reported success; a different native provider process with fresh matching state was verified. Protocol health is not independently proven."
        )
        return record
    except BaseException:
        record.update(
            state="unknown", reason="completion_unverified", finished_at=clock()
        )
        journal.write(record)
        progress(
            "Outcome unknown. No retry is allowed. Use read-only reconciliation; the provider may remain draining or unavailable."
        )
        raise


def process_start(pid):
    """Kernel start time (microseconds) for pid, or None if unavailable/exited."""
    import sys

    try:
        if sys.platform == "darwin":
            verifier = MacOSProcessVerifier(
                expected_owner_uid=os.getuid(), expected_executable="/usr/bin/true"
            )
            return verifier._identity(pid)["born_us"]
        with open(f"/proc/{pid}/stat", "rb") as stream:
            fields = stream.read().rsplit(b")", 1)[1].split()
        if fields[0] == b"Z":
            return None
        with open("/proc/stat", "rb") as stream:
            boot = next(int(x.split()[1]) for x in stream if x.startswith(b"btime "))
        return boot * 1_000_000 + int(fields[19]) * 1_000_000 // os.sysconf("SC_CLK_TCK")
    except Exception:
        return None


def process_alive(child):
    """Same PID with the same recorded start time; PID reuse never counts.

    If the start time could not be read when recorded, the child is treated as
    possibly running for as long as any process holds that PID (conservative).
    """
    if type(child) is not dict:
        return False
    if child.get("born_us") is None:
        try:
            os.kill(child["pid"], 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True
        return True
    return process_start(child["pid"]) == child["born_us"]


# invoke_restart's 840 s budget plus TERM/cleanup margin.
RECONCILE_UNIDENTIFIED_SECONDS = 900


def reconcile_operation(journal, *, inspect_target, alive=process_alive, clock=utc_now):
    """Read-only: record current observations for an unresolved operation and reopen the gate.

    Never invokes the provider. Refuses while the recorded command is still running.
    It records what is observable now; it cannot prove what happened during the attempt.
    """
    record = journal.read()
    _require(record is not None and record["state"] in {"intent", "unknown"})
    if alive(record.get("child")):
        raise ValueError("restart_still_running")
    if "child" not in record:
        # Spawned but not recorded (crash between spawn and write), or written by an
        # older version: the command may still be running and can't be identified.
        # Wait out the whole invocation budget before allowing reconciliation.
        elapsed = (timestamp(clock()) - timestamp(record["started_at"])).total_seconds()
        if elapsed < RECONCILE_UNIDENTIFIED_SECONDS:
            raise ValueError("restart_may_still_be_running")
    try:
        current = inspect_target()
        observation = (
            "original_process_observed"
            if current["process"] == record["target"]["process"]
            else "different_process_observed"
        )
    except Exception:
        current, observation = None, "provider_unobservable"
    record.update(
        state="reconciled", reason="reconciled_read_only", reconciled_at=clock(),
        observation=observation,
    )
    record.setdefault("finished_at", record["reconciled_at"])
    if current is not None:
        record["current"] = current
    journal.write(record)
    return record


def invoke_restart(executable, *, interrupted, progress, budget=840, started=None,
                   output=None):
    """Discard output, preserve child after caller interruption, never force provider.

    On interruption/deadline only the wrapper-owned CLI is sent TERM, never a
    provider/process group. Its exit does not cancel accepted upstream work.
    The journal remains unresolved; no restart or cleanup retry is performed.
    """
    child = subprocess.Popen(
        [executable, "restart", "--timeout", "600", "--startup-timeout", "180"],
        stdin=subprocess.DEVNULL,
        # Output is discarded unless the console supplies a private file for progress.
        stdout=subprocess.DEVNULL if output is None else output,
        stderr=subprocess.DEVNULL if output is None else subprocess.STDOUT,
        cwd=str(owner_home()),
        env={
            "HOME": str(owner_home()),
            "PATH": "/usr/bin:/bin",
            "DARKBLOOM_NO_UPDATE_CHECK": "1",
        },
        start_new_session=True,
    )
    if started is not None:
        started(child.pid)
    began = time.monotonic()
    next_message = began + 10
    while child.poll() is None:
        if interrupted.is_set() or time.monotonic() - began > budget:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError("manual outcome unknown")
        if time.monotonic() >= next_message:
            progress(
                "Waiting for upstream drain/restart/authorization. Detailed phase and accepted-work count are unknown; raw output is discarded."
            )
            next_message = time.monotonic() + 10
        time.sleep(0.1)
    return child.returncode


def _job_running(label, uid):
    """Read only one fixed launchd job; discard all text except running/PID evidence."""
    import re

    _require(label in {"io.darkbloom.provider", "io.darkbloom.watchdog"})
    result = subprocess.run(
        ["/bin/launchctl", "print", f"gui/{uid}/{label}"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise ValueError(
            "existing_watchdog_required"
            if label.endswith("watchdog")
            else "provider_job_unavailable"
        )
    _require(len(result.stdout) <= 65536 and len(result.stderr) <= 4096)
    text = result.stdout.decode("utf-8", "strict")
    _require(re.search(r"^\s*state = running$", text, re.M) is not None)
    match = re.search(r"^\s*pid = ([0-9]+)$", text, re.M)
    _require(match is not None)
    return int(match[1])


def installation_preflight(executable, source, uid):
    """Pilot-only ordinary provider; never discover/read credentials or config.

    Already-running watchdog is required so the supported restart cannot newly
    enroll/activate recovery. This does not authorize unattended Gargoyl repair.
    """
    import plistlib
    import sys

    home = owner_home()
    policy = load_pilot_configuration(home=home).require_local(uid)
    _require(sys.platform == "darwin")
    _require(
        executable == policy.provider_executable
        and source == policy.source
    )
    stamp = executable_stamp(executable)
    p = home / "Library/LaunchAgents/io.darkbloom.provider.plist"
    _require(str(p.resolve(strict=True)) == str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        _require(
            stat.S_ISREG(s.st_mode)
            and s.st_uid == uid
            and s.st_nlink == 1
            and not s.st_mode & 0o022
        )
        payload = os.read(fd, 65537)
        _require(len(payload) <= 65536)
    finally:
        os.close(fd)
    value = plistlib.loads(payload)
    args = value.get("ProgramArguments")
    _require(
        value.get("Label") == "io.darkbloom.provider"
        and type(args) is list
        and args[:2] == [executable, "start"]
        and all(type(x) is str for x in args)
        and not any(
            x
            in {
                "--config",
                "-c",
                "--cluster-member",
                "--supervise",
                "--local-only",
                "--local-port",
            }
            or x.startswith(("--config=", "--local-"))
            for x in args
        )
    )
    _require(args[2:3] == ["--foreground"])
    index = 3
    while index < len(args):
        _require(
            args[index] in {"--coordinator-url", "--model"} and index + 1 < len(args)
        )
        index += 2
    target = observed_target(source, executable, uid)
    _require(target["version"] in policy.versions)
    version = subprocess.run(
        [executable, "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=5,
        cwd=str(home),
        env={
            "HOME": str(home),
            "PATH": "/usr/bin:/bin",
            "DARKBLOOM_NO_UPDATE_CHECK": "1",
        },
    )
    _require(
        version.returncode == 0
        and len(version.stdout) <= 128
        and len(version.stderr) <= 4096
        and version.stdout.decode("ascii", "strict").strip() == target["version"]
    )
    _require(_job_running("io.darkbloom.provider", uid) == target["process"]["pid"])
    _job_running("io.darkbloom.watchdog", uid)
    _require(stamp == executable_stamp(executable))
    return target, stamp


def validate_record(data):
    from gargoyl.repair_restart_contract import process_identity

    _require(
        type(data) is dict
        and set(data)
        <= {
            "schema",
            "operation_id",
            "state",
            "started_at",
            "finished_at",
            "target",
            "replacement",
            "reason",
            "child",
            "reconciled_at",
            "observation",
            "current",
        }
        and {"schema", "operation_id", "state", "started_at", "target", "reason"}
        <= set(data)
        and type(data["schema"]) is int
        and data["schema"] == 1
        and data["state"] in {"intent", "unknown", "completed", "reconciled"}
        and type(data["operation_id"]) is str
        and len(data["operation_id"]) == 32
        and uuid.UUID(hex=data["operation_id"]).hex == data["operation_id"]
        and data["reason"]
        in {
            "invocation_not_confirmed",
            "completion_unverified",
            "cli_success_and_replacement_observed",
            "reconciled_read_only",
        }
    )
    timestamp(data["started_at"])
    if "child" in data:
        child = data["child"]
        _require(
            type(child) is dict
            and set(child) == {"pid", "born_us"}
            and type(child["pid"]) is int
            and child["pid"] > 0
            and (child["born_us"] is None or (type(child["born_us"]) is int and child["born_us"] > 0))
        )
    reconciled = data["state"] == "reconciled"
    _require(("reconciled_at" in data) == reconciled and ("observation" in data) == reconciled)
    if reconciled:
        _require(timestamp(data["reconciled_at"]) >= timestamp(data["started_at"]))
        _require(
            data["observation"]
            in {"original_process_observed", "different_process_observed", "provider_unobservable"}
        )
    _require("current" not in data or data["state"] == "reconciled")
    if "finished_at" in data:
        _require(timestamp(data["finished_at"]) >= timestamp(data["started_at"]))
    for key in ("target", "replacement", "current"):
        if key in data:
            target = data[key]
            _require(
                type(target) is dict
                and set(target) == {"process", "version", "observed_at"}
                and target["version"] in SUPPORTED_VERSIONS
            )
            process_identity(target["process"])
            timestamp(target["observed_at"])
    _require(
        data["state"] != "completed"
        or ("replacement" in data and "finished_at" in data)
    )
    _require(
        data["reason"]
        == {
            "intent": "invocation_not_confirmed",
            "unknown": "completion_unverified",
            "completed": "cli_success_and_replacement_observed",
            "reconciled": "reconciled_read_only",
        }[data["state"]]
    )
    _require(
        data["state"] != "completed"
        or data["replacement"]["process"] != data["target"]["process"]
    )
    return data


def read_operation(directory):
    """Read last record without creating or modifying anything; may see active intent."""
    p = Path(directory)
    _require(str(p) == str(p.parent.resolve(strict=True) / p.name))
    try:
        fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        s = os.fstat(fd)
        _require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700)
        reader = object.__new__(ManualJournal)
        reader.fd, reader.lock = fd, None
        return reader.read()
    finally:
        os.close(fd)
