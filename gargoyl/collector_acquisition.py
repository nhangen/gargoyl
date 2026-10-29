"""Bounded acquisition from an explicitly trusted POSIX producer.

Not an OS sandbox: upstream status/doctor perform network, filesystem, helper and
key reads. No executable discovery, credential loading, shell or service install.
Only locally authored synthetic producers are executed by this package's tests.
"""
import math
import os
import selectors
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

from gargoyl.collector_adapters import AdapterResult, parse_observations
from gargoyl.telemetry import PolicyError, timestamp

COMMANDS = {
    "darkbloom_status_text_v1": "status",
    "darkbloom_doctor_text_v1": "doctor",
}


@dataclass(frozen=True)
class AcquisitionResult:
    source_kind: str
    observed_at: str
    completed_at: str
    result: AdapterResult
    cleanup_complete: bool


def _number(value):
    # Integers are finite without a float conversion; callers apply range bounds.
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _path(value):
    return type(value) is str and len(value) <= 4096 and "\0" not in value and os.path.isabs(value)


def _group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True  # Unable to verify cleanup must never mean successful cleanup.


def _signal_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except OSError:
        pass  # Confirmation is separately required; do not leak the error/path.


def _cleanup(process, deadline, grace):
    # No drain: close both pipes before bounded group termination/reaping. Descendants
    # retaining pipe handles cannot keep the caller waiting for EOF after failure.
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    end = min(deadline, time.monotonic() + grace)
    escalate = time.monotonic() + max(0, end - time.monotonic()) / 2
    _signal_group(process.pid, signal.SIGTERM)
    killed = False
    while True:
        reaped = process.poll() is not None
        if reaped and not _group_exists(process.pid):
            return True
        now = time.monotonic()
        if not killed and now >= escalate:
            _signal_group(process.pid, signal.SIGKILL)
            killed = True
        if now >= end:
            # A final nonblocking reap may observe exit following SIGKILL. If not,
            # explicitly report incomplete cleanup instead of waiting indefinitely.
            return process.poll() is not None and not _group_exists(process.pid)
        time.sleep(min(.01, end - now))


class BoundedAcquirer:
    def __init__(self, executable, *, environment, cwd, wall_clock, monotonic_clock,
                 total_timeout_seconds=5.0, cleanup_grace_seconds=1.0,
                 max_output_bytes=65536):
        if os.name != "posix" or not _path(executable) or not _path(cwd):
            raise PolicyError("invalid acquisition platform or paths")
        if (type(environment) is not dict or len(environment) > 128
                or any(type(k) is not str or type(v) is not str or not k
                       or "=" in k or "\0" in k or "\0" in v
                       for k, v in environment.items())):
            raise PolicyError("invalid acquisition environment")
        try:
            environment_size = sum(len(k.encode()) + len(v.encode()) for k, v in environment.items())
            executable.encode()
            cwd.encode()
        except UnicodeError:
            raise PolicyError("invalid acquisition configuration") from None
        if environment_size > 65536:
            raise PolicyError("invalid acquisition environment")
        if (not _number(total_timeout_seconds) or not _number(cleanup_grace_seconds)
                or not 0 < cleanup_grace_seconds < total_timeout_seconds <= 30
                or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 65536
                or not callable(wall_clock) or not callable(monotonic_clock)):
            raise PolicyError("invalid acquisition budgets or clocks")
        self._executable, self._environment, self._cwd = executable, dict(environment), cwd
        self._wall_clock, self._monotonic_clock = wall_clock, monotonic_clock
        self._total, self._grace, self._cap = total_timeout_seconds, cleanup_grace_seconds, max_output_bytes
        self._lock = threading.Lock()
        self._halted = False

    def _wall(self):
        try:
            value = self._wall_clock()
            timestamp(value)
            return value
        except Exception:
            raise PolicyError("invalid acquisition wall clock") from None

    def _clock(self, previous=None):
        try:
            value = self._monotonic_clock()
            if (not _number(value) or value < 0 or value > 2**53
                    or (previous is not None and value < previous)):
                raise ValueError
            return value
        except Exception:
            raise PolicyError("invalid acquisition monotonic clock") from None

    def acquire(self, source_kind, *, stop_event):
        if (type(source_kind) is not str or source_kind not in COMMANDS
                or not callable(getattr(stop_event, "is_set", None))):
            raise PolicyError("invalid acquisition request")
        if not self._lock.acquire(blocking=False):
            raise PolicyError("acquisition already active")
        try:
            if self._halted:
                raise PolicyError("acquisition halted after incomplete cleanup")
            return self._acquire(source_kind, stop_event)
        finally:
            self._lock.release()

    def _acquire(self, kind, stop_event):
        start = self._wall()
        clock = self._clock()
        logical_deadline = clock + self._total - self._grace
        if not math.isfinite(logical_deadline) or logical_deadline <= clock:
            raise PolicyError("invalid acquisition clock range")
        real_deadline = time.monotonic() + self._total
        execution_deadline = real_deadline - self._grace
        process = None
        output = bytearray()
        error = None
        clean = True
        try:
            if stop_event.is_set():
                error = "unavailable"
            else:
                process = subprocess.Popen(
                    [self._executable, COMMANDS[kind]], cwd=self._cwd,
                    env=self._environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True, close_fds=True,
                )
                count = 0
                with selectors.DefaultSelector() as selector:
                    for pipe in (process.stdout, process.stderr):
                        os.set_blocking(pipe.fileno(), False)
                        selector.register(pipe, selectors.EVENT_READ)
                    while True:
                        clock = self._clock(clock)
                        remaining = min(logical_deadline - clock,
                                        execution_deadline - time.monotonic())
                        if stop_event.is_set():
                            error = "unavailable"
                            break
                        if remaining <= 0:
                            error = "timeout"
                            break
                        if not selector.get_map() and process.poll() is not None:
                            if process.returncode != 0:
                                error = "unavailable"
                            break
                        for key, _ in selector.select(min(.02, remaining)):
                            data = os.read(key.fd, min(4096, self._cap - count + 1))
                            if not data:
                                selector.unregister(key.fileobj)
                            else:
                                count += len(data)
                                if count > self._cap:
                                    error = "unavailable"
                                    break
                                if key.fileobj is process.stdout:
                                    output.extend(data)
                        if error:
                            break
        except PermissionError:
            error = "permission_denied" if process is None else "unavailable"
        except Exception:
            error = "unavailable"
        finally:
            if process is not None:
                clean = _cleanup(process, real_deadline, self._grace)
                if not clean:
                    self._halted = True
                    error = error or "unavailable"
        try:
            result = (AdapterResult({}, (error,)) if error else
                      parse_observations(kind, bytes(output), observed_at=start, ttl=60))
        finally:
            output.clear()
        return AcquisitionResult(kind, start, self._wall(), result, clean)
