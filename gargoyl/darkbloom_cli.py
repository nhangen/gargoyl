"""Fixed, explicitly configured Darkbloom CLI invocations for the local operator console.

Only argument vectors written here are executed; there is no shell, discovery or
user-supplied argument. Raw output is parsed into fixed fields and discarded.
Supported semantics come from the inspected 0.10.5/0.10.6 release sources (their
RestartCommand, ServiceDrain and doctor renderer are identical between tags).
This is not an OS sandbox: upstream commands may read configuration and use the network.
"""
import hashlib
import os
import pwd
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass

from gargoyl.collector_acquisition import _cleanup
from gargoyl.telemetry import PolicyError

# Release sources inspected for restart/drain/doctor semantics, with the installed
# executable digests recorded during investigation (docs/darkbloom-restart-evidence.md,
# docs/local-diagnostic-collection.md). Other versions are reported as unsupported.
SUPPORTED_VERSIONS = {
    '0.10.5': 'f568a3de578664bbc4246a3e51688aa9595fe51b7aaac8e26bbd829b8733b85d',
    '0.10.6': '4474b0605343b502f58c45e7e696dba575d4802eb56cd30802ab9b526371c7c3',
}
# Upstream defaults, passed explicitly so the confirmation page states what will run.
RESTART_DRAIN_TIMEOUT = 600
RESTART_STARTUP_TIMEOUT = 180
RESTART_ARGUMENTS = ('restart', '--timeout', str(RESTART_DRAIN_TIMEOUT),
                     '--startup-timeout', str(RESTART_STARTUP_TIMEOUT))
MAX_OUTPUT_BYTES = 65536


def validate_executable(path, owner_uid):
    """Absolute, canonical, owner- or root-owned regular executable; no group/other write."""
    if (type(path) is not str or not path.startswith('/') or len(path) > 4096 or '\0' in path
            or os.path.realpath(path) != path):
        raise PolicyError('invalid provider executable')
    info = os.stat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (owner_uid, 0)
            or info.st_mode & 0o022 or not info.st_mode & 0o100):
        raise PolicyError('invalid provider executable')
    return path


def executable_file(path):
    """Cheap identity of the executable file, to notice replacement after it was inspected."""
    try:
        info = os.stat(path)
    except OSError:
        return None
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]


def executable_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def cli_environment(owner_uid):
    """Minimal explicit environment; nothing is inherited from the monitor's parent."""
    home = pwd.getpwuid(owner_uid).pw_dir
    return {'HOME': home, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C',
            'NO_COLOR': '1', 'TERM': 'dumb', 'USER': pwd.getpwuid(owner_uid).pw_name}


@dataclass(frozen=True)
class RunResult:
    returncode: object  # int, or None when the command did not finish
    output: bytes
    error: object  # None, 'timeout', 'output_limit', 'unavailable', 'permission_denied'
    cleanup_complete: bool


def run_bounded(argv, *, environment, cwd, timeout_seconds, grace_seconds=1.0):
    """Run a fixed argv with a deadline, combined bounded output and verified cleanup.

    Unlike collection acquisition, a nonzero exit is a result, not an error: doctor
    reports failed checks through its exit status.
    """
    if (type(argv) is not tuple or not argv or any(type(a) is not str for a in argv)
            or not 0 < grace_seconds < timeout_seconds <= 60):
        raise PolicyError('invalid command request')
    deadline = time.monotonic() + timeout_seconds
    output = bytearray()
    error = None
    process = None
    try:
        process = subprocess.Popen(list(argv), cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - grace_seconds - time.monotonic()
                if remaining <= 0:
                    error = 'timeout'
                    break
                for key, _ in selector.select(min(0.05, remaining)):
                    data = os.read(key.fd, 4096)
                    if not data:
                        selector.unregister(key.fileobj)
                    elif len(output) + len(data) > MAX_OUTPUT_BYTES:
                        error = 'output_limit'
                        break
                    else:
                        output.extend(data)
                if error:
                    break
            while error is None and process.poll() is None:
                if time.monotonic() >= deadline - grace_seconds:
                    error = 'timeout'
                    break
                time.sleep(0.02)
    except PermissionError:
        error = 'permission_denied'
    except OSError:
        error = 'unavailable'
    clean = True
    if process is not None:
        clean = _cleanup(process, deadline, grace_seconds)
        if process.stdout:
            process.stdout.close()
    returncode = process.returncode if process is not None and error is None else None
    return RunResult(returncode, bytes(output), error, clean)


def _lines(output):
    try:
        text = output.decode('utf-8')
    except UnicodeDecodeError:
        return None
    return [line.rstrip('\r') for line in text.split('\n')]


def parse_version(result):
    """`darkbloom --version` prints only the version string."""
    if result.error or result.returncode != 0:
        return None
    lines = [line for line in (_lines(result.output) or []) if line.strip()]
    if len(lines) == 1 and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', lines[0].strip()):
        return lines[0].strip()
    return None


def parse_doctor(result):
    """Summarize `doctor` (no flags) by level counts from its DETAILED CHECKS section.

    Check names and details are discarded (they can carry paths, URLs or model
    names). Exit 0 means no failure-level check; exit 1 means at least one.
    Anything else is unsupported output, never a guessed pass.
    """
    if result.error or result.returncode not in (0, 1):
        return None
    lines = _lines(result.output)
    if lines is None or lines.count('DETAILED CHECKS') != 1:
        return None
    counts = {'PASS': 0, 'WARN': 0, 'FAIL': 0, 'INFO': 0}
    for line in lines[lines.index('DETAILED CHECKS') + 1:]:
        if not line:
            break
        match = re.fullmatch(r'  \[(PASS|WARN|FAIL|INFO)\] [^:\n]{1,200}: .*', line)
        if not match:
            return None
        counts[match.group(1)] += 1
    if not sum(counts.values()) or (counts['FAIL'] > 0) != (result.returncode == 1):
        return None
    return {'passed': counts['PASS'], 'warnings': counts['WARN'], 'failed': counts['FAIL'],
            'info': counts['INFO'], 'exit': result.returncode}


# Fixed progress/result messages from RestartCommand.swift and ServiceDrain.swift
# (0.10.5/0.10.6). Each maps to a normalized event; raw text is never displayed.
RESTART_EVENTS = (
    ('draining', re.compile(r'Draining accepted requests \(deadline: [0-9]+s\)\. New work is refused by the running provider\.')),
    ('remaining', re.compile(r'  ([0-9]{1,9}) accepted request\(s\) remaining')),
    ('awaiting_ack', re.compile(r'  Requests finished; waiting for coordinator usage acknowledgement')),
    ('drained', re.compile(r'Drain drained: ([0-9]{1,9}) unfinished request\(s\); coordinator acknowledgement: (received|not needed \(no coordinator connection\))\.')),
    ('forced', re.compile(r'Forced (?:stop|lifecycle requested|termination).*')),
    ('relaunched', re.compile(r'Drained provider relaunched; waiting for fresh authorization\.\.\.')),
    ('started', re.compile(r'Provider started\.')),
    ('authorized', re.compile(r'Provider restarted and freshly authorized \([^)\n]{0,64}\)\.')),
    ('drain_incomplete', re.compile(r'(?:Error: )?(?:Drain did not complete: |No completed drain acknowledgement before the deadline\.).*')),
    ('drain_exit', re.compile(r'(?:Error: )?Provider exited before confirming its drain\..*')),
    ('stop_timeout', re.compile(r'(?:Error: )?The drained provider is still shutting down\. No replacement was started\..*')),
    ('unconfirmed', re.compile(r'(?:Error: )?Restart launched, but fresh authorization was not confirmed within [0-9]+s\..*')),
    ('refused_identity', re.compile(r'(?:Error: )?Cannot confirm the running provider identity\. No process or recovery setting was changed\.')),
    ('refused_no_drain', re.compile(r'(?:Error: )?This running provider does not expose graceful-drain control\..*')),
    ('refused_not_installed', re.compile(r'(?:Error: )?No launchd configuration is installed\..*')),
    ('not_running', re.compile(r'Provider is not running\. Start it with .*')),
)

# Outcome classes. Only 'cli_confirmed' can become verified; everything else keeps
# the restart gate closed until read-only reconciliation.
OUTCOME_TEXT = {
    'cli_confirmed': 'Darkbloom reported the provider restarted and freshly authorized.',
    'relaunched_unconfirmed': 'The provider was relaunched, but fresh authorization was not confirmed. Outcome unknown.',
    'not_restarted_attention': 'No replacement was started, but the drain began: the provider may remain draining with automatic restart disabled.',
    'refused_no_change': 'Darkbloom refused before changing the provider.',
    'forced_anomaly': 'Darkbloom reported a forced lifecycle, which Gargoyl never requests. Outcome unknown.',
    'unknown': 'The restart command ended without a recognised result. Outcome unknown.',
}


def restart_events(output):
    """Return (events, unrecognised_line_count); events carry only fixed fields."""
    lines = _lines(output)
    if lines is None:
        return [], -1
    events, unknown = [], 0
    for line in lines:
        if not line.strip():
            continue
        for name, pattern in RESTART_EVENTS:
            match = pattern.fullmatch(line)
            if match:
                value = int(match.group(1)) if name in ('remaining', 'drained') else None
                events.append((name, value))
                break
        else:
            unknown += 1
    return events, unknown


def classify_restart(events, returncode):
    names = {name for name, _ in events}
    if 'forced' in names:
        return 'forced_anomaly'
    launched = bool(names & {'relaunched', 'started'})
    if launched and 'authorized' in names and returncode == 0:
        return 'cli_confirmed'
    if launched:
        return 'relaunched_unconfirmed'
    if names & {'drain_incomplete', 'drain_exit', 'stop_timeout'}:
        return 'not_restarted_attention'
    if names & {'refused_identity', 'refused_no_drain', 'refused_not_installed', 'not_running'} and returncode not in (0, None):
        return 'refused_no_change'
    return 'unknown'


def progress(events):
    """Latest normalized phase for display while the command runs."""
    phase, remaining = 'starting', None
    for name, value in events:
        if name == 'draining':
            phase = 'draining'
        elif name == 'remaining':
            phase, remaining = 'draining', value
        elif name == 'awaiting_ack':
            phase, remaining = 'awaiting_ack', 0
        elif name == 'drained':
            phase, remaining = 'drained', value
        elif name in ('relaunched', 'started'):
            phase = 'awaiting_authorization'
        elif name == 'authorized':
            phase = 'authorized'
    return phase, remaining
