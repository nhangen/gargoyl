"""Operator-triggered Darkbloom restart: one durable attempt record and a closed gate.

This wraps Darkbloom's own `restart` (graceful drain, no --force) for a person who
explicitly confirmed it. It is not unattended repair and adds no retry.

Guarantees, stated narrowly:
- An attempt is durably claimed (fsync + atomic rename) before the command starts.
- While any attempt is unresolved the gate stays closed; only a verified success
  or an explicit read-only reconciliation reopens it. Nothing retries.
- The command runs in its own session and writes to a private file, so stopping
  this monitor neither signals it nor breaks its output. It is never killed:
  interrupting Darkbloom mid-drain is not a rollback.
Not guaranteed: durable exactly-once execution. A crash between the claim and
recording the child leaves an unknown outcome, and Darkbloom itself does not keep
a durable cross-restart request ledger (docs/darkbloom-restart-evidence.md).
"""
import fcntl
import json
import os
import stat
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone

from gargoyl.collector_state_file import _read
from gargoyl.darkbloom_cli import (
    OUTCOME_TEXT,
    RESTART_ARGUMENTS,
    SUPPORTED_VERSIONS,
    classify_restart,
    cli_environment,
    executable_file,
    progress,
    restart_events,
)
from gargoyl.telemetry import PolicyError, timestamp

RECORD = 'restart.json'
MAX_RECORD = 65536
MAX_OUTPUT = 65536
STATE_FRESH_SECONDS = 60


class Refused(Exception):
    """A restart or reconciliation request was refused; the message is safe to show."""


def _private_directory(path, owner_uid):
    if type(path) is not str or not path.startswith('/') or os.path.realpath(path) != path:
        raise PolicyError('invalid restart state directory')
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o077):
        raise PolicyError('restart state directory must be a private owned directory (mode 0700)')
    return path


def _now_utc():
    return datetime.now(timezone.utc).isoformat()


class AttemptStore:
    """Single-writer private record, locked for the lifetime of this process."""

    def __init__(self, directory, owner_uid):
        self.directory = _private_directory(directory, owner_uid)
        self.uid = owner_uid
        self._lock_fd = os.open(os.path.join(directory, 'lock'),
                                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._lock_fd)
            raise PolicyError('restart state directory is in use by another monitor') from None

    def close(self):
        os.close(self._lock_fd)

    def _path(self, name):
        return os.path.join(self.directory, name)

    def load(self):
        try:
            fd = os.open(self._path(RECORD), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077:
                raise PolicyError('restart record has unsafe ownership or mode')
            data = stream.read(MAX_RECORD + 1)
        if len(data) > MAX_RECORD:
            raise PolicyError('restart record too large')
        record = json.loads(data)
        if type(record) is not dict or record.get('schema') != 1:
            raise PolicyError('unsupported restart record')
        return record

    def save(self, record):
        payload = json.dumps(record, sort_keys=True).encode()
        if len(payload) > MAX_RECORD:
            raise PolicyError('restart record too large')
        temporary = self._path('restart.json.' + uuid.uuid4().hex + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self._path(RECORD))
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def output_path(self, attempt_id):
        return self._path('attempt-' + attempt_id + '.out')

    def read_output(self, attempt_id):
        try:
            fd = os.open(self.output_path(attempt_id), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return b''
        with os.fdopen(fd, 'rb') as stream:
            return stream.read(MAX_OUTPUT + 1)

    def discard_output(self, attempt_id):
        try:
            os.unlink(self.output_path(attempt_id))
        except FileNotFoundError:
            pass


class SystemProcesses:
    """Kernel start time per PID, so a reused PID is never mistaken for our child."""

    def __init__(self):
        self._mac = None
        if sys.platform == 'darwin':
            from gargoyl.repair_process_identity import MacOSProcessVerifier
            # Only its per-PID kernel start-time query is used; the image is not checked here.
            self._mac = MacOSProcessVerifier(expected_owner_uid=os.getuid(),
                                             expected_executable='/usr/bin/true')

    def alive(self, child):
        """True only for the same PID with the same recorded start time."""
        return (child is not None and child.get('born_us') is not None
                and self.birth(child['pid']) == child['born_us'])

    def birth(self, pid):
        try:
            if self._mac is not None:
                return self._mac._identity(pid)['born_us']
            with open(f'/proc/{pid}/stat', 'rb') as stream:
                fields = stream.read().rsplit(b')', 1)[1].split()
            if fields[0] == b'Z':
                return None
            ticks = int(fields[19])
            with open('/proc/stat', 'rb') as stream:
                boot = next(int(line.split()[1]) for line in stream if line.startswith(b'btime '))
            return boot * 1_000_000 + ticks * 1_000_000 // os.sysconf('SC_CLK_TCK')
        except Exception:
            return None


def read_provider_state(source, owner_uid, now):
    """Fixed fields from the owner-local daemon state; raw content is discarded."""
    try:
        state = json.loads(_read(source, owner_uid, 65536))
    except Exception:
        return None
    try:
        written = datetime.fromtimestamp(state['written_at'], timezone.utc)
        identity = state.get('process_identity')
        trust = state.get('trust') if type(state.get('trust')) is dict else {}
        result = {
            'version': state['version'] if type(state.get('version')) is str else None,
            'written_at': written.isoformat(),
            'fresh': 0 <= (timestamp(now) - written).total_seconds() <= STATE_FRESH_SECONDS,
            'trust_status': trust.get('status') if trust.get('status') in
            {'online', 'serving', 'offline', 'untrusted'} else None,
            'identity': None,
        }
        if (type(identity) is dict and type(identity.get('pid')) is int
                and identity.get('pid') == state.get('pid') and identity['pid'] > 0
                and type(identity.get('start_time_micros')) is int
                and 0 < identity['start_time_micros'] < 2**64):
            result['identity'] = {'pid': identity['pid'], 'born_us': identity['start_time_micros']}
        return result
    except Exception:
        return None


class RestartController:
    """Owns the gate, one running attempt and its record. Thread-safe."""

    def __init__(self, *, host, executable, executable_info, owner_uid, source, store,
                 processes=None, provider_verifier=None, clock=_now_utc, launch=subprocess.Popen,
                 environment=None):
        self.host, self.executable, self.info = host, executable, executable_info
        self.uid, self.source, self.store, self.clock = owner_uid, source, store, clock
        self.processes = processes or SystemProcesses()
        self.verify_provider = provider_verifier
        self._launch = launch
        self._environment = environment if environment is not None else cli_environment(owner_uid)
        self._lock = threading.Lock()
        self._live = None  # (events, unknown_count) while our child runs
        self._watcher = None
        self._closed = threading.Event()
        record = store.load() or {'schema': 1, 'host': host, 'current': None, 'history': []}
        if record.get('host') != host:
            raise PolicyError('restart record belongs to a different host')
        self._record = record
        self._recover()

    # -- record helpers ------------------------------------------------------

    def _save(self):
        self.store.save(self._record)

    def _finish(self, current, *, outcome, exit_code, events, unknown, verified, verification, note=None):
        phase, remaining = progress(events)
        current.update(phase='finished', outcome=outcome, exit_code=exit_code,
                       verified=verified, verification=verification, finished_at=self.clock(),
                       last_progress=phase, remaining=remaining, unrecognised_lines=unknown,
                       note=note)
        self._save()
        self.store.discard_output(current['attempt_id'])

    def _recover(self):
        """After a monitor restart: never assume success; keep the gate closed."""
        current = self._record.get('current')
        if not current or current['phase'] not in ('claimed', 'running'):
            return
        child = current.get('child')
        if self.processes.alive(child):
            # Still running from a previous monitor process; watch it, never signal it.
            self._watcher = threading.Thread(target=self._watch_detached, args=(current,),
                                             name='gargoyl-restart-watch', daemon=True)
            self._watcher.start()
            return
        events, unknown = restart_events(self.store.read_output(current['attempt_id']))
        outcome = classify_restart(events, None)  # exit status was not observed
        if outcome == 'cli_confirmed':
            outcome = 'relaunched_unconfirmed'
        reason = ('the monitor stopped before the restart command was recorded as started'
                  if not child else 'the monitor stopped while the restart command was running')
        self._finish(current, outcome=outcome, exit_code=None, events=events, unknown=unknown,
                     verified=False, verification='Not verified: ' + reason + '.',
                     note='interrupted')

    # -- read-only views -----------------------------------------------------

    def snapshot(self):
        with self._lock:
            record = json.loads(json.dumps(self._record))
            live = self._live
        if live is not None and record['current']:
            phase, remaining = progress(live[0])
            record['current']['last_progress'], record['current']['remaining'] = phase, remaining
        return record

    def gate(self):
        """(open, reason). Closed while any attempt is running or unresolved."""
        current = self._record.get('current')
        if not current:
            return True, None
        if current['phase'] in ('claimed', 'running'):
            return False, 'A restart is in progress.'
        if current['phase'] == 'finished' and not current.get('verified'):
            return False, 'The last restart has no verified outcome. Reconcile before another restart.'
        return True, None

    def target(self, now):
        """What a restart would act on now, or a reason it can't be offered."""
        if self.info.get('version') not in SUPPORTED_VERSIONS:
            return None, ('Installed Darkbloom version is unsupported or unreadable. Restart semantics '
                          'were verified only for ' + ', '.join(sorted(SUPPORTED_VERSIONS)) + '.')
        if not self.info.get('recognised_build'):
            return None, ('The installed executable is not a recorded ' + self.info['version'] + ' release '
                          'build (SHA-256 mismatch), so its restart behaviour is unverified.')
        if executable_file(self.executable) != self.info.get('file'):
            return None, ('The Darkbloom executable changed after this monitor inspected it. Restart the '
                          'monitor so the new build is checked.')
        state = read_provider_state(self.source, self.uid, now)
        if state is None:
            return None, 'Provider state is unreadable, so the restart target is unknown.'
        if not state['fresh']:
            return None, 'Provider state is not fresh (older than 60 s), so the restart target is unknown.'
        if state['version'] != self.info['version']:
            return None, 'The running provider reports a different version than the installed CLI.'
        if state['identity'] is None:
            return None, 'Provider state has no process identity, so the target can\'t be confirmed.'
        identity = dict(state['identity'], owner_uid=self.uid)
        kernel = None
        if self.verify_provider is not None:
            kernel = bool(self.verify_provider(identity))
            if not kernel:
                return None, 'The kernel does not confirm the reported provider process.'
        return {'pid': identity['pid'], 'born_us': identity['born_us'], 'version': state['version'],
                'trust_status': state['trust_status'], 'kernel_verified': kernel,
                'token': f"{identity['pid']}:{identity['born_us']}"}, None

    # -- actions -------------------------------------------------------------

    def start(self, *, now, confirmed_token):
        with self._lock:
            opened, reason = self.gate()
            if not opened:
                raise Refused(reason)
            target, reason = self.target(now)
            if target is None:
                raise Refused(reason)
            if confirmed_token != target['token']:
                raise Refused('The provider process changed since the confirmation page was shown. '
                              'Review the new target before restarting.')
            attempt_id = uuid.uuid4().hex
            current = {'attempt_id': attempt_id, 'phase': 'claimed', 'claimed_at': self.clock(),
                       'target': target, 'child': None, 'outcome': None, 'verified': False,
                       'verification': None, 'arguments': list(RESTART_ARGUMENTS)}
            history = self._record.get('history', [])
            previous = self._record.get('current')
            if previous:
                history = ([_summary(previous)] + history)[:20]
            self._record.update(current=current, history=history)
            self._save()  # Durable claim before any effect.
            try:
                fd = os.open(self.store.output_path(attempt_id),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    process = self._launch([self.executable, *RESTART_ARGUMENTS], stdin=subprocess.DEVNULL,
                                           stdout=fd, stderr=subprocess.STDOUT, start_new_session=True,
                                           close_fds=True, env=self._environment,
                                           cwd=self._environment['HOME'])
                finally:
                    os.close(fd)
            except Exception:
                self._finish(current, outcome='refused_no_change', exit_code=None, events=[], unknown=0,
                             verified=False, verification='The restart command could not be started.')
                raise Refused('The restart command could not be started. Nothing was run.') from None
            born = self.processes.birth(process.pid)
            current.update(phase='running', child={'pid': process.pid, 'born_us': born},
                           started_at=self.clock())
            self._save()
            self._live = ([], 0)
            self._watcher = threading.Thread(target=self._watch_child, args=(current, process),
                                             name='gargoyl-restart', daemon=True)
            self._watcher.start()
            return attempt_id

    def _poll_output(self, current):
        events, unknown = restart_events(self.store.read_output(current['attempt_id']))
        with self._lock:
            self._live = (events, unknown)
        return events, unknown

    def _watch_child(self, current, process):
        while process.poll() is None:
            if self._closed.wait(0.5):
                return
            self._poll_output(current)
        if not self._closed.is_set():
            self._complete(current, process.returncode)

    def _watch_detached(self, current):
        child = current['child']
        while self.processes.alive(child):
            if self._closed.wait(1):
                return
            self._poll_output(current)
        if self._closed.is_set():
            return
        with self._lock:
            events, unknown = restart_events(self.store.read_output(current['attempt_id']))
            outcome = classify_restart(events, None)
            if outcome == 'cli_confirmed':
                outcome = 'relaunched_unconfirmed'
            self._finish(current, outcome=outcome, exit_code=None, events=events, unknown=unknown,
                         verified=False, verification='Not verified: this monitor restarted while the '
                         'command ran, so its exit status was not observed.', note='interrupted')
            self._live = None

    def _complete(self, current, returncode):
        with self._lock:
            events, unknown = restart_events(self.store.read_output(current['attempt_id']))
            if unknown < 0:
                events, unknown = [], -1
            outcome = classify_restart(events, returncode)
            verified, verification = False, None
            if outcome == 'cli_confirmed':
                verified, verification = self._verify(current['target'])
            else:
                verification = 'Not verified: ' + OUTCOME_TEXT[outcome]
            self._finish(current, outcome=outcome, exit_code=returncode, events=events,
                         unknown=unknown, verified=verified, verification=verification)
            self._live = None

    def _verify(self, target):
        """Independent check: fresh state names a different, kernel-confirmed process."""
        now = self.clock()
        state = read_provider_state(self.source, self.uid, now)
        if state is None or not state['fresh']:
            return False, 'Not verified: provider state after the restart is unreadable or not fresh.'
        identity = state['identity']
        if identity is None or (identity['pid'], identity['born_us']) == (target['pid'], target['born_us']):
            return False, 'Not verified: provider state still names the original process.'
        if self.verify_provider is None:
            return False, ('Not verified: a new process is reported, but kernel process checks are '
                           'unavailable on this platform.')
        if not self.verify_provider(dict(identity, owner_uid=self.uid)):
            return False, 'Not verified: the kernel does not confirm the newly reported process.'
        return True, ('Verified: fresh provider state names a new process (PID '
                      f"{identity['pid']}), confirmed by the kernel, with trust status "
                      f"{state['trust_status'] or 'unknown'}.")

    def reconcile(self, *, now):
        """Read-only: record what is observable now and reopen the gate. Never restarts."""
        with self._lock:
            current = self._record.get('current')
            if not current or current['phase'] != 'finished' or current.get('verified'):
                raise Refused('There is no unresolved restart to reconcile.')
            child = current.get('child')
            if self.processes.alive(child):
                raise Refused('The restart command is still running. Wait for it to finish.')
            state = read_provider_state(self.source, self.uid, now)
            target = current['target']
            if state is None:
                observed = 'provider state unreadable'
            elif not state['fresh']:
                observed = 'provider state not fresh'
            else:
                identity = state['identity']
                if identity is None:
                    observed = 'fresh state without a process identity'
                elif (identity['pid'], identity['born_us']) == (target['pid'], target['born_us']):
                    observed = 'the original provider process is still reported'
                else:
                    kernel = (self.verify_provider(dict(identity, owner_uid=self.uid))
                              if self.verify_provider else None)
                    observed = ('a different provider process is reported'
                                + (', confirmed by the kernel' if kernel else
                                   ', not confirmed by the kernel' if kernel is False else ''))
                observed += f"; trust status {state['trust_status'] or 'unknown'}"
            current.update(phase='reconciled', reconciled_at=self.clock(),
                           reconciliation='At reconciliation: ' + observed + '. This records the '
                           'present state; it does not prove what happened during the attempt.')
            self._save()
            self.store.discard_output(current['attempt_id'])
            return current['reconciliation']

    def close(self):
        """Stop recording (monitor shutdown). A running command is not signalled; the next
        monitor process recovers its attempt from the durable record as unknown."""
        self._closed.set()

    def wait(self, timeout=None):
        """Test/shutdown helper: join the watcher thread if any."""
        if self._watcher is not None:
            self._watcher.join(timeout)


def _summary(current):
    keys = ('attempt_id', 'claimed_at', 'finished_at', 'outcome', 'verified', 'reconciled_at', 'note')
    return {key: current.get(key) for key in keys}
