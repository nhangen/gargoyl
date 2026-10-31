"""Fixed, bounded read-only macOS unified-log query. Raw text never leaves this module."""
import json
import os
import selectors
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone

from gargoyl.telemetry import timestamp

LIMIT = 65536
TTL = 45


def unknown(reason, now):
    return dict(state='unknown', reason=reason, observed_at=now, freshness_seconds=TTL,
                window_start=None, window_end=None, count=None, redacted_count=None,
                latest_event_at=None)



def validate_log_report(value):
    keys = {'state', 'reason', 'observed_at', 'freshness_seconds', 'window_start',
            'window_end', 'count', 'redacted_count', 'latest_event_at'}
    if (type(value) is not dict or set(value) != keys or type(value['freshness_seconds']) is not int or value['freshness_seconds'] != TTL
            or value['state'] not in {'observed', 'unknown'}
            or value['reason'] not in {'not_configured', 'target_unverified', 'cleanup_unconfirmed',
                'query_unavailable', 'permission_denied', 'source_stale', 'visible_records_only', 'target_or_state_unverified'}):
        raise ValueError('log evidence unavailable')
    observed = timestamp(value['observed_at'])
    if value['state'] == 'unknown':
        if any(value[k] is not None for k in ('window_start', 'window_end', 'count',
                                             'redacted_count', 'latest_event_at')):
            raise ValueError('log evidence unavailable')
    else:
        start, end = timestamp(value['window_start']), timestamp(value['window_end'])
        if (not start <= end <= observed or value['reason'] != 'visible_records_only'
                or type(value['count']) is not int or not 0 <= value['count'] <= 512
                or type(value['redacted_count']) is not int
                or not 0 <= value['redacted_count'] <= value['count']):
            raise ValueError('log evidence unavailable')
        if value['count']:
            if not start <= timestamp(value['latest_event_at']) <= end:
                raise ValueError('log evidence unavailable')
        elif value['latest_event_at'] is not None:
            raise ValueError('log evidence unavailable')
    return dict(value)

def parse_records(payload, *, pid, owner_uid, start, end):
    """Strict NDJSON metadata allowlist; message content supplies only a redaction bit."""
    if type(payload) is not bytes or len(payload) > LIMIT:
        raise ValueError('log evidence unavailable')
    seen = {}
    events = []
    raw_count = 0
    finished = False
    for line in payload.splitlines():
        if not line.strip():
            continue
        if len(line) > 16384:
            raise ValueError('log evidence unavailable')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('log evidence unavailable')
                result[key] = value
            return result
        record = json.loads(line, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('log evidence unavailable')))
        if finished:
            raise ValueError('log evidence unavailable')
        if (type(record) is dict and set(record) == {'count', 'finished'}
                and type(record['count']) is int and record['count'] == raw_count
                and type(record['finished']) in (bool, int) and record['finished'] == 1):
            finished = True
            continue
        if (type(record) is not dict or record.get('eventType') != 'logEvent'
                or record.get('subsystem') != 'dev.darkbloom.provider'
                or record.get('category') != 'coordinator'
                or type(record.get('processID')) is not int or record['processID'] != pid
                or type(record.get('userID')) is not int or record['userID'] != owner_uid
                or record.get('messageType') not in {'Error', 'Fault'}):
            raise ValueError('log evidence unavailable')
        at = record.get('timestamp')
        if type(at) is not str or len(at) > 40:
            raise ValueError('log evidence unavailable')
        event = datetime.strptime(at, '%Y-%m-%d %H:%M:%S.%f%z').astimezone(timezone.utc)
        if not timestamp(start) <= event <= timestamp(end):
            raise ValueError('log evidence unavailable')
        metadata = []
        for key in ('machTimestamp', 'threadID', 'traceID'):
            value = record.get(key)
            if type(value) is not int or not 0 <= value < 2**64:
                raise ValueError('log evidence unavailable')
            metadata.append(value)
        raw_count += 1
        key = (event, *metadata)
        message = record.get('eventMessage')
        if type(message) is not str:
            raise ValueError('log evidence unavailable')
        redacted = '<private>' in message
        if key in seen:
            if seen[key] != redacted:
                raise ValueError('log evidence unavailable')
            continue
        seen[key] = redacted
        events.append((event, redacted))
        if len(events) > 512:
            raise ValueError('log evidence unavailable')
    if not finished:
        raise ValueError('log evidence unavailable')
    return dict(count=len(events), redacted_count=sum(redacted for _, redacted in events),
                latest_event_at=max(at for at, _ in events).isoformat().replace('+00:00', 'Z') if events else None)


def _capture(argv, stop):
    """Only the fixed log reader child is terminated, never the provider or a process group."""
    process = None
    total = time.monotonic() + 3
    output = bytearray()
    count = 0
    succeeded = False
    denied = False
    diagnostic_stderr = bytearray()
    try:
        if stop.is_set():
            raise TimeoutError
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'TZ': 'UTC', 'LC_ALL': 'C'},
            cwd='/', close_fds=True)
        with selectors.DefaultSelector() as selector:
            for pipe in (process.stdout, process.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                if stop.is_set() or time.monotonic() >= total - 1:
                    raise TimeoutError
                for key, _ in selector.select(.05):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(chunk)
                    if count > LIMIT:
                        raise ValueError('log evidence unavailable')
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
                    else:
                        diagnostic_stderr.extend(chunk[:max(0, 4096-len(diagnostic_stderr))])
            if process.wait(timeout=max(.01, total - 1 - time.monotonic())) != 0:
                lower = bytes(diagnostic_stderr).lower()
                denied = any(token in lower for token in (b'not permitted', b'permission denied',
                                                          b'cannot run while sandboxed', b'not authorized'))
                raise ValueError('log query unavailable')
        succeeded = True
    except Exception as error:
        denied = denied or isinstance(error, PermissionError)
    finally:
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=max(.01, (total - time.monotonic()) / 2))
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=max(.01, total - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
    clean = process is None or process.poll() is not None
    if denied and clean:
        raise PermissionError('scoped log query denied')
    return bytes(output) if succeeded and clean else None, clean



def process_birth(identity):
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=identity['born_us'])

def _system_log_valid():
    info = os.lstat('/usr/bin/log')
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


class CoordinatorLogReader:
    def __init__(self, *, executable, clock):
        self.executable, self.clock = executable, clock
        self._cached = None
        self._identity = None
        self._due = 0
        self._halt_reason = None

    def read(self, identity, verifier, *, now, stop):
        if self._halt_reason:
            return unknown(self._halt_reason, now)
        if not verifier(identity):
            return unknown('target_unverified', now)
        if self._identity == identity and time.monotonic() < self._due and self._cached:
            return dict(self._cached)
        self._identity = dict(identity)
        self._due = time.monotonic() + 30
        try:
            if not _system_log_valid():
                raise ValueError
            predicate = ('subsystem == "dev.darkbloom.provider" AND category == "coordinator" '
                         f'AND processIdentifier == {identity["pid"]} '
                         'AND (messageType == 16 OR messageType == 17)')
            payload, clean = _capture(['/usr/bin/log', 'show', '--style', 'ndjson',
                                         '--last', '5m', '--predicate', predicate], stop)
            end = self.clock()
            if not clean:
                self._halt_reason = 'cleanup_unconfirmed'
            if not clean or payload is None:
                raise ValueError
            if not verifier(identity):
                self._identity, self._cached, self._due = None, None, 0
                return unknown('target_unverified', now)
            start = max(timestamp(now) - timedelta(seconds=300),
                        process_birth(identity))
            if timestamp(end) < timestamp(now) or (timestamp(end) - timestamp(now)).total_seconds() > 3.5:
                raise ValueError
            values = parse_records(payload, pid=identity['pid'], owner_uid=identity['owner_uid'],
                                   start=start.isoformat(), end=end)
            self._cached = dict(state='observed', reason='visible_records_only', observed_at=end,
                freshness_seconds=TTL, window_start=start.isoformat(), window_end=end, **values)
        except PermissionError:
            self._halt_reason = 'permission_denied'
            self._cached = unknown(self._halt_reason, now)
        except Exception:
            self._halt_reason = self._halt_reason or 'query_unavailable'
            self._cached = unknown(self._halt_reason, now)
        return dict(self._cached)
