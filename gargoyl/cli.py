"""Explicit local parsing or one-shot acquisition, without persistence or repairs."""

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from gargoyl.collector_acquisition import BoundedAcquirer
from gargoyl.collector_adapters import MAX_SOURCE_BYTES, parse_observations
from gargoyl.collector_state_file import read_daemon_state
from gargoyl.telemetry import timestamp

KINDS = {'status': 'darkbloom_status_text_v1', 'doctor': 'darkbloom_doctor_text_v1'}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default includes user-supplied argument values.
        raise ValueError('invalid CLI arguments')


class _StopFlag:
    requested = False

    def is_set(self):
        return self.requested


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _read(path):
    if path == '-':
        return sys.stdin.buffer.read(MAX_SOURCE_BYTES + 1)
    with Path(path).open('rb') as stream:
        return stream.read(MAX_SOURCE_BYTES + 1)


def _environment(path):
    if path == '-':
        raise ValueError('environment requires an explicit file')
    payload = _read(path)
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError('environment limit exceeded')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate environment key')
            result[key] = value
        return result

    return json.loads(payload.decode('utf-8'), object_pairs_hook=unique)


def _emit(kind, observed, result, *, completed=None, cleanup=None, interrupted=False):
    value = dict(schema_version=1, source_kind=kind, observed_at=observed,
                 readings=result.readings, errors=list(result.errors))
    if cleanup is not None:
        value.update(completed_at=completed, cleanup_complete=cleanup)
    if interrupted or cleanup is False:
        value.update(readings={}, errors=['unavailable'])
    print(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))


def main(argv=None):
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Parse supplied bytes; execute nothing.')
    inspect.add_argument('source', choices=(*KINDS, 'state'))
    inspect.add_argument('--input', required=True, help='Text: file or stdin (-); state: absolute file path.')
    inspect.add_argument('--observed-at', help='Required UTC source time for text; forbidden for state.')
    inspect.add_argument('--owner-uid', type=int, help='Required expected owner UID for state; forbidden for text.')
    capture = commands.add_parser('capture', help='Explicitly execute one bounded local acquisition.',
        description='Upstream status/doctor may read keys/files and use the network. '
                    'This is not a sandbox, authenticated repair, or durable collection.')
    capture.add_argument('source', choices=KINDS)
    capture.add_argument('--executable', required=True, help='Explicit trusted absolute executable.')
    capture.add_argument('--cwd', required=True, help='Explicit absolute working directory.')
    capture.add_argument('--environment', required=True, help='Explicit JSON environment file; {} is allowed. '
                         'No parent environment is inherited.')
    monitor = commands.add_parser('monitor', help='Continuously read owner-local state and serve a loopback dashboard.')
    monitor.add_argument('--input', required=True, help='Absolute private daemon-state file.')
    monitor.add_argument('--owner-uid', required=True, type=int)
    monitor.add_argument('--host', required=True, help='Stable opaque host UUID; no enrollment implied.')
    monitor.add_argument('--interval', type=float, default=5)
    monitor.add_argument('--port', type=int, default=8765)
    monitor.add_argument('--provider-executable', help='Explicit canonical provider image; enables owner-local native diagnostics.')
    monitor.add_argument('--coordinator-errors', action='store_true', help='Opt in to a bounded current-provider coordinator error/fault query; requires --provider-executable.')
    status = commands.add_parser('status', help='Check the local viewer; does not imply source health.')
    status.add_argument('--port', type=int, default=8765)
    try:
        args = parser.parse_args(argv)
        if args.command in {'monitor', 'status'}:
            from gargoyl.monitor import main as monitor_main
            return monitor_main(args)
        if args.command == 'inspect' and args.source == 'state':
            if args.observed_at is not None or args.owner_uid is None:
                raise ValueError('invalid state inspection arguments')
            state_result = read_daemon_state(args.input, expected_owner_uid=args.owner_uid,
                                             now=_utc_now(), ttl=60)
            _emit('darkbloom_daemon_state_json_v1', state_result.observed_at, state_result.result)
            return 1 if state_result.result.errors else 0
        kind = KINDS[args.source]
        if args.command == 'inspect':
            if args.owner_uid is not None:
                raise ValueError('invalid text inspection arguments')
            timestamp(args.observed_at)
            payload = _read(args.input)
            result = parse_observations(kind, payload, observed_at=args.observed_at)
            _emit(kind, args.observed_at, result)
            return 1 if result.errors else 0
        acquirer = BoundedAcquirer(args.executable, environment=_environment(args.environment),
            cwd=args.cwd, wall_clock=_utc_now, monotonic_clock=time.monotonic,
            total_timeout_seconds=5, cleanup_grace_seconds=1, max_output_bytes=65536)
    except (ValueError, OSError, UnicodeError, RecursionError):
        print('CLI input or configuration unavailable or invalid.', file=sys.stderr)
        return 2

    stop = _StopFlag()

    def request_stop(signum, frame):
        # Signal handlers must not acquire Event/Condition locks: a second
        # signal can reenter while the first handler still owns that lock.
        stop.requested = True

    previous = {}
    try:
        # Signals request cleanup instead of raising out of acquisition. Repeated
        # signals also only assign the flag; restore caller handlers on every path.
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, request_stop)
        acquired = acquirer.acquire(kind, stop_event=stop)
        # Commit one result before publication. Signals during/after output do
        # not change the already chosen JSON or exit status.
        interrupted = stop.is_set()
        _emit(kind, acquired.observed_at, acquired.result, completed=acquired.completed_at,
              cleanup=acquired.cleanup_complete, interrupted=interrupted)
        if not acquired.cleanup_complete:
            return 3
        if interrupted:
            return 130
        return 1 if acquired.result.errors else 0
    except Exception:
        print('Acquisition unavailable; no result established.', file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
