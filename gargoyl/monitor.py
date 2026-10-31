"""Local read-only monitoring: continuous state polling and a loopback dashboard.

Only normalized evidence is retained, in bounded process memory. No keys, durable
plaintext spool, producer commands, enrollment, delivery or repair capability.
"""
import http.client
import math
import signal
import sys
import threading
import time
from collections import deque
from html import escape

from gargoyl.collector import collect
from gargoyl.collector_state_file import read_daemon_state, validate_daemon_state_source
from gargoyl.dashboard import render_dashboard
from gargoyl.dashboard.runtime import EvidenceViewer, utc_now
from gargoyl.telemetry import effective_state, host_id, timestamp, validate_snapshot


def traffic_window(samples, now):
    """Compare fresh contiguous counter observations without asserting billing or uptime."""
    if len(samples) < 2:
        return None
    recent = []
    for sample in reversed(samples):
        fields = sample['fields']
        request = fields['requests_total']
        tokens = fields['tokens_total']
        if (fields['error_code']['value'] != 'none'
                or effective_state(request, now) != 'observed'
                or effective_state(tokens, now) != 'observed'
                or request['timestamp'] != tokens['timestamp']
                or request['value'] is None or tokens['value'] is None):
            break
        recent.append((request, tokens))
    if len(recent) < 2:
        return None
    recent.reverse()
    for (previous, previous_tokens), (current, current_tokens) in zip(recent, recent[1:]):
        if (timestamp(current['timestamp']) < timestamp(previous['timestamp'])
                or (current['timestamp'] == previous['timestamp']
                    and (current['value'] != previous['value']
                         or current_tokens['value'] != previous_tokens['value']))
                or current['value'] < previous['value']
                or current_tokens['value'] < previous_tokens['value']):
            return None
    first, first_tokens = recent[0]
    last, last_tokens = recent[-1]
    elapsed = (timestamp(last['timestamp']) - timestamp(first['timestamp'])).total_seconds()
    if elapsed <= 0:
        return None
    return last['value'] - first['value'], last_tokens['value'] - first_tokens['value'], elapsed


class LocalMonitor:
    """Single collection owner, locked detached reads; at most 64 observations."""

    def __init__(self, source, owner_uid, identity, *, interval=5, clock=utc_now):
        host_id(identity)
        validate_daemon_state_source(source, owner_uid)
        if (type(interval) not in (int, float) or not math.isfinite(interval)
                or not 1 <= interval <= 60 or not callable(clock)):
            raise ValueError('invalid monitor configuration')
        self.source, self.owner_uid, self.identity = source, owner_uid, identity
        self.interval, self.clock = interval, clock
        self._lock = threading.Lock()
        self._history = deque(maxlen=64)
        self._collections = 0

    def tick(self):
        now = self.clock()
        result = read_daemon_state(self.source, expected_owner_uid=self.owner_uid, now=now)
        snapshot = collect(self.identity, now, result.result.readings, errors=result.result.errors)
        with self._lock:
            self._history.append(snapshot)
            self._collections += 1
        return validate_snapshot(snapshot)

    def snapshots(self, *, now):
        timestamp(now)
        with self._lock:
            # Never let a previously good sample mask a current failed read.
            return [validate_snapshot(self._history[-1])] if self._history else []

    def render_page(self, now):
        with self._lock:
            samples = [validate_snapshot(item) for item in self._history]
            count = self._collections
        page = render_dashboard(samples[-1:], [self.identity], now)
        summary = ('<section aria-label="Live collection"><h2>Local collection</h2>'
                   f'<p>{count} completed polls · {self.interval:g}s interval · '
                   'Repairs disabled · Memory only</p>')
        if samples:
            fields = samples[-1]['fields']
            summary += '<p>Latest source read: <strong>' + escape(fields['error_code']['value']) + '</strong>. '
            source = fields['requests_total']
            source_state = effective_state(source, now)
            age = max(0, (timestamp(now) - timestamp(source['timestamp'])).total_seconds())
            summary += 'A current collector heartbeat does not establish a current source.</p>'
            summary += f'<p>Request evidence: <strong>{escape(source_state)}</strong> · age {age:.0f}s · TTL 60s. Unknown timestamps describe collection, not a successful source read.</p>'
            summary += '<p>Requests total: <strong>' + escape(str(fields['requests_total']['value']) if fields['requests_total']['value'] is not None else 'unknown') + '</strong> · Tokens total: <strong>' + escape(str(fields['tokens_total']['value']) if fields['tokens_total']['value'] is not None else 'unknown') + '</strong>. Cumulative source claims.</p>'
            window = traffic_window(samples, now)
            if window is None:
                summary += '<p>Recent counter change: unknown (not enough fresh, continuous evidence).</p>'
            else:
                requests, tokens, elapsed = window
                summary += (f'<p>Recent counter change: {requests} requests · {tokens} tokens '
                            f'over {elapsed:.0f}s of source timestamps. Counter changes are '
                            'not confirmed paid work; an undetected reset can affect this comparison.</p>')
            summary += '<details><summary>Recent traffic observations</summary><div class="scroll"><table><thead><tr><th>Collected at</th><th>Requests total</th><th>Tokens total</th><th>Source timestamp</th><th>Read error</th></tr></thead><tbody>'
            for sample in reversed(samples):
                f = sample['fields']
                values = [sample['collected_at'], f['requests_total']['value'],
                          f['tokens_total']['value'], f['requests_total']['timestamp'],
                          f['error_code']['value']]
                summary += '<tr>' + ''.join('<td>' + escape(str(v) if v is not None else 'unknown') + '</td>' for v in values) + '</tr>'
            summary += '</tbody></table></div></details>'
        else:
            summary += '<p>Waiting for first observation. Source state is unknown.</p>'
        summary += '<p>Up to 64 normalized observations remain in this process. Restart clears history. No earnings or daemon liveness are inferred.</p></section>'
        return page.replace('<h1>Fleet evidence</h1>', '<h1>Gargoyl local monitor</h1>' + summary)


class MonitorViewer(EvidenceViewer):
    # Permit the same loopback endpoint to restart while previous HTTP
    # connections are in TIME_WAIT. This does not enable SO_REUSEPORT or
    # permit replacing another active listener.
    allow_reuse_address = True

    def render_page(self, now):
        return self.reader.render_page(now)


def run_monitor(monitor, *, port=8765, stop=None, ready=None):
    """Run until stop; caller owns signal handling. Always close and join viewer."""
    stop = stop or threading.Event()
    viewer = MonitorViewer(monitor, [monitor.identity], port=port, refresh_seconds=2)
    thread = threading.Thread(target=viewer.serve_forever, name='gargoyl-viewer', daemon=True)
    try:
        monitor.tick()
        thread.start()
        if ready:
            ready(viewer.server_port)
        due = time.monotonic() + monitor.interval
        while not stop.is_set():
            remaining = due - time.monotonic()
            if remaining > 0:
                stop.wait(min(remaining, 0.2))
                continue
            monitor.tick()
            now = time.monotonic()
            due += (math.floor(max(0, now - due) / monitor.interval) + 1) * monitor.interval
        return 0
    finally:
        if thread.is_alive():
            viewer.shutdown()
            thread.join()
        viewer.server_close()


def status(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid status port')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=6)
    try:
        connection.request('HEAD', '/')
        response = connection.getresponse()
        running = response.status == 200 and (response.getheader('Server') or '').strip() == 'Gargoyl'
        print('Local viewer responding; inspect source freshness in the dashboard.' if running
              else 'Local viewer unavailable; monitoring is not established.')
        return 0 if running else 1
    except (OSError, http.client.HTTPException):
        print('Local viewer unavailable; monitoring is not established.')
        return 1
    finally:
        connection.close()


def main(args):
    if args.command == 'status':
        return status(args.port)
    if type(args.port) is not int or not 0 <= args.port <= 65535:
        raise ValueError('invalid monitor port')
    monitor = LocalMonitor(args.input, args.owner_uid, args.host, interval=args.interval)

    class SignalStop:
        requested = False

        def is_set(self):
            return self.requested

        def wait(self, seconds):
            time.sleep(min(seconds, 0.2))

    stop = SignalStop()
    previous = {}

    def request_stop(signum, frame):
        stop.requested = True

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, request_stop)
        return run_monitor(monitor, port=args.port, stop=stop,
                           ready=lambda port: print(f'Gargoyl listening on http://127.0.0.1:{port}/; repairs disabled. Ctrl-C to stop.', flush=True))
    except Exception:
        print('Local monitoring failed; listener stopped. No repair attempted.', file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
