"""Opt-in local operator tools behind a per-process secret path.

The public `/` page is unchanged and read-only. Tools live under `/s/<token>/`, where
the token is printed once on the monitor's terminal. It is never set as a cookie:
browsers share 127.0.0.1 cookies across ports, so a cookie could reach other local
servers. Every state-changing request is a POST that must carry the exact Host and
Origin, a same-origin fetch context, a small form body and a single-use nonce
(which also absorbs double clicks). Tools that run Darkbloom use fixed argument
vectors. The token protects against other local users and web pages; any process
running as the same user can already run Darkbloom directly.
"""
import hmac
import json
import secrets
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from html import escape

from gargoyl.collector_adapters import parse_observations
from gargoyl.darkbloom_cli import (
    OUTCOME_TEXT,
    RESTART_ARGUMENTS,
    RESTART_DRAIN_TIMEOUT,
    RESTART_STARTUP_TIMEOUT,
    SUPPORTED_VERSIONS,
    executable_digest,
    executable_file,
    parse_doctor,
    parse_version,
    run_bounded,
)
from gargoyl.dashboard.runtime import _Handler
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.restart_attempts import Refused
from gargoyl.telemetry import timestamp

CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
NONCE_SECONDS = 600
MAX_NONCES = 64
MAX_BODY = 2048

# Capability inventory. Every row is rendered; unsupported and proposed rows say why.
INVENTORY = (
    ('refresh', 'Refresh diagnostics now', 'Read-only', 'available',
     'Collects the owner-local state file immediately instead of waiting for the next poll.'),
    ('version', 'Provider version and build', 'Read-only · runs Darkbloom', 'available',
     'Runs `darkbloom --version` and hashes the configured executable against the recorded release builds.'),
    ('status', 'Daemon status', 'Read-only · runs Darkbloom · uses network', 'available',
     'Runs `darkbloom status` and keeps only its daemon running/stopped line. Status also performs an '
     'update check over the network and reads local configuration.'),
    ('doctor', 'Doctor checks', 'Read-only · runs Darkbloom · uses network', 'available',
     'Runs `darkbloom doctor` with no flags (never --clear-backend-guard) and keeps only pass, warning '
     'and failure counts. Check details are discarded.'),
    ('evidence', 'Health, model and connection evidence', 'Read-only', 'available',
     'Per-source evidence on the dashboard: liveness, eligibility, attestation, model residency and '
     'coordinator reachability where collected. Model names are withheld by design.'),
    ('history', 'Traffic and normalized history', 'Read-only', 'available',
     'The last 64 normalized observations held in this process, with fresh counter windows.'),
    ('export', 'Export redacted diagnostics', 'Read-only', 'available',
     'Downloads normalized observations, tool summaries and restart outcomes as JSON. No raw output, '
     'paths, model names or log text.'),
    ('details', 'Local details', 'Read-only', 'available',
     'Shows this monitor\'s configured files, executable, version and restart record location.'),
    ('restart', 'Manual provider restart', 'Changes service state', 'available-if-enabled',
     'Runs Darkbloom\'s own graceful `restart` after typed confirmation. Enabled only with --enable-restart.'),
    ('protocol', 'Coordinator protocol compatibility', 'Read-only', 'unsupported',
     'No supported evidence source exists in Darkbloom 0.10.5/0.10.6; it stays unknown.'),
    ('logs', 'Raw log export or streaming', 'Read-only', 'unsupported',
     'Deliberately not collected: raw logs can contain prompts, identifiers and keys. Only fixed '
     'error-record counts are available (--coordinator-errors).'),
    ('earnings', 'Earnings or payout verification', 'Read-only', 'unsupported',
     'Counters are not settlement evidence; there are no request windows, currency or receipts.'),
    ('stop', 'Stop or start the provider', 'Changes service state', 'proposed',
     'Proposed, not implemented. Would wrap `darkbloom stop`/`start`; needs a decision on leaving a host offline.'),
    ('force', 'Forced restart', 'Changes service state', 'proposed',
     'Proposed, not implemented, and not recommended: --force interrupts accepted requests.'),
    ('guard', 'Clear crash-loop backend guard', 'Changes service state', 'proposed',
     'Proposed, not implemented. Would run `darkbloom doctor --clear-backend-guard`, which deletes guard state.'),
    ('update', 'Update Darkbloom', 'Changes service state', 'proposed',
     'Proposed, not implemented. Changes the installed build these tools were verified against.'),
)


def inspect_executable(executable, environment):
    """Version (by running --version) and digest at startup; failures stay unknown."""
    info = {'path': executable, 'version': None, 'digest': None, 'recognised_build': False,
            'checked_at': datetime.now(timezone.utc).isoformat(), 'file': executable_file(executable)}
    try:
        info['version'] = parse_version(run_bounded((executable, '--version'), environment=environment,
                                                    cwd=environment['HOME'], timeout_seconds=5))
    except Exception:
        pass
    try:
        info['digest'] = executable_digest(executable)
    except OSError:
        pass
    info['recognised_build'] = (info['version'] in SUPPORTED_VERSIONS
                                and SUPPORTED_VERSIONS[info['version']] == info['digest'])
    return info


def e(value):
    return escape(str(value), quote=True)


def _local_time(value):
    try:
        return timestamp(value).strftime('%Y-%m-%d %H:%M:%SZ')
    except Exception:
        return 'unknown'


class OperatorTools:
    def __init__(self, monitor, *, executable, executable_info, environment, restart=None,
                 clock=lambda: datetime.now(timezone.utc).isoformat(), token=None,
                 runner=run_bounded):
        self.monitor, self.executable, self.info = monitor, executable, executable_info
        self.environment, self.restart, self.clock = environment, restart, clock
        self.token = token or secrets.token_urlsafe(32)
        self.base = '/s/' + self.token
        self._run = runner
        self._lock = threading.Lock()
        self._nonces = {}
        self._results = {}
        self._running = None

    # -- request protection --------------------------------------------------

    def token_matches(self, candidate):
        return hmac.compare_digest(candidate.encode(), self.token.encode())

    def issue(self, purpose):
        with self._lock:
            now = time.monotonic()
            for key in [k for k, (_, expiry) in self._nonces.items() if expiry < now]:
                del self._nonces[key]
            while len(self._nonces) >= MAX_NONCES:
                del self._nonces[next(iter(self._nonces))]
            nonce = secrets.token_urlsafe(24)
            self._nonces[nonce] = (purpose, now + NONCE_SECONDS)
            return nonce

    def consume(self, nonce, purpose):
        with self._lock:
            entry = self._nonces.pop(nonce, None) if type(nonce) is str else None
        return entry is not None and entry[0] == purpose and entry[1] >= time.monotonic()

    # -- tools ---------------------------------------------------------------

    def start_tool(self, tool):
        if tool not in ('refresh', 'version', 'status', 'doctor'):
            raise Refused('Unknown or unsupported tool.')
        with self._lock:
            if self._running:
                raise Refused('Another check is already running. Wait for it to finish.')
            self._running = tool
        threading.Thread(target=self._tool_thread, args=(tool,), name='gargoyl-tool', daemon=True).start()

    def _tool_thread(self, tool):
        started = self.clock()
        try:
            result = getattr(self, '_tool_' + tool)()
        except Exception:
            result = {'state': 'unknown', 'summary': 'The check failed before producing a result.'}
        with self._lock:
            self._results[tool] = dict(result, started_at=started, finished_at=self.clock())
            self._running = None

    def _tool_refresh(self):
        before = self.monitor.collections
        self.monitor.request_poll()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and self.monitor.collections == before:
            time.sleep(0.1)
        if self.monitor.collections == before:
            return {'state': 'unknown', 'summary': 'No new collection completed within 15 s.'}
        return {'state': 'observed', 'summary': f'Collection {self.monitor.collections} completed.'}

    def _command(self, *arguments, timeout):
        return self._run((self.executable, *arguments), environment=self.environment,
                         cwd=self.environment['HOME'], timeout_seconds=timeout)

    def _tool_version(self):
        result = self._command('--version', timeout=5)
        version = parse_version(result)
        try:
            digest = executable_digest(self.executable)
        except OSError:
            digest = None
        recognised = version in SUPPORTED_VERSIONS and SUPPORTED_VERSIONS[version] == digest
        if version is None:
            return {'state': 'unknown', 'summary': 'Version output was not recognised.'}
        changed = digest != self.info.get('digest')
        return {'state': 'observed', 'summary': f'Darkbloom {version}. Build '
                + ('matches a recorded release build.' if recognised else 'is not a recorded release build.')
                + (' The executable changed since this monitor started; restart the monitor to re-check.'
                   if changed else ''), 'version': version, 'recognised_build': recognised}

    def _tool_status(self):
        result = self._command('status', timeout=20)
        if result.error:
            return {'state': 'unknown', 'summary': f'Status did not complete ({result.error}).'}
        parsed = parse_observations('darkbloom_status_text_v1', result.output,
                                    observed_at=self.clock(), ttl=60)
        daemon = parsed.readings.get('daemon_state')
        if daemon is None or daemon['value'] is None:
            return {'state': 'unknown', 'summary': 'The daemon line was not in a recognised format.'}
        return {'state': 'observed', 'summary': f"Darkbloom status reports the daemon {daemon['value']}.",
                'daemon_state': daemon['value']}

    def _tool_doctor(self):
        result = self._command('doctor', timeout=45)
        if result.error:
            return {'state': 'unknown', 'summary': f'Doctor did not complete ({result.error}).'}
        summary = parse_doctor(result)
        if summary is None:
            return {'state': 'unknown', 'summary': 'Doctor output was not in the recognised 0.10.5/0.10.6 format.'}
        verdict = 'no failed checks' if summary['failed'] == 0 else f"{summary['failed']} failed"
        return {'state': 'observed', 'summary': f"{summary['passed']} passed, {summary['warnings']} "
                f"warnings, {verdict} ({summary['info']} informational).", 'counts': summary}

    def results(self):
        with self._lock:
            return dict(self._results), self._running

    # -- pages ---------------------------------------------------------------

    def nav(self, current):
        items = [(self.base + '/', 'Dashboard', current == 'dashboard'),
                 (self.base + '/tools', 'Tools', current == 'tools')]
        if self.restart is not None:
            items.append((self.base + '/restart', 'Restart', current == 'restart'))
        return items

    def _page(self, title, current, body):
        return page_start(title, extra_nav=self.nav(current)) + body + PAGE_END

    def _form(self, action, purpose, label, *, fields='', primary=False, note=''):
        return ('<form method="post" action="' + e(self.base + action) + '" class="tool-form">'
                '<input type="hidden" name="nonce" value="' + e(self.issue(purpose)) + '">' + fields
                + '<button type="submit" class="btn' + (' btn-primary' if primary else '') + '">'
                + e(label) + '</button>' + note + '</form>')

    def operator_section(self, *, private):
        if not private:
            return ('<section aria-labelledby="operator-title"><h2 id="operator-title">Operator tools</h2>'
                    '<p>Operator tools are enabled for this monitor. Open the private link printed in the '
                    'monitor\'s terminal. This public page never shows it and offers no actions.</p></section>')
        restart = ('<a href="' + e(self.base + '/restart') + '">Manual restart</a> is enabled.'
                   if self.restart is not None else 'Manual restart is not enabled (--enable-restart).')
        return ('<section aria-labelledby="operator-title"><h2 id="operator-title">Operator tools</h2>'
                '<p>Read-only checks, export and local details are on the <a href="' + e(self.base + '/tools')
                + '">Tools page</a>. ' + restart + ' Nothing here repairs automatically.</p></section>')

    def tools_page(self, now):
        results, running = self.results()
        rows = []
        for tool, name, kind, status, description in INVENTORY:
            if status == 'available-if-enabled':
                status = 'available' if self.restart is not None else 'not enabled'
            badge = {'available': 'st-observed', 'unsupported': 'st-unknown',
                     'proposed': 'st-info', 'not enabled': 'st-unknown'}[status]
            action = ''
            if tool in ('refresh', 'version', 'status', 'doctor'):
                action = ('<span class="st st-info">running…</span>' if running == tool else
                          self._form('/tools/run', 'tool', 'Run', fields='<input type="hidden" name="tool" value="'
                                     + tool + '">'))
            elif tool == 'export':
                action = '<a class="btn" href="' + e(self.base + '/export.json') + '" download>Download JSON</a>'
            elif tool in ('evidence', 'history'):
                action = '<a class="btn" href="' + e(self.base + ('/#fleet-overview' if tool == 'evidence'
                                                                    else '/#traffic-history')) + '">Open</a>'
            elif tool == 'details':
                action = '<a class="btn" href="#local-details">Show</a>'
            elif tool == 'restart' and self.restart is not None:
                action = '<a class="btn" href="' + e(self.base + '/restart') + '">Review restart</a>'
            result = results.get(tool)
            outcome = ''
            if result:
                outcome = ('<p class="tool-result"><span class="ev ev-' + e(result['state']) + '">'
                           + e(result['state']) + '</span> ' + e(result['summary']) + ' <small>Finished '
                           + e(_local_time(result['finished_at'])) + '</small></p>')
            rows.append('<tr><th scope="row">' + e(name) + '<p class="muted">' + e(description) + '</p>' + outcome
                        + '</th><td>' + e(kind) + '</td><td><span class="st ' + badge + '">' + e(status)
                        + '</span></td><td>' + action + '</td></tr>')
        info = self.info
        details = (
            '<section id="local-details" aria-labelledby="details-title"><h2 id="details-title">Local details</h2>'
            '<dl class="facts">'
            '<div><dt>Host ID</dt><dd class="mono">' + e(self.monitor.identity) + '</dd></div>'
            '<div><dt>State file</dt><dd class="mono">' + e(self.monitor.source) + '</dd></div>'
            '<div><dt>Darkbloom executable</dt><dd class="mono">' + e(self.executable) + '</dd></div>'
            '<div><dt>Version at monitor start</dt><dd>' + e(info.get('version') or 'unknown') + ' · '
            + ('recorded release build' if info.get('recognised_build') else 'not a recorded release build')
            + '</dd></div>'
            '<div><dt>Executable SHA-256</dt><dd class="mono">' + e(info.get('digest') or 'unknown') + '</dd></div>'
            '<div><dt>Restart record</dt><dd class="mono">'
            + e(self.restart.store.directory if self.restart is not None else 'restart not enabled') + '</dd></div>'
            '</dl><p>Darkbloom logs: run <code>darkbloom logs</code> in a terminal. Gargoyl does not read or '
            'export raw logs.</p></section>')
        refresh = '<meta http-equiv="refresh" content="2">' if running else ''
        body = (refresh + '<h1>Operator tools</h1><p>Read-only checks are separate from the one action that '
                'changes service state. Checks that run Darkbloom use fixed arguments and keep only '
                'normalized results. Unsupported tools say what is missing; proposed tools are not built.</p>'
                '<div class="table-wrap" tabindex="0" role="region" aria-label="Operator tools table"><table>'
                '<thead><tr><th scope="col">Tool</th><th scope="col">Effect</th><th scope="col">Status</th>'
                '<th scope="col">Action</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>' + details)
        return self._page('Operator tools · Gargoyl', 'tools', body)

    def export(self, now):
        results, _ = self.results()
        record = self.restart.snapshot() if self.restart is not None else None
        payload = {
            'schema': 1, 'generated_at': now, 'host': self.monitor.identity,
            'redaction': 'Normalized fields only: no raw command output, paths, model names, logs or keys.',
            'executable': {'version': self.info.get('version'), 'recognised_build': self.info.get('recognised_build')},
            'collections': self.monitor.collections,
            'observations': self.monitor.history(),
            'tools': {name: {k: v for k, v in result.items() if k in
                             ('state', 'summary', 'started_at', 'finished_at', 'version', 'daemon_state', 'counts')}
                      for name, result in results.items()},
            'restart': None if record is None else {
                'current': _public_attempt(record.get('current')),
                'history': [_public_attempt(item) for item in record.get('history', [])],
            },
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    # -- restart pages -------------------------------------------------------

    def restart_page(self, now, *, message=None):
        restart = self.restart
        current = restart.snapshot().get('current')
        opened, reason = restart.gate()
        notice = ('<div class="callout danger" role="alert"><p>' + e(message) + '</p></div>') if message else ''
        status_link = ('<p><a href="' + e(self.base + '/restart/status') + '">View the last restart and its outcome</a>.</p>'
                       if current else '')
        if not opened:
            return self._page('Restart · Gargoyl', 'restart', '<h1>Manual provider restart</h1>' + notice
                              + '<div class="callout warn"><p>' + e(reason) + '</p></div>' + status_link)
        target, problem = restart.target(now)
        if target is None:
            return self._page('Restart · Gargoyl', 'restart', '<h1>Manual provider restart</h1>' + notice
                              + '<div class="callout warn"><p>Restart is unavailable: ' + e(problem)
                              + '</p></div>' + status_link)
        prefix = self.monitor.identity[:8]
        born = datetime.fromtimestamp(target['born_us'] / 1e6, timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
        kernel = {True: 'confirmed by the kernel', False: 'not confirmed', None: 'kernel check unavailable on this platform'}[target['kernel_verified']]
        command = 'darkbloom ' + ' '.join(RESTART_ARGUMENTS)
        body = (
            '<h1>Manual provider restart</h1>' + notice
            + '<p>This runs Darkbloom\'s own graceful restart once, after you confirm. It is not an automatic '
            'repair and it is never retried.</p>'
            '<section aria-labelledby="target-title"><h2 id="target-title">Target</h2><dl class="facts">'
            '<div><dt>Host</dt><dd class="mono">' + e(self.monitor.identity) + '</dd></div>'
            '<div><dt>Provider process</dt><dd>PID ' + e(target['pid']) + ', started ' + e(born)
            + ' · ' + e(kernel) + '</dd></div>'
            '<div><dt>Darkbloom</dt><dd>' + e(target['version']) + ' · trust status '
            + e(target['trust_status'] or 'unknown') + '</dd></div>'
            '<div><dt>Command</dt><dd class="mono">' + e(command) + '</dd></div>'
            '</dl></section>'
            '<section aria-labelledby="impact-title"><h2 id="impact-title">Expected interruption</h2><ul>'
            '<li>New work is refused as soon as the drain starts.</li>'
            f'<li>Accepted requests may finish, for up to {RESTART_DRAIN_TIMEOUT // 60} minutes, and the coordinator must acknowledge usage.</li>'
            '<li>The provider then stops and relaunches with its existing configuration and model. It does '
            f'not serve until it is freshly authorized, for up to {RESTART_STARTUP_TIMEOUT // 60} minutes.</li>'
            '<li>If the drain does not finish in time, nothing is restarted, but Darkbloom leaves the provider '
            'draining with automatic restart disabled. That needs your attention afterwards.</li>'
            '<li>Darkbloom never forces: Gargoyl does not pass --force.</li></ul></section>'
            '<section aria-labelledby="guarantee-title"><h2 id="guarantee-title">What is and isn\'t guaranteed</h2><ul>'
            '<li>Gargoyl records the attempt durably before running anything and allows one attempt at a time.</li>'
            '<li>Duplicate or double-clicked submissions are rejected.</li>'
            '<li>If the outcome is uncertain, for example because the monitor stopped mid-restart, restart stays '
            'blocked until you reconcile. Gargoyl never retries.</li>'
            '<li>Not guaranteed: exactly-once execution across crashes. Darkbloom keeps no durable ledger of '
            'restart requests, and a crash at the wrong moment leaves the outcome unknown.</li></ul></section>'
            '<section aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm</h2>'
            '<form method="post" action="' + e(self.base + '/restart') + '" class="confirm">'
            '<input type="hidden" name="nonce" value="' + e(self.issue('restart')) + '">'
            '<input type="hidden" name="target" value="' + e(target['token']) + '">'
            '<label for="confirm-host">Type <code>' + e(prefix) + '</code>, the start of the host ID, to confirm</label>'
            '<div class="row"><input class="input" id="confirm-host" name="confirm" autocomplete="off" '
            'spellcheck="false" required maxlength="8" pattern="' + e(prefix) + '">'
            '<button type="submit" class="btn btn-primary">Restart provider on ' + e(prefix) + '…</button></div>'
            '<p class="muted">This page does not refresh. If the provider process changes before you submit, '
            'the restart is refused and you can review the new target.</p></form></section>' + status_link)
        return self._page('Restart · Gargoyl', 'restart', body)

    def restart_status_page(self, now, *, message=None):
        record = self.restart.snapshot()
        current = record.get('current')
        notice = ('<div class="callout danger" role="alert"><p>' + e(message) + '</p></div>') if message else ''
        if not current:
            return self._page('Restart status · Gargoyl', 'restart', '<h1>Restart status</h1>' + notice
                              + '<p>No restart has been attempted from this monitor\'s record.</p>')
        running = current['phase'] in ('claimed', 'running')
        refresh = '<meta http-equiv="refresh" content="2">' if running else ''
        phase = PHASE_TEXT.get(current.get('last_progress') or 'starting', 'In progress')
        if running and current.get('remaining') and current.get('last_progress') == 'draining':
            phase += f" {current['remaining']} accepted request(s) remaining."
        if running:
            badge, headline = 'st-info', 'In progress'
        elif current['phase'] == 'reconciled':
            badge, headline = 'st-unknown', 'Reconciled'
        elif current.get('verified'):
            badge, headline = 'st-observed', 'Verified restart'
        else:
            badge, headline = 'st-failed', 'Unresolved'
        facts = (
            '<dl class="facts">'
            '<div><dt>Attempt</dt><dd class="mono">' + e(current['attempt_id'][:12]) + '</dd></div>'
            '<div><dt>Claimed</dt><dd>' + e(_local_time(current.get('claimed_at'))) + '</dd></div>'
            '<div><dt>Target process</dt><dd>PID ' + e(current['target']['pid']) + '</dd></div>'
            '<div><dt>Finished</dt><dd>' + e(_local_time(current.get('finished_at')) if current.get('finished_at') else '—') + '</dd></div>'
            '</dl>')
        body = refresh + '<h1>Restart status</h1>' + notice + '<p><span class="st ' + badge + '">' + e(headline) + '</span></p>' + facts
        if running:
            body += ('<section aria-labelledby="progress-title"><h2 id="progress-title">Progress</h2><p>' + e(phase)
                     + '</p><p class="muted">This page refreshes every 2 seconds. Stopping the monitor does not stop '
                     'the restart; it continues and is reported as unknown until reconciled.</p></section>')
        else:
            outcome = current.get('outcome') or 'unknown'
            body += ('<section aria-labelledby="outcome-title"><h2 id="outcome-title">Outcome</h2><p>'
                     + e(OUTCOME_TEXT.get(outcome, OUTCOME_TEXT['unknown'])) + '</p><p>'
                     + e(current.get('verification') or '') + '</p>'
                     + (f"<p>Exit status {e(current['exit_code'])}.</p>" if current.get('exit_code') is not None else
                        '<p>Exit status not observed.</p>')
                     + ('<p class="muted">' + e(current['unrecognised_lines']) + ' output line(s) were not recognised '
                        'and were discarded.</p>' if current.get('unrecognised_lines') else '') + '</section>')
            if current['phase'] == 'reconciled':
                body += '<p>' + e(current.get('reconciliation', '')) + '</p>'
            elif not current.get('verified'):
                body += ('<section aria-labelledby="reconcile-title"><h2 id="reconcile-title">Reconcile</h2>'
                         '<p>Restart stays blocked until you reconcile. Reconciling only reads the current provider '
                         'state and records it; it never restarts anything. Check the dashboard first, and if the '
                         'provider is still draining with automatic restart disabled, resolve that in Darkbloom.</p>'
                         + self._form('/restart/reconcile', 'reconcile', 'Reconcile and record current state')
                         + '</section>')
        history = record.get('history', [])
        if history:
            body += ('<details><summary>Earlier attempts (' + str(len(history)) + ')</summary><div class="table-wrap" '
                     'tabindex="0" role="region" aria-label="Earlier restart attempts"><table><thead><tr>'
                     '<th scope="col">Claimed</th><th scope="col">Outcome</th><th scope="col">Verified</th>'
                     '<th scope="col">Reconciled</th></tr></thead><tbody>'
                     + ''.join('<tr><td>' + e(_local_time(item.get('claimed_at'))) + '</td><td>'
                               + e(item.get('outcome') or 'unknown') + '</td><td>' + ('yes' if item.get('verified') else 'no')
                               + '</td><td>' + e(_local_time(item['reconciled_at']) if item.get('reconciled_at') else '—')
                               + '</td></tr>' for item in history) + '</tbody></table></div></details>')
        return self._page('Restart status · Gargoyl', 'restart', body)


PHASE_TEXT = {
    'starting': 'Starting: Darkbloom is confirming the provider and publishing the drain request.',
    'draining': 'Draining: new work is refused while accepted requests finish.',
    'awaiting_ack': 'Requests finished; waiting for the coordinator to acknowledge usage.',
    'drained': 'Drained; stopping the provider.',
    'awaiting_authorization': 'Relaunched; waiting for fresh authorization (up to 3 minutes).',
    'authorized': 'Freshly authorized; verifying independently.',
}


def _public_attempt(item):
    if not item:
        return None
    keys = ('attempt_id', 'phase', 'claimed_at', 'finished_at', 'outcome', 'verified', 'verification',
            'reconciled_at', 'reconciliation', 'note', 'exit_code')
    return {key: item.get(key) for key in keys if key in item}


class OperatorHandler(_Handler):
    """Public GET / unchanged; private routes under /s/<token>/; POST only there."""
    csp = CSP
    # Browsers send `Origin: null` on POST under no-referrer, which would defeat the
    # exact-Origin check. same-origin still sends nothing to other origins (and these
    # pages load no external resources or links), so the private path never leaks.
    referrer_policy = 'same-origin'

    def _authority(self):
        return f'127.0.0.1:{self.server.server_port}'

    def _guard(self, *, require_origin):
        if self.headers.get_all('Host') != [self._authority()]:
            return False
        origins = self.headers.get_all('Origin')
        if origins is None:
            return not require_origin
        if origins != ['http://' + self._authority()]:
            return False
        site = self.headers.get_all('Sec-Fetch-Site')
        return site is None or site == ['same-origin']

    def _private_path(self):
        """Return the route after a valid /s/<token> prefix, or None."""
        tools = self.server.tools
        path = self.path.split('?', 1)[0]
        if not path.startswith('/s/'):
            return None
        token, _, rest = path[3:].partition('/')
        if not tools.token_matches(token):
            return None
        return '/' + rest

    def _page(self, status, body, *, refresh=False):
        if refresh:
            body = body.replace('<title>', f'<meta http-equiv="refresh" content="{self.server.refresh_seconds}"><title>', 1)
        self._respond(status, body)

    def _redirect(self, location):
        self.send_response(303)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', self.referrer_policy)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        if self.path == '/' or not self.path.startswith('/s/'):
            return super().do_GET()
        if not self._guard(require_origin=False):
            self.send_error(403)
            return
        route = self._private_path()
        if route is None:
            self.send_error(404)
            return
        self.connection.settimeout(5)
        tools = self.server.tools
        try:
            now = self.server.clock()
            timestamp(now)
            if route == '/':
                page = self.server.reader.render_page(now, operator_section=tools.operator_section(private=True),
                                                      extra_nav=tools.nav('dashboard'))
                self._page(200, page, refresh=True)
            elif route == '/tools':
                self._page(200, tools.tools_page(now))
            elif route == '/export.json':
                self._respond(200, tools.export(now), content_type='application/json; charset=utf-8',
                              headers=(('Content-Disposition', 'attachment; filename="gargoyl-diagnostics.json"'),))
            elif route == '/restart' and tools.restart is not None:
                self._page(200, tools.restart_page(now))
            elif route == '/restart/status' and tools.restart is not None:
                self._page(200, tools.restart_status_page(now))
            else:
                self.send_error(404)
        except Exception:
            self._respond(503, page_start('Unavailable') + '<h1>Unavailable</h1><p>Evaluation failed. '
                          'State is unknown. No action was taken.</p>' + PAGE_END)

    do_HEAD = do_GET

    def do_POST(self):
        if not self._guard(require_origin=True):
            self.send_error(403)
            return
        route = self._private_path()
        if route is None:
            self.send_error(404)
            return
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/x-www-form-urlencoded':
            self.send_error(415)
            return
        try:
            length = int(self.headers.get('Content-Length', ''))
        except ValueError:
            self.send_error(411)
            return
        if not 0 < length <= MAX_BODY:
            self.send_error(413)
            return
        try:
            form = urllib.parse.parse_qs(self.rfile.read(length).decode('ascii'), strict_parsing=True,
                                         max_num_fields=8)
        except (ValueError, UnicodeDecodeError):
            self.send_error(400)
            return
        if any(len(values) != 1 for values in form.values()):
            self.send_error(400)
            return
        form = {key: values[0] for key, values in form.items()}
        self.connection.settimeout(5)
        tools = self.server.tools
        base = tools.base
        now = self.server.clock()
        if route == '/tools/run':
            if not tools.consume(form.get('nonce'), 'tool'):
                return self._redirect(base + '/tools')
            try:
                tools.start_tool(form.get('tool'))
            except Refused:
                pass
            return self._redirect(base + '/tools')
        if tools.restart is None:
            self.send_error(404)
            return
        if route == '/restart':
            if not tools.consume(form.get('nonce'), 'restart'):
                # Stale, replayed or double-clicked submission: show status, never a second attempt.
                return self._redirect(base + '/restart/status')
            if form.get('confirm') != self.server.reader.identity[:8]:
                return self._page(200, tools.restart_page(now, message='The confirmation text did not match. '
                                                           'Nothing was run.'))
            try:
                tools.restart.start(now=now, confirmed_token=form.get('target', ''))
            except Refused as refused:
                return self._page(200, tools.restart_page(now, message=str(refused) + ' Nothing was run.'))
            return self._redirect(base + '/restart/status')
        if route == '/restart/reconcile':
            if not tools.consume(form.get('nonce'), 'reconcile'):
                return self._redirect(base + '/restart/status')
            try:
                tools.restart.reconcile(now=now)
            except Refused as refused:
                return self._page(200, tools.restart_status_page(now, message=str(refused)))
            return self._redirect(base + '/restart/status')
        self.send_error(404)
