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
import os
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
    classify_restart,
    executable_digest,
    executable_file,
    parse_doctor,
    parse_version,
    progress,
    restart_events,
    run_bounded,
)
from gargoyl.dashboard.runtime import _Handler
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.manual_restart import (
    ManualJournal,
    executable_stamp,
    installation_preflight,
    invoke_restart,
    observed_target,
    owner_home,
    process_alive,
    read_operation,
    reconcile_operation,
    run_restart,
)
from gargoyl.telemetry import timestamp


class Refused(Exception):
    """A request was refused; the message is safe to show."""


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
     'Runs `darkbloom doctor` with no flags (never `--clear-backend-guard`). Shows counts and the names of '
     'failed or warning checks; their details are discarded.'),
    ('evidence', 'Health, model and connection evidence', 'Read-only', 'available',
     'Per-source evidence on the dashboard: liveness, eligibility, attestation, model residency and '
     'coordinator reachability where collected. Model names are withheld by design.'),
    ('history', 'Traffic and normalized history', 'Read-only', 'available',
     'The last 64 normalized observations held in this process, with fresh counter windows.'),
    ('export', 'Export redacted diagnostics', 'Read-only', 'available',
     'The monitor\'s /report.json: bounded normalized history, dashboard projection and redacted log '
     'metadata. No raw output, model names, credentials or executable paths.'),
    ('details', 'Local details', 'Read-only', 'available',
     'Shows this monitor\'s configured files, executable, version and restart record location.'),
    ('restart', 'Manual provider restart', 'Changes service state', 'available-if-enabled',
     'Runs Darkbloom\'s own graceful `restart` once after typed confirmation. Enabled only with '
     '--enable-restart. Shares one journal, lock and gate with `gargoyl tools restart`.'),
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


def _with_code(text):
    """Escape, then render `backticked` spans as <code>."""
    parts = escape(text).split('`')
    return ''.join(('<code>' + part + '</code>') if index % 2 else part for index, part in enumerate(parts))


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
        # One bounded pool per form purpose, so auto-refreshing tool forms can't
        # evict an open restart or reconcile form.
        with self._lock:
            now = time.monotonic()
            pool = self._nonces.setdefault(purpose, {})
            for key in [k for k, expiry in pool.items() if expiry < now]:
                del pool[key]
            while len(pool) >= MAX_NONCES:
                del pool[next(iter(pool))]
            nonce = secrets.token_urlsafe(24)
            pool[nonce] = now + NONCE_SECONDS
            return nonce

    def consume(self, nonce, purpose):
        with self._lock:
            pool = self._nonces.get(purpose, {})
            expiry = pool.pop(nonce, None) if type(nonce) is str else None
        return expiry is not None and expiry >= time.monotonic()

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
        text = (f"{summary['passed']} passed, {summary['warnings']} warnings, {verdict} "
                f"({summary['info']} informational).")
        if summary['failed_checks']:
            text += ' Failed: ' + ', '.join(summary['failed_checks']) + '.'
        if summary['warning_checks']:
            text += ' Warnings: ' + ', '.join(summary['warning_checks']) + '.'
        return {'state': 'observed', 'summary': text, 'counts': summary}

    def results(self):
        with self._lock:
            return dict(self._results), self._running

    # -- pages ---------------------------------------------------------------

    def nav(self, current):
        items = [(self.base + '/', 'Dashboard', current == 'dashboard')]
        if current != 'dashboard':  # the dashboard adds its own in-page host links
            items += [(self.base + '/#fleet-overview', 'Hosts', False),
                      (self.base + '/#needs-attention', 'Needs attention', False)]
        items.append((self.base + '/tools', 'Tools', current == 'tools'))
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
        available, unavailable = [], []
        for tool, name, kind, status, description in INVENTORY:
            if status == 'available-if-enabled':
                status = 'available' if self.restart is not None else 'not enabled'
            text = _with_code(description)
            if status != 'available':
                unavailable.append('<li class="tool"><div class="tool-main"><h3>' + e(name) + '</h3><p>' + text
                                   + '</p></div><span class="st ' + ('st-info' if status == 'proposed' else 'st-unknown')
                                   + '">' + e(status) + '</span></li>')
                continue
            action = ''
            if tool in ('refresh', 'version', 'status', 'doctor'):
                action = ('<span class="st st-info">running…</span>' if running == tool else
                          self._form('/tools/run', 'tool', 'Run', fields='<input type="hidden" name="tool" value="'
                                     + tool + '">'))
            elif tool == 'export':
                action = '<a class="btn" href="/report.json" download="gargoyl-report.json">Download JSON</a>'
            elif tool in ('evidence', 'history'):
                action = '<a class="btn" href="' + e(self.base + ('/#fleet-overview' if tool == 'evidence'
                                                                    else '/#traffic-history')) + '">Open</a>'
            elif tool == 'details':
                action = '<a class="btn" href="#local-details">Show</a>'
            elif tool == 'restart':
                action = '<a class="btn btn-danger" href="' + e(self.base + '/restart') + '">Review restart</a>'
            result = results.get(tool)
            outcome = ''
            if result:
                outcome = ('<p class="tool-result"><span class="ev ev-' + e(result['state']) + '">'
                           + e(result['state']) + '</span> ' + e(result['summary']) + ' <small>Finished '
                           + e(_local_time(result['finished_at'])) + '</small></p>')
            effect = 'st-warning' if kind == 'Changes service state' else 'st-info'
            available.append('<li class="tool"><div class="tool-main"><h3>' + e(name) + '</h3><p>' + text + '</p>'
                             '<p class="tool-effect"><span class="st ' + effect + '">' + e(kind) + '</span></p>'
                             + outcome + '</div><div class="tool-action">' + action + '</div></li>')
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
            + e(self.restart.directory if self.restart is not None else 'restart not enabled in the console') + '</dd></div>'
            '</dl><p>Darkbloom logs: run <code>darkbloom logs</code> in a terminal. Gargoyl does not read or '
            'export raw logs. Terminal equivalents: <code>gargoyl tools inspect</code>, '
            '<code>gargoyl tools restart</code>, <code>gargoyl tools reconcile</code>.</p></section>')
        refresh = '<meta http-equiv="refresh" content="2">' if running else ''
        body = (refresh + '<h1>Operator tools</h1><p>Each tool says whether it only reads or changes service '
                'state. Checks that run Darkbloom use fixed arguments and keep only normalized results.</p>'
                '<section aria-labelledby="tools-title"><h2 id="tools-title" class="sr-only">Available tools</h2>'
                '<ul class="tool-list">' + ''.join(available) + '</ul></section>'
                '<details class="unavailable-tools"><summary>Not available yet (' + str(len(unavailable)) + ')</summary>'
                '<ul class="tool-list">' + ''.join(unavailable) + '</ul></details>' + details)
        return self._page('Operator tools · Gargoyl', 'tools', body)

    # -- restart pages -------------------------------------------------------

    def _notice(self, message):
        return ('<div class="callout danger" role="alert"><p>' + e(message) + '</p></div>') if message else ''

    def restart_page(self, now, *, message=None):
        restart = self.restart
        record = restart.record()
        opened, reason = restart.gate(record)
        status_link = ('<p><a href="' + e(self.base + '/restart/status') + '">View the last manual restart and its '
                       'outcome</a>.</p>' if record else '')
        head = '<h1>Manual provider restart</h1>' + self._notice(message)
        if not opened:
            return self._page('Restart · Gargoyl', 'restart', head + '<div class="callout warn"><p>' + e(reason)
                              + '</p></div>' + status_link)
        target, problem = restart.target()
        if target is None:
            return self._page('Restart · Gargoyl', 'restart', head + '<div class="callout warn"><p>Restart is '
                              'unavailable: ' + e(problem) + '</p></div>' + status_link)
        prefix = self.monitor.identity[:8]
        born = datetime.fromtimestamp(target['born_us'] / 1e6, timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
        command = 'darkbloom ' + ' '.join(RESTART_ARGUMENTS)
        body = (
            head + '<p>This runs Darkbloom\'s own graceful restart once, after you confirm. It is not an automatic '
            'repair and it is never retried. The terminal command <code>gargoyl tools restart</code> uses the '
            'same record and gate, so only one restart can be in progress from either place.</p>'
            '<section aria-labelledby="target-title"><h2 id="target-title">Target</h2><dl class="facts">'
            '<div><dt>Host</dt><dd class="mono">' + e(self.monitor.identity) + '</dd></div>'
            '<div><dt>Provider process</dt><dd>PID ' + e(target['pid']) + ', started ' + e(born)
            + ' · confirmed by the kernel</dd></div>'
            '<div><dt>Darkbloom</dt><dd>' + e(target['version']) + ' · launchd provider and watchdog running</dd></div>'
            '<div class="wide"><dt>Executable</dt><dd class="mono">' + e(self.executable) + '</dd></div>'
            '<div class="wide"><dt>Command</dt><dd class="mono nowrap-words">' + e(command) + '</dd></div>'
            '</dl></section>'
            '<section aria-labelledby="impact-title"><h2 id="impact-title">Expected interruption</h2><ul>'
            '<li>New work is refused as soon as the drain starts.</li>'
            f'<li>Accepted requests may finish, for up to {RESTART_DRAIN_TIMEOUT // 60} minutes, and the coordinator must acknowledge usage.</li>'
            '<li>Darkbloom temporarily disables startup and its watchdog, then stops the provider and relaunches it '
            'with its existing configuration and model. It does not serve until freshly authorized, for up to '
            f'{RESTART_STARTUP_TIMEOUT // 60} minutes, and then restores configured recovery.</li>'
            '<li>If the drain or startup times out, nothing more is done: the provider can be left draining or '
            'with automatic restart disabled, which needs your attention.</li>'
            '<li>Gargoyl never passes --force. It waits up to 14 minutes; past that it stops only its own command '
            '(not the provider), and the outcome is unknown.</li></ul></section>'
            '<p class="guarantee"><strong>Runs once, never retried.</strong> If anything is uncertain, restart '
            'stays blocked until you reconcile.</p>'
            '<details class="fine-print"><summary>What is and isn\'t guaranteed</summary><ul>'
            '<li>The attempt is recorded durably before Darkbloom runs. One attempt at a time, shared with the '
            'terminal command and the Mac app.</li>'
            '<li>Duplicate or double-clicked submissions are rejected.</li>'
            '<li>Darkbloom restarts the provider that is current when it runs; Gargoyl re-checks the target just '
            'before invoking, but the two checks aren\'t atomic.</li>'
            '<li>Not exactly-once across crashes: Darkbloom keeps no durable ledger of restart requests.</li>'
            '</ul></details>'
            '<section aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm</h2>'
            '<form method="post" action="' + e(self.base + '/restart') + '" class="confirm">'
            '<input type="hidden" name="nonce" value="' + e(self.issue('restart')) + '">'
            '<input type="hidden" name="target" value="' + e(target['token']) + '">'
            '<label for="confirm-host">Type <code>' + e(prefix) + '</code>, the start of the host ID, to confirm</label>'
            '<div class="row"><input class="input" id="confirm-host" name="confirm" autocomplete="off" '
            'spellcheck="false" autocapitalize="none" autocorrect="off" required maxlength="8" pattern="'
            + e(prefix) + '" title="Type the 8 characters shown">'
            '<button type="submit" class="btn btn-danger">Restart provider</button></div>'
            '<p class="muted">This page does not refresh. If the provider process changes before you submit, '
            'the restart is refused and you can review the new target.</p></form></section>' + status_link)
        return self._page('Restart · Gargoyl', 'restart', body)

    def restart_status_page(self, now, *, message=None, note=None):
        restart = self.restart
        record = restart.record()
        live = restart.live(record)
        head = ('<h1>Restart status</h1>' + self._notice(message)
                + ('<div class="callout" role="status"><p>' + e(note) + '</p></div>' if note else ''))
        if record is None and not live['active']:
            failure = ('<p>' + e(live['failure']) + '</p>') if live['failure'] else ''
            return self._page('Restart status · Gargoyl', 'restart', head + failure
                              + '<p>No manual restart is recorded.</p>')
        state = record['state'] if record else 'intent'
        running = live['active']
        refresh = '<meta http-equiv="refresh" content="2">' if running else ''
        if running:
            badge, headline = 'st-info', 'In progress'
        elif state == 'completed':
            badge, headline = 'st-observed', 'Verified restart'
        elif state == 'reconciled':
            badge, headline = 'st-unknown', 'Reconciled'
        elif live['outcome'] in ('not_restarted_attention', 'forced_anomaly'):
            badge, headline = 'st-failed', 'Unresolved'
        else:
            badge, headline = 'st-warning', 'Unresolved'
        facts = '<dl class="facts">'
        if record:
            facts += ('<div><dt>Operation</dt><dd class="mono">' + e(record['operation_id'][:12]) + '</dd></div>'
                      '<div><dt>Started</dt><dd>' + e(_local_time(record['started_at'])) + '</dd></div>'
                      '<div><dt>Target process</dt><dd>PID ' + e(record['target']['process']['pid']) + '</dd></div>'
                      + ('<div><dt>Replacement process</dt><dd>PID ' + e(record['replacement']['process']['pid'])
                         + '</dd></div>' if record.get('replacement') else '')
                      + ('<div><dt>Finished</dt><dd>' + e(_local_time(record['finished_at'])) + '</dd></div>'
                         if record.get('finished_at') else '')
                      + ('<div><dt>Reconciled</dt><dd>' + e(_local_time(record['reconciled_at'])) + '</dd></div>'
                         if record.get('reconciled_at') else ''))
        facts += '</dl>'
        body = refresh + head + '<p><span class="st ' + badge + '">' + e(headline) + '</span></p>' + facts
        if running:
            phase, remaining = live['phase']
            elapsed = int(live['elapsed'] or 0)
            text = (f'{elapsed // 60}:{elapsed % 60:02d} elapsed of 14:00 at most. '
                    + (PHASE_TEXT[phase] if phase != 'starting' else
                       'Darkbloom has not reported a phase yet.'))
            if phase == 'draining' and remaining:
                text += f" {remaining} accepted request{'s' if remaining != 1 else ''} remaining."
            body += ('<section aria-labelledby="progress-title"><h2 id="progress-title">Progress</h2><p role="status">' + e(text)
                     + '</p><p class="muted">Phases come from Darkbloom\'s own messages, which it may only write out '
                     'when the command finishes, so detailed phases can lag. The elapsed time is always current.</p>'
                     '<p class="muted">This page refreshes every 2 seconds. Stopping the monitor does not stop the '
                     'restart; it is then reported as unknown until reconciled.</p></section>')
        else:
            body += '<section aria-labelledby="outcome-title"><h2 id="outcome-title">Outcome</h2>'
            if state == 'completed':
                body += ('<p>Darkbloom reported success, and fresh provider state names a different process (PID '
                         + e(record['replacement']['process']['pid']) + ') confirmed by the kernel, on the same '
                         'version (' + e(record['replacement'].get('version') or record['target'].get('version') or 'unknown')
                         + '). Protocol health and earnings are not independently proven. Check the <a href="'
                         + e(self.base + '/#fleet-overview') + '">dashboard evidence</a> for fresh authorization. '
                         'Manual restart is available again.</p>')
            elif state == 'reconciled':
                detail = OUTCOME_TEXT.get(live['outcome']) if live['outcome'] else None
                body += (('<p>Attempt outcome: ' + e(detail) + '</p>' if detail else '')
                         + '<p>' + e(OBSERVATION_TEXT[record['observation']]) + ' This records the present state; '
                         'it does not prove what happened during the attempt.</p>')
                if record['observation'] != 'different_process_observed':
                    body += ('<div class="callout warn"><p>Check the <a href="' + e(self.base + '/#fleet-overview')
                             + '">dashboard</a> before restarting: the provider may still be draining with '
                             'automatic restart disabled.</p></div>')
                body += ('<p><a href="' + e(self.base + '/restart') + '">Manual restart</a> is available again.</p>')
            else:
                detail = OUTCOME_TEXT.get(live['outcome']) if live['outcome'] else None
                body += ('<p>' + e(detail or 'The outcome is unknown: it was not verified, or the restart was '
                         'started by another session (the CLI or an earlier monitor) that didn\'t record a result.')
                         + '</p>' + (f"<p>Darkbloom exited with status {e(live['exit_code'])}"
                            + (' (non-zero: not verified).' if live['exit_code'] else '.') + '</p>'
                            if live['exit_code'] is not None else ''))
            body += '</section>'
            if state in ('intent', 'unknown'):
                body += ('<section aria-labelledby="next-title"><h2 id="next-title">What to do next</h2><ol>'
                         '<li>Check the provider: <a href="' + e(self.base + '/#fleet-overview') + '">dashboard '
                         'evidence</a>, or run <a href="' + e(self.base + '/tools') + '">Daemon status</a> on the Tools page.</li>'
                         + self._next_steps(live['outcome']) + '</ol></section>'
                         '<section aria-labelledby="reconcile-title"><h2 id="reconcile-title">Reconcile</h2>'
                         '<p>Restart stays blocked until you reconcile. Reconciling only reads the current provider '
                         'state and records it; it never restarts anything, and it is refused while the restart '
                         'command is still running.</p>'
                         + '<form method="post" action="' + e(self.base + '/restart/reconcile') + '" class="confirm">'
                         '<input type="hidden" name="nonce" value="' + e(self.issue('reconcile')) + '">'
                         '<label for="reconcile-host">Type <code>' + e(self.monitor.identity[:8]) + '</code> to confirm</label>'
                         '<div class="row"><input class="input" id="reconcile-host" name="confirm" autocomplete="off" '
                         'spellcheck="false" autocapitalize="none" autocorrect="off" required maxlength="8" pattern="'
                         + e(self.monitor.identity[:8]) + '" title="Type the 8 characters shown">'
                         '<button type="submit" class="btn">Reconcile and record current state</button></div></form>'
                         + '</section>')
        return self._page('Restart status · Gargoyl', 'restart', body)

    @staticmethod
    def _next_steps(outcome):
        steps = ''
        if outcome in ('not_restarted_attention', 'unknown', None):
            steps += ('<li>' + ('Darkbloom' if outcome == 'not_restarted_attention' else 'If the drain began, Darkbloom')
                      + ' may have left the provider draining with automatic restart disabled. Restarting again '
                      '(after reconciling) waits for the drain again. <code>darkbloom restart --force</code> in a '
                      'terminal would interrupt the remaining requests; Gargoyl never does that.</li>')
        if outcome in ('relaunched_unconfirmed', 'unknown', None):
            steps += ('<li>' + ('The provider was relaunched but not confirmed' if outcome == 'relaunched_unconfirmed'
                                else 'If the provider was relaunched but not confirmed')
                      + ': it may still be starting. Give it a few minutes and check again before reconciling.</li>')
        if outcome == 'refused_no_change':
            steps += '<li>Darkbloom changed nothing. Fix what it refused on, then reconcile and try again.</li>'
        if outcome == 'forced_anomaly':
            steps += ('<li>Darkbloom reported a forced lifecycle, which Gargoyl never requests. Check the provider '
                      'and Darkbloom logs (<code>darkbloom logs</code>) before reconciling.</li>')
        return steps


PHASE_TEXT = {
    'starting': 'Starting: preflight passed; Darkbloom is confirming the provider and publishing the drain request.',
    'draining': 'Draining: new work is refused while accepted requests finish.',
    'awaiting_ack': 'Requests finished; waiting for the coordinator to acknowledge usage.',
    'drained': 'Drained; stopping the provider.',
    'awaiting_authorization': 'Relaunched; waiting for fresh authorization (up to 3 minutes).',
    'authorized': 'Freshly authorized; verifying the replacement process independently.',
}

OBSERVATION_TEXT = {
    'original_process_observed': 'At reconciliation, the original provider process was still reported and confirmed.',
    'different_process_observed': 'At reconciliation, a different provider process was reported and confirmed by the kernel.',
    'provider_unobservable': 'At reconciliation, no fresh, kernel-confirmed provider process could be observed.',
}

OUTPUT_NAME = 'console-restart-output'


class ConsoleRestart:
    """Browser front end for gargoyl.manual_restart.

    Same fixed journal directory, lock, gate, installation preflight and invocation as
    `gargoyl tools restart`. Adds: confirmation bound to the displayed process, the
    child's PID/start in the record, and progress parsed from a private output file
    that is deleted afterwards. The restart is never interrupted on monitor shutdown.
    """

    def __init__(self, *, executable, directory, preflight, inspect, observe, invoke=invoke_restart,
                 alive=process_alive, run=run_restart):
        self.executable, self.directory = executable, directory
        self._preflight, self._inspect, self._observe = preflight, inspect, observe
        self._invoke, self._alive, self._run = invoke, alive, run
        self._lock = threading.Lock()
        self._active = False
        self._message = None
        self._outcome = self._exit_code = self._failure = None
        self._operation = None  # operation_id the live outcome belongs to
        self._began = None
        self._events = []
        self._never = threading.Event()  # monitor shutdown never interrupts a restart

    @classmethod
    def for_installation(cls, executable, source, uid):
        def preflight():
            return installation_preflight(executable, source, uid)

        def inspect(stamp):
            if executable_stamp(executable) != stamp:
                raise ValueError('installation changed')
            return observed_target(source, executable, uid)
        return cls(executable=executable, directory=str(owner_home() / '.gargoyl-manual-restart'),
                   preflight=preflight, inspect=inspect,
                   observe=lambda: observed_target(source, executable, uid))

    def record(self):
        try:
            return read_operation(self.directory)
        except Exception:
            return {'unreadable': True}

    def gate(self, record=None):
        if self._active:
            return False, 'A manual restart is in progress from this console.'
        record = self.record() if record is None else record
        if record and record.get('unreadable'):
            return False, 'The manual restart record is unreadable or has unsafe permissions. Restart is blocked.'
        if record and record['state'] not in ('completed', 'reconciled'):
            return False, ('The last manual restart (from this console or the terminal) has no verified outcome. '
                           'Reconcile before another restart.')
        return True, None

    def target(self):
        try:
            target, stamp = self._preflight()
        except Exception as error:
            if str(error) == 'existing_watchdog_required':
                return None, 'the provider watchdog is not verified running; Gargoyl will not newly enable it.'
            return None, ('installation preflight failed (pilot installation only: macOS, owner UID 501, '
                          'MBP-2026.local, canonical paths, plain launchd provider job, running watchdog, fresh '
                          'state, Darkbloom 0.10.5/0.10.6 with matching --version).')
        process = target['process']
        return {'pid': process['pid'], 'born_us': process['born_us'], 'version': target['version'],
                'token': f"{process['pid']}:{process['born_us']}", 'target': target, 'stamp': stamp}, None

    def live(self, record=None):
        """Live state of this console's attempt. Outcome details are shown only for the
        operation they belong to, never against a later CLI operation."""
        with self._lock:
            events = list(self._events)
            result = {'active': self._active, 'message': self._message, 'outcome': self._outcome,
                      'exit_code': self._exit_code, 'failure': self._failure,
                      'elapsed': None if self._began is None else time.monotonic() - self._began}
            operation = self._operation
        if result['active']:
            events = restart_events(self._read_output())[0]
        elif record is not None and record.get('operation_id') != operation:
            result['outcome'] = result['exit_code'] = None
        result['phase'] = progress(events)
        return result

    def _read_output(self):
        try:
            fd = os.open(os.path.join(self.directory, OUTPUT_NAME), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return b''
        with os.fdopen(fd, 'rb') as stream:
            return stream.read(65536)

    def start(self, *, now, confirmed_token):
        with self._lock:
            opened, reason = self.gate()
            if not opened:
                raise Refused(reason)
            target, problem = self.target()
            if target is None:
                raise Refused('Restart is unavailable: ' + problem)
            if confirmed_token != target['token']:
                raise Refused('The provider process changed since the confirmation page was shown. '
                              'Review the new target before restarting.')
            try:
                journal = ManualJournal(self.directory)
            except BlockingIOError:
                raise Refused('Another manual restart (terminal or console) holds the restart lock.') from None
            except Exception:
                raise Refused('The manual restart record could not be opened safely.') from None
            self._active, self._message, self._failure = True, 'Starting.', None
            self._outcome = self._exit_code = self._operation = None
            self._began = time.monotonic()
            self._events = []
            try:
                threading.Thread(target=self._attempt, args=(journal, target), name='gargoyl-restart',
                                 daemon=True).start()
            except BaseException:
                self._active = False
                journal.close()
                raise Refused('The restart could not be started. Nothing was run.') from None

    def _attempt(self, journal, chosen):
        output = None
        try:
            try:
                os.unlink(OUTPUT_NAME, dir_fd=journal.fd)
            except FileNotFoundError:
                pass
            output = os.open(OUTPUT_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                             dir_fd=journal.fd)
            stamp = chosen['stamp']

            def invoke(record_child):
                fresh, current_stamp = self._preflight()  # revalidate immediately before invoking
                if fresh['process'] != chosen['target']['process'] or current_stamp != stamp:
                    raise ValueError('target changed')
                code = self._invoke(self.executable, interrupted=self._never, progress=self._note,
                                    started=record_child, output=output)
                with self._lock:
                    self._exit_code = code
                return code

            self._run(journal, chosen['target'], inspect_target=lambda: self._inspect(stamp), invoke=invoke,
                      confirm=lambda value: value['process'] == chosen['target']['process'],
                      progress=self._note, invoke_with_child=True)
        except BaseException:
            pass  # run_restart has recorded the unknown outcome (or nothing was claimed)
        finally:
            events = restart_events(self._read_output())[0]
            try:
                operation = (journal.read() or {}).get('operation_id')
            except Exception:
                operation = None
            if output is not None:
                os.close(output)
            try:
                os.unlink(OUTPUT_NAME, dir_fd=journal.fd)
            except OSError:
                pass
            journal.close()
            with self._lock:
                self._events = events
                self._outcome = classify_restart(events, self._exit_code) if events or self._exit_code is not None else None
                self._operation = operation
                self._active = False

    def _note(self, text):
        with self._lock:
            self._message = text

    def reconcile(self, *, now):
        if self._active:
            raise Refused('A manual restart is in progress from this console.')
        try:
            journal = ManualJournal(self.directory)
        except BlockingIOError:
            raise Refused('A manual restart (terminal or console) is running and holds the lock.') from None
        except Exception:
            raise Refused('The manual restart record could not be opened safely.') from None
        with journal:
            try:
                record = journal.read()
            except Exception:
                raise Refused('The manual restart record is unreadable or has unsafe permissions.') from None
            if record is None or record['state'] not in ('intent', 'unknown'):
                raise Refused('There is no unresolved manual restart to reconcile.')
            try:
                # Observation only: preflight may legitimately fail after a drain timeout.
                reconcile_operation(journal, inspect_target=self._observe, alive=self._alive)
                try:  # raw output left behind if a monitor stopped mid-restart
                    os.unlink(OUTPUT_NAME, dir_fd=journal.fd)
                except OSError:
                    pass
            except Exception as error:
                if str(error) == 'restart_still_running':
                    raise Refused('The restart command is still running. Wait for it to finish.') from None
                if str(error) == 'restart_may_still_be_running':
                    raise Refused('The restart command\'s process was not recorded, so it may still be running. '
                                  'Reconciliation is available 15 minutes after the attempt started.') from None
                raise Refused('Reconciliation could not be recorded.') from None

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
        if not self.path.startswith('/s/'):
            # Public routes keep the read-only viewer's stricter headers.
            self.csp, self.referrer_policy = _Handler.csp, _Handler.referrer_policy
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
            elif route == '/restart' and tools.restart is not None:
                self._page(200, tools.restart_page(now))
            elif route == '/restart/status' and tools.restart is not None:
                used = self.path.split('?', 1)[1:] == ['form=used']
                self._page(200, tools.restart_status_page(now, note='That form was already used or has expired; '
                                                          'it did not start anything new.' if used else None))
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
            # The header deadline started at connection setup; give the body its own bound.
            self.rfile.raw.deadline = time.monotonic() + 5
            body = self.rfile.read(length)
        except OSError:
            try:
                self.send_error(408)
            except OSError:
                pass
            return
        if len(body) != length:
            self.send_error(400)
            return
        try:
            form = urllib.parse.parse_qs(body.decode('ascii'), strict_parsing=True, max_num_fields=8)
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
            if not tools.consume(form.get('nonce'), 'restart'):  # checked before the typed text
                # Stale, replayed or double-clicked submission: never a second attempt.
                return self._redirect(base + '/restart/status?form=used')
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
                return self._redirect(base + '/restart/status?form=used')
            if form.get('confirm') != self.server.reader.identity[:8]:
                return self._page(200, tools.restart_status_page(now, message='The confirmation text did not '
                                                                 'match. Nothing was recorded.'))
            try:
                tools.restart.reconcile(now=now)
            except Refused as refused:
                return self._page(200, tools.restart_status_page(now, message=str(refused)))
            return self._redirect(base + '/restart/status')
        self.send_error(404)
