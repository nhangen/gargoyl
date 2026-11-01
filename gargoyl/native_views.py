"""Pure native admin presentation. No browser authority, provider calls or secrets."""

from datetime import datetime, timezone
from html import escape

from gargoyl.collector_coordinator_log import validate_log_report
from gargoyl.dashboard import render_dashboard
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.manual_restart import validate_record
from gargoyl.telemetry import effective_state, timestamp, validate_snapshot

HOST = "00000000-0000-4000-8000-000000000001"
VIEWS = ("tools", "evidence", "history", "operation", "details")
LABELS = ("Operator tools", "Live evidence", "Traffic history", "Manual operation", "Local details")


def e(value):
    return escape(str(value), quote=True)


def nav(current):
    return tuple((f"gargoyl-view://{view}/", label, view == current)
                 for view, label in zip(VIEWS, LABELS))


def card(title, text, *, view=None, state="Read-only"):
    action = (f'<a class="btn" href="gargoyl-view://{view}/">Open</a>' if view else '')
    return ('<li class="tool"><div class="tool-main"><h3>' + e(title)
            + '</h3><p>' + e(text) + '</p><p class="tool-effect"><span class="st st-info">'
            + e(state) + '</span></p></div><div class="tool-action">' + action + '</div></li>')


def render_view(view, evidence, record, *, journal_available=True, now=None):
    """Inputs are reconstructed normalized export and validated journal; never raw HTML."""
    if view not in VIEWS:
        raise ValueError("unsupported view")
    now = now or datetime.now(timezone.utc).isoformat()
    timestamp(now)
    if evidence is not None:
        timestamp(evidence['evaluated_at'])
        samples = evidence['snapshots']
        if type(samples) is not list or len(samples) > 64:
            raise ValueError("history limit")
        samples = [validate_snapshot(sample) for sample in samples]
        if any(sample['host_id'] != HOST for sample in samples):
            raise ValueError("host differs")
        evidence = dict(evidence, snapshots=samples)
    if record is not None:
        record = validate_record(record)
    if view == "evidence" and evidence is not None:
        # Re-evaluate TTL at viewing time, not the monitor's earlier evaluation time.
        html = render_dashboard(evidence['snapshots'][-1:], [HOST], now,
                                extra_nav=nav(view), badge="Native operator console")
        notice = ('<p>Native evidence view. Use Refresh to load current evidence and re-evaluate '
                  'freshness. No provider command is run.</p>')
        log = evidence.get('coordinator_log_report')
        if log is not None:
            log = dict(log)
            log.pop('effective_state', None)
            log = validate_log_report(log)
            age = (timestamp(now) - timestamp(log['observed_at'])).total_seconds()
            state = 'unknown' if age < 0 else ('stale' if age > log['freshness_seconds'] else log['state'])
            notice += ('<section><h2>Scoped coordinator log evidence</h2><p>Effective state: ' + e(state)
                       + ' · reason: ' + e(log['reason']) + ' · observed: ' + e(log['observed_at'])
                       + '</p>')
            if state == 'observed':
                notice += ('<p>Visible records: ' + e(log['count']) + ' · redacted records: '
                           + e(log['redacted_count']) + ' · latest event: ' + e(log['latest_event_at']) + '</p>')
            else:
                notice += '<p>Current counts and recency are unknown; no current log observation is available.</p>'
            notice += ('<p>Counts cover selected visible records only. They do not establish root '
                       'cause, routing failure or a restart trigger.</p></section>')
        html = html.replace('<main id="main">', '<main id="main">' + notice, 1)
        if len(html.encode()) > 500000:
            raise ValueError("view limit")
        return html.replace('href="#', 'href="about:blank#')
    body = '<h1>' + LABELS[VIEWS.index(view)] + '</h1>'
    body += ('<p>Native Mac app · automatic repair is off. Use Refresh to load current evidence '
             'and re-evaluate freshness. Views do not refresh automatically.</p>')
    if evidence is None:
        body += ('<div class="callout warn"><p>Monitor evidence unavailable — health, eligibility, '
                 'model and traffic are unknown. Use Start monitoring if needed, then Refresh. '
                 'This does not start Darkbloom or resolve an uncertain operation.</p></div>')
    else:
        body += '<p class="muted">Viewed at ' + e(now) + ' · monitor evaluated at ' + e(evidence['evaluated_at']) + '</p>'
    if view == "tools":
        body += '<section><h2>Inspect and operate</h2><ul class="tool-list">'
        body += card("Health, model and connection", "Normalized observations and daemon reports, with source timestamps, stale and unknown states. Protocol compatibility remains unknown.", view="evidence")
        body += card("Traffic history", "Up to 64 retained samples. Counter observations do not prove routing, demand or earnings.", view="history")
        body += card("Refresh evidence", "Use Refresh in the native toolbar. Reads the latest monitor report; does not force a poll or run provider diagnostics.")
        body += card("Export diagnostics", "Use Export… in the native toolbar to choose a file. Normalized evidence only; no raw logs, model names or credentials.")
        body += card("Manual provider restart", "Use Restart provider… in the native toolbar to review the exact installation and interruption, then confirm with your Mac. No action begins from these links. Preconditions are checked when you review; availability is not assumed.", view="operation", state="Changes service state · Mac confirmation required")
        body += card("Local details", "Inspect collection boundaries and which capabilities are unavailable.", view="details")
        body += '</ul></section><section><h2>Not available in this app</h2><ul class="tool-list">'
        body += card("Provider status / doctor commands", "Not run here: upstream commands may load configuration or use network/helpers. Existing normalized evidence is available instead.", state="Unavailable")
        body += card("Automatic repair, force, clear guard and provider updates", "Disabled. No automatic retry, force, credential setup or provider lifecycle action is inferred from diagnostic warnings.", state="Unavailable")
        body += '</ul></section>'
    elif view == "history" and evidence is not None:
        body += '<section><h2>Retained local counter observations</h2><p>In-memory history, lost when the monitor restarts. Cumulative values; no inferred deltas or earnings. Zero traffic alone is not failure.</p><div class="scroll" tabindex="0"><table><thead><tr><th>Collected</th><th>Metric</th><th>Value</th><th>Source</th><th>Observed</th><th>Effective state</th></tr></thead><tbody>'
        rows = 0
        for sample in evidence['snapshots']:
            for metric in ('requests_total', 'tokens_total'):
                field = sample['fields'].get(metric)
                if field is None:
                    continue
                state = ("unknown" if timestamp(sample["collected_at"]) > timestamp(now)
                         else effective_state(field, now))
                body += '<tr>' + ''.join('<td>' + e(v) + '</td>' for v in (sample['collected_at'], metric, field['value'], field['source'], field['timestamp'], state)) + '</tr>'
                rows += 1
        body += '</tbody></table></div>'
        if not rows:
            body += '<p>Unknown — no retained counter observations.</p>'
        body += '</section>'
    elif view == "operation":
        body += '<section><h2>Shared manual-operation record</h2>'
        if not journal_available:
            body += '<div class="callout warn"><p>Operation record unavailable. Outcome is unknown; this view cannot authorize a retry.</p></div>'
        elif record is None:
            body += '<p>No manual operation recorded. This is not proof that a restart is currently available.</p>'
        else:
            verified = record['state'] == 'completed' and record['reason'] == 'cli_success_and_replacement_observed'
            body += '<p><span class="st ' + ('st-observed' if verified else 'st-warning') + '">' + ('Verified replacement observed' if verified else 'Unresolved — native retry blocked') + '</span></p><dl class="facts">'
            facts = [("Operation", record['operation_id']), ("State", record['state']), ("Reason", record['reason']), ("Started", record['started_at']), ("Target PID", record['target']['process']['pid'])]
            if 'finished_at' in record:
                facts.append(("Finished", record['finished_at']))
            if 'replacement' in record:
                facts.append(("Replacement PID", record['replacement']['process']['pid']))
            body += ''.join('<div><dt>' + e(k) + '</dt><dd class="mono">' + e(v) + '</dd></div>' for k, v in facts) + '</dl>'
        body += ('<p>Review the exact target and interruption with Restart provider… in the native toolbar. '
                 'One shared durable journal prevents concurrent submissions. Intent, unknown and externally '
                 'reconciled records remain blocked in the native app. This view never clears the gate.</p>'
                 '<p>Accepted work may drain for 10 minutes; startup may take 3 minutes. No force or automatic '
                 'retry. An interrupted or uncertain command may leave the provider draining or unavailable. '
                 'Darkbloom has no durable request ledger; exactly-once execution is not claimed.</p>'
                 '<p>While an operation runs, the native status area shows received progress. The journal '
                 'does not prove a current phase or remaining work. Protocol health remains separate.</p></section>')
    elif view == "details":
        body += ('<section><h2>Local collection boundaries</h2><dl class="facts">'
                 '<div><dt>Host</dt><dd class="mono">' + HOST + '</dd></div>'
                 '<div><dt>Monitor</dt><dd>IPv4 loopback · port 8766 · read-only report</dd></div>'
                 '<div><dt>History</dt><dd>At most 64 normalized samples; memory only</dd></div>'
                 '<div><dt>Owner confirmation</dt><dd>Native Mac authentication and private worker pipe</dd></div>'
                 '<div><dt>Browser actions</dt><dd>Disabled in this installation</dd></div>'
                 '<div><dt>Automatic repair</dt><dd>Disabled</dd></div></dl>'
                 '<p>Gargoyl’s own background recovery restarts the monitor, not Darkbloom. Closing, '
                 'hiding or minimizing this window leaves monitoring and the provider running.</p>'
                 '<p>Provider version/build inspection is not performed by opening these pages. '
                 'Daemon-reported values are reports, not independent binary provenance. Raw logs, '
                 'credential files and model names are not collected by these views.</p></section>')
    html = page_start(LABELS[VIEWS.index(view)] + ' · Gargoyl', extra_nav=nav(view), badge="Native operator console") + body + PAGE_END
    if len(html.encode()) > 500000:
        raise ValueError("view limit")
    return html.replace('href="#', 'href="about:blank#')
