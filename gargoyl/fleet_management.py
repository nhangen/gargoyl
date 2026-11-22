"""Private read-only inventory/collector projection; never enrollment or authority.

Account IDs are joined to this Mac only by fresh unique public-identity evidence.
No caller-supplied collector association, aliases or report status can grant a
remote collector or provider operation. Remote transport/enrollment is absent.
"""
from html import escape

from gargoyl.fleet_identity import matching_provider
from gargoyl.fleet_state import evidence_state, provider_key, validate_inventory
from gargoyl.telemetry import effective_state, host_id, timestamp, validate_snapshot


def management_projection(inventory, local, evidence, now, local_host_id, preview=False, lifecycle=None):
    host_id(local_host_id)
    at = timestamp(now)
    samples = []
    if evidence is not None:
        raw = evidence['snapshots']
        if type(raw) is not list or len(raw) > 64:
            raise ValueError('collector history unavailable')
        samples = [validate_snapshot(item) for item in raw]
        if any(item['host_id'] != local_host_id for item in samples):
            raise ValueError('collector host differs')
    if inventory is None:
        return dict(inventory_available=False, partial=True, rows=[], preview=preview, lifecycle=lifecycle)
    validate_inventory(inventory)
    try:
        matched = matching_provider(inventory, local, now)
    except (ValueError, KeyError, TypeError):
        matched = None
    rows = []
    for item in inventory['providers']:
        report, heartbeat = evidence_state(inventory, item, now)
        associated = matched == item['id']
        process_state = 'unknown'
        if associated and samples and timestamp(samples[-1]['collected_at']) <= at:
            process = samples[-1]['fields'].get('daemon_state')
            if process is not None and process['source'] == 'host':
                process_state = effective_state(process, now)
                if process['value'] is None and process_state != 'blocked':
                    process_state = 'unknown'
        rows.append(dict(provider_id=item['id'], source_name=item['name'],
                         source_kind=item['name_kind'], key=provider_key(item['id']),
                         reported_status=item['reported_status'],
                         version=item['version'],
                         account_state=report, heartbeat_state=heartbeat,
                         collection='local_associated' if associated else 'inventory_only',
                         process_state=process_state,
                         history_samples=len(samples) if associated and evidence is not None else None,
                         manual_restart='native_review' if associated else 'unavailable'))
    return dict(inventory_available=True, partial=inventory['partial'], rows=rows,
                fetched_at=inventory['fetched_at'], connection=inventory['connection'],
                preview=preview, lifecycle=lifecycle)


ADVERSE_STATUSES = {"offline", "stopped", "error", "failed", "unhealthy", "ineligible", "disconnected"}


def _report_text(status):
    # The reported value is plain text, outlined when adverse; the glyph describes report
    # freshness, so the two channels never share meaning (evidence doctrine).
    text = escape(status, quote=True) if status else '<span class="faint">status not reported</span>'
    if status is not None and status.lower() in ADVERSE_STATUSES:
        text = '<span class="adv">' + text + "</span>"
    return text


def management_html(projection, aliases):
    from gargoyl.fleet_aliases import validate_aliases
    aliases = validate_aliases(aliases)
    def e(value):
        return escape(str(value), quote=True)
    body = ('<section><h2>Provider management and coverage</h2><p>Each row is an account record, '
            'not an enrolled collector. Only a fresh unique public-identity match associates this '
            'Mac’s direct observations. Source names, local aliases and actual IDs stay distinct.</p>')
    if not projection['inventory_available']:
        if projection.get('preview'):
            return body + ('<p>Inventory unavailable in read-only preview mode — coverage is unknown. '
                           'Account connection is disabled in preview mode.</p></section>')
        return body + ('<p>Inventory unavailable — coverage is unknown, not an empty fleet. '
                       'Use Account to inspect the saved session; no new sign-in is initiated here.</p></section>')
    session_status = e(projection['connection'])
    if projection.get('preview'):
        session_status += ' (read-only preview mode)'
    elif projection.get('lifecycle'):
        session_status += ' · reader ' + e(projection['lifecycle']['status'])
    body += '<p>Account inventory read ' + e(projection['fetched_at']) + ' · session last reported ' + session_status + '. These are coordinator reports, not independent remote health.</p>'
    if projection['partial']:
        body += '<p>Partial inventory. Missing providers have unknown coverage.</p>'
    body += ('<div class="scroll" tabindex="0" role="region" aria-label="Provider management coverage">'
             '<table><thead><tr><th>Provider / actual ID</th><th>Report</th><th>Heartbeat</th>'
             '<th>Version</th><th>Evidence coverage</th><th>History</th>'
             '<th>Operator workflow</th></tr></thead><tbody>')
    for row in projection['rows']:
        label = aliases.get(row['provider_id'], row['source_name'])
        identity = ('<a href="gargoyl-view://fleet-node-' + row['key'] + '/">' + e(label)
                    + '</a><br><span class="mono">' + e(row['provider_id']) + '</span>')
        if row['provider_id'] in aliases:
            identity += '<br><span class="muted">Local alias · source: ' + e(row['source_name']) + '</span>'
        if row['collection'] == 'local_associated':
            identity += '<br><span class="muted">This Mac · unique identity match</span>'
        coverage = ('<span class="muted">Direct observations: </span>' + e(row['process_state'])
                    if row['collection'] == 'local_associated'
                    else '<span class="muted">Direct observations: </span><span class="faint">none (no verified association)</span>')
        history = ('<a href="gargoyl-view://history/">Open local history</a> · '
                   + (e(row['history_samples']) + ' retained samples' if row['history_samples'] is not None
                      else 'unavailable') if row['collection'] == 'local_associated'
                   else '<span class="faint">none here</span>')
        workflow = ('<a href="gargoyl-view://operation/">Restart local…</a> · '
                    '<a href="gargoyl-view://operation/">status</a>' if row['collection'] == 'local_associated'
                    else '<span class="faint">unavailable</span>')
        body += ('<tr><th scope="row">' + identity + '</th>'
                 '<td>' + _report_text(row['reported_status']) + '<br><span class="muted">report '
                 + e(row['account_state']) + '</span></td>'
                 '<td>' + e(row['heartbeat_state']) + '</td>'
                 '<td>' + ('<span class="mono">' + e(row['version']) + '</span>' if row['version']
                           else '<span class="faint">not reported</span>') + '</td>'
                 '<td>' + coverage + '</td><td>' + history + '</td><td>' + workflow + '</td></tr>')
    body += '</tbody></table></div>'
    body += ('<p>Inventory rows differ only in their reported fields. No verified direct collector '
             'association exists for them: this view holds no remote history (its absence is not zero '
             'activity) and the account grant has no provider control, so no enrollment, remote command '
             'or restart is initiated for an inventory row. The Restart local… link applies to this Mac '
             'only and needs a fresh preflight plus your Mac’s confirmation; this view grants nothing.</p>')
    if not projection['rows']:
        body += '<p>No usable returned provider records; check account connection and partial coverage.</p>'
    return body + ('</section><section><h2>Available graphical tools</h2><p>Use <strong>Aliases…</strong> '
                   'to name known IDs without guessing machine mappings. Refresh reads the latest '
                   'normalized report. Export local… saves redacted local evidence. Start monitor/Stop monitor '
                   'affects Gargoyl only. These tools do not enroll or control other machines.</p>'
                   '<h2>History and collector limits</h2><p>Local history retains at most 64 samples in memory; '
                   'monitor restart clears it. Durable encrypted history is not activated: its separate '
                   'key and retention policy still need approval. No history key is created by opening '
                   'this view. Automatic repair, forced restart, backend-guard clearing and provider '
                   'updates are unavailable; diagnostic warnings never authorize an action.</p></section>')
