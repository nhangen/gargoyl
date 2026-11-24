"""Private read-only inventory/collector projection; never enrollment or authority.

Account IDs are joined to this Mac only by fresh unique public-identity evidence.
No caller-supplied collector association, aliases or report status can grant a
remote collector or provider operation. Remote transport/enrollment is absent.
"""
from html import escape

from gargoyl.fleet_identity import matching_provider
from gargoyl.fleet_state import (
    account_report_state,
    heartbeat_state,
    provider_key,
    validate_inventory,
)
from gargoyl.fleet_views import report_freshness_html, reported_status_html
from gargoyl.telemetry import effective_state, host_id, timestamp, validate_snapshot


def _compact_report_value(value):
    if value is not None and len(escape(value).encode()) > 88:
        # Fourteen characters plus an ellipsis fit even when each expands to six bytes.
        return value[:9] + '…' + value[-5:]
    return value


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
        matched = matching_provider(inventory, local, now, lifecycle=lifecycle)
    except (ValueError, KeyError, TypeError):
        matched = None
    rows = []
    for item in inventory['providers']:
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
                         heartbeat_state=heartbeat_state(item, now),
                         collection='local_associated' if associated else 'inventory_only',
                         process_state=process_state,
                         history_samples=len(samples) if associated and evidence is not None else None,
                         manual_restart='native_review' if associated else 'unavailable'))
    return dict(inventory_available=True, partial=inventory['partial'], rows=rows,
                fetched_at=inventory['fetched_at'], connection=inventory['connection'],
                report_state=account_report_state(inventory, now, lifecycle=lifecycle),
                preview=preview, lifecycle=lifecycle)


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
    body += ('<p>Account inventory read ' + e(projection['fetched_at']) + ' · '
             + report_freshness_html(projection['report_state']) + ' · session last reported '
             + session_status + '. These are coordinator reports, not independent remote health.</p>')
    if projection['partial']:
        body += '<p>Partial inventory. Missing providers have unknown coverage.</p>'
    body += ('<div class="scroll management-table" tabindex="0" role="region" aria-label="Provider management coverage" '
             'aria-describedby="management-coverage">'
             '<table><thead><tr><th scope="col">Provider / actual ID</th><th scope="col">Report</th>'
             '<th scope="col">Heartbeat</th><th scope="col">Version</th><th scope="col">Evidence coverage</th>'
             '<th scope="col">History</th><th scope="col">Operator workflow</th></tr></thead><tbody>')
    shortened = False
    for row in projection['rows']:
        status = _compact_report_value(row['reported_status'])
        version = _compact_report_value(row['version'])
        shortened |= status != row['reported_status'] or version != row['version']
        label = aliases.get(row['provider_id'], row['source_name'])
        identity = ('<a href="gargoyl-view://fleet-node-' + row['key'] + '/">' + e(label)
                    + '</a><br><span class="mono">' + e(row['provider_id']) + '</span>')
        if row['provider_id'] in aliases:
            identity += '<br><span class="muted">Local alias · source: ' + e(row['source_name']) + '</span>'
        if row['collection'] == 'local_associated':
            identity += '<br><strong>This Mac · unique identity match</strong>'
            coverage = 'Native process evidence: ' + e(row['process_state'])
            sample_count = row['history_samples']
            retained = 'Monitor history unavailable'
            if sample_count is not None:
                retained = f"{sample_count} retained " + ('sample' if sample_count == 1 else 'samples')
            history = '<a href="gargoyl-view://history/">Open local history</a><br>' + retained
            workflow = '<a href="gargoyl-view://operation/">Operation status</a>'
            if not projection.get('preview'):
                workflow = 'Use <strong>Restart local…</strong> in the toolbar<br>' + workflow
        else:
            coverage = 'Inventory only'
            history = 'None here'
            workflow = 'Unavailable'
        unavailable = ' class="faint"' if row['collection'] == 'inventory_only' else ''
        body += ('<tr><th scope="row">' + identity + '</th>'
                 '<td>' + reported_status_html(row, display_value=status) + '</td>'
                 '<td>' + e(row['heartbeat_state']) + '</td>'
                 '<td>' + ('<span class="mono">' + e(version) + '</span>' if version
                           else '<span class="faint">not reported</span>') + '</td>'
                 '<td>' + coverage + '</td><td' + unavailable + '>' + history
                 + '</td><td' + unavailable + '>' + workflow + '</td></tr>')
    body += '</tbody></table></div>'
    body += ('<p id="management-coverage">Inventory-only rows have no verified direct collector '
             'association. There is no remote history here, so activity is unknown. The account grant '
             'has no provider control, so no enrollment, remote command or restart is initiated for '
             'an inventory row.')
    if not projection.get('preview') and any(row['manual_restart'] == 'native_review' for row in projection['rows']):
        body += ' A local restart requires fresh preflight and confirmation on this Mac.'
    if shortened:
        body += ' Select a provider to see its full report values.'
    body += '</p>'
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
