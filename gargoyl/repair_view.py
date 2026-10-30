"""Read-only repair data presentation; no routes, execution or authorization minting."""
from html import escape

from gargoyl.repair_catalog import RunbookCatalog, VerifiedRunbook
from gargoyl.repair_contract import (
    RepairAuditEntry,
    RepairConfirmation,
    RepairPlan,
    RepairReceipt,
    canonical,
    require,
    validate_confirmation,
)


def _text(value):
    return escape(str(value), quote=True)


def _page(title, content):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width">'
            f'<title>{_text(title)}</title></head><body><h1>{_text(title)}</h1>'
            '<p>Read-only presentation. This page cannot authorize, confirm, execute, '
            'retry or resume an operation.</p>' + content + '</body></html>')


def _unavailable():
    return _page('Repair data unavailable', '<p>Input validation failed. State is unknown; '
                 'no authorization or successful outcome is established.</p>')


def _fields(values):
    return '<dl>' + ''.join(f'<dt>{_text(name)}</dt><dd>{_text(value)}</dd>'
                           for name, value in values) + '</dl>'


def _checks(checks):
    return ('<table><thead><tr><th>Check</th><th>State</th><th>Required</th></tr></thead><tbody>'
            + ''.join(f'<tr><td>{_text(c["check_id"])}</td><td>{_text(c["state"])}</td>'
                      f'<td>{_text(c["required"])}</td></tr>' for c in checks)
            + '</tbody></table>')


def _plan_details(plan):
    value = plan.as_dict()
    book = VerifiedRunbook(canonical(value['runbook']))
    manifest = book.as_dict()['manifest']
    details = _fields([
        ('Target host', value['target_host']), ('Runbook', manifest['runbook_id']),
        ('Version', manifest['version']), ('Runbook digest', book.digest),
        ('Plan digest', plan.digest), ('Operation', manifest['operation']),
        ('Manifest timeout seconds', manifest['timeout_seconds']),
        ('Preflight evaluated at', value['evaluated_at']), ('Plan expires at', value['expires_at']),
    ])
    details += '<h2>Recorded preflight checks</h2>' + _checks(value['checks'])
    details += '<h2>Exact preflight evidence</h2>'
    if not value['evidence']:
        return details + '<p>No evidence supplied. Evidence state is unknown.</p>'
    details += ('<table><thead><tr><th>Metric</th><th>Value</th><th>Reported state</th>'
                '<th>Source</th><th>Observation time</th><th>Collection time</th>'
                '<th>Freshness seconds</th></tr></thead><tbody>')
    for snapshot in value['evidence']:
        for metric, field in snapshot['fields'].items():
            row = (metric, field['value'] if field['value'] is not None else 'unknown',
                   field['state'], field['source'], field['timestamp'],
                   snapshot['collected_at'], field['freshness_seconds'])
            details += '<tr>' + ''.join(f'<td>{_text(v)}</td>' for v in row) + '</tr>'
    return details + '</tbody></table>'


def render_preview(plan, catalog, *, now, confirmation=None):
    """Revalidate catalog/plan and optional intent binding; never establish authority.

    Current checks are recomputed via the catalog without replacing the original
    plan or digest. No signature/authentication logic is duplicated here.
    """
    try:
        require(type(plan) is RepairPlan and type(catalog) is RunbookCatalog)
        checked = catalog.validate_plan(RepairPlan(getattr(plan, 'payload', None)), now=now)
        value = checked.as_dict()
        current = catalog.plan(VerifiedRunbook(canonical(value['runbook'])),
                               value['target_host'], value['evidence'], now=now).as_dict()
        intent = None
        if confirmation is not None:
            require(type(confirmation) is RepairConfirmation)
            intent = validate_confirmation(
                RepairConfirmation(getattr(confirmation, 'payload', None)), checked, now=now).as_dict()
        content = '<p>Catalog signature and exact version/digest pin revalidated for this preview.</p>'
        if current['blocked']:
            content += '<p>Blocked: preconditions_blocked. Authoritative prerequisites are unavailable. '
            content += 'No impact override is supported.</p>'
        else:
            content += '<p>Preview only: no required catalog check blocks this diagnostic operation. '
            content += 'Authenticated user confirmation and an available adapter are not established.</p>'
        content += _plan_details(checked)
        content += '<h2>Current evidence assessment</h2>' + _fields([('Evaluated now', now)])
        content += _checks(current['checks'])
        content += '<p>Unknown, stale, future or conflicting evidence never supplies authorization. '
        content += 'Execution must obtain current evidence and independently revalidate preflight.</p>'
        content += '<h2>Explicit confirmation binding</h2>'
        if intent is None:
            content += '<p>No confirmation supplied. No actor or user click is established.</p>'
        else:
            content += '<p>Intent binding valid as data only. Actor identity, actual user click and '
            content += 'permission remain unverified by this page.</p>'
            content += _fields([(name, intent[name]) for name in (
                'actor_id', 'click_id', 'target_host', 'runbook_id', 'version',
                'runbook_digest', 'plan_digest', 'confirmed_at', 'expires_at', 'impact_acknowledged')])
        return _page('Runbook preview', content)
    except Exception:
        return _unavailable()


def _receipt_details(receipt):
    value = receipt.as_dict()
    content = '<h2>Reported terminal result</h2>' + _fields([
        ('Reported outcome', value['outcome']), ('Stage', value['stage']),
        ('Reason', value['reason']), ('Cleanup complete', value['cleanup_complete']),
        ('Actor ID', value['actor_id']), ('Click ID', value['click_id']),
        ('Started at', value['started_at']), ('Finished at', value['finished_at']),
    ])
    if value['outcome'] == 'outcome_unknown':
        content += '<p>Outcome unknown. Side effects may have occurred; no automatic retry or resume.</p>'
    elif value['outcome'] != 'succeeded':
        content += '<p>This record does not report success and grants no retry permission.</p>'
    else:
        content += '<p>The supplied record reports success; this display does not independently '
        content += 'verify execution, user authorization or audit durability.</p>'
    if value['reason'] == 'clock_invalid':
        content += '<p>Clock invalid: finished_at is a fallback bound, not a trustworthy completion time.</p>'
    return content + _plan_details(RepairPlan(canonical(value['preflight'])))


def _historical_notice():
    return ('<p>Historical data: shape and internal bindings validated only. '
            'Authenticity and durable audit storage are not established by a wrapper class. '
            'Current catalog trust, preflight validity and authority are not asserted. '
            'Recorded checks below are historical claims, not current safety evidence.</p>')


def render_receipt(receipt):
    """Display historical receipt data without current-catalog/expiry authorization."""
    try:
        require(type(receipt) is RepairReceipt)
        checked = RepairReceipt(getattr(receipt, 'payload', None))
        return _page('Historical repair receipt', _historical_notice() + _receipt_details(checked))
    except Exception:
        return _unavailable()


def render_audit_entry(entry):
    """Display validated audit data; None never means success or absence of effects."""
    if entry is None:
        return _page('Audit result unavailable', '<p>No audit entry supplied. Outcome unknown; '
                     'no absence of side effects, successful outcome or retry permission is established.</p>')
    try:
        require(type(entry) is RepairAuditEntry)
        value = RepairAuditEntry(getattr(entry, 'payload', None)).as_dict()
        content = _historical_notice()
        if value['state'] == 'started':
            content += '<p>Recorded claim: started. Outcome unknown: recovery_required. '
            content += 'No terminal receipt is present. Do not automatically retry, reset or resume.</p>'
            intent = value['confirmation']
            content += _fields([('Actor ID', intent['actor_id']), ('Click ID', intent['click_id']),
                                ('Started at', value['started_at'])])
            content += _plan_details(RepairPlan(canonical(value['plan'])))
        else:
            content += _receipt_details(RepairReceipt(canonical(value['receipt'])))
        return _page('Historical audit record', content)
    except Exception:
        return _unavailable()
