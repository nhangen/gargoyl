"""Read-only fleet evidence projection. No host access or repair capability."""
from datetime import datetime, timezone
from html import escape

from gargoyl.dashboard.diagnostics import coordinator_diagnostics
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.telemetry import (
    METRICS,
    effective_state,
    host_id,
    timestamp,
    validate_snapshot,
)

LOCAL = {"daemon", "doctor", "launchd", "host", "collector"}
CORRELATED = ("daemon_state", "routing_eligible", "attestation_state", "model_state")


def build_dashboard(snapshots, expected_hosts, now=None):
    """Validate all input; project per-source evidence without treating absence as success.

    Call on each collection and at least once per minute as time passes. The caller
    owns ingestion/refresh scheduling. No network, filesystem, or repair side effects.
    """
    now = datetime.now(timezone.utc).isoformat() if now is None else now
    current = timestamp(now)
    hosts = {host_id(item) for item in expected_hosts}
    validated = [validate_snapshot(item) for item in snapshots]
    hosts.update(item["host_id"] for item in validated)
    result = {"evaluated_at": now, "hosts": []}
    for identity in sorted(hosts):
        evidence = {metric: [] for metric in METRICS}
        for snapshot in validated:
            if snapshot["host_id"] != identity:
                continue
            for metric, field in snapshot["fields"].items():
                item = dict(field, collected_at=snapshot["collected_at"], reported_state=field["state"])
                item["state"] = effective_state(field, now)
                if timestamp(snapshot["collected_at"]) > current:
                    item["state"] = "unknown"
                evidence[metric].append(item)
        latest = {}
        for metric, items in evidence.items():
            latest[metric] = []
            for source in sorted({item["source"] for item in items}):
                candidates = [item for item in items if item["source"] == source]
                newest = max(timestamp(item["timestamp"]) for item in candidates)
                candidates = [item for item in candidates if timestamp(item["timestamp"]) == newest]
                # Contradictory reports with the same source timestamp cannot win by order.
                chosen = max(candidates, key=lambda item: timestamp(item["collected_at"])).copy()
                if len({(item["value"], item["reported_state"], item["freshness_seconds"]) for item in candidates}) > 1:
                    chosen.update(state="unknown", value=None, conflicting_observations=[item.copy() for item in candidates])
                latest[metric].append(chosen)
            items.sort(key=lambda item: (timestamp(item["timestamp"]), item["source"]))
        incidents = []
        heartbeat = [item for item in latest["heartbeat_age_seconds"] if item["source"] == "collector"]
        if not heartbeat:
            incidents.append("missing_collector_heartbeat")
        elif any(item["state"] != "observed" or item["value"] + (current - timestamp(item["timestamp"])).total_seconds() > item["freshness_seconds"] for item in heartbeat):
            incidents.append("collector_heartbeat_not_current")
        comparisons = []
        for metric in CORRELATED:
            local = [item for item in latest[metric] if item["source"] in LOCAL]
            remote = [item for item in latest[metric] if item["source"] == "coordinator"]
            state = "unknown"
            fresh_local = [item for item in local if item["state"] == "observed"]
            fresh_remote = [item for item in remote if item["state"] == "observed"]
            if any(left["value"] != right["value"] for left in fresh_local for right in fresh_remote):
                state = "mismatch"
            elif local and remote and all(item["state"] == "observed" for item in local + remote):
                state = "agreement"
            comparisons.append({"metric": metric, "state": state, "evidence": local + remote})
            if state == "mismatch":
                incidents.append(metric + "_mismatch")
        result["hosts"].append({"host_id": identity, "latest": latest, "history": evidence,
                                "comparisons": comparisons, "incidents": incidents,
                                "diagnostics": coordinator_diagnostics(evidence["error_code"])})
    return result


ADVERSE_VALUES = {
    'daemon_state': frozenset({'stopped', 'degraded'}),
    'doctor_state': frozenset({'failed'}),
    'launchd_state': frozenset({'stopped', 'missing'}),
    'model_state': frozenset({'absent', 'failed'}),
    'memory_pressure': frozenset({'warning', 'critical'}),
    'thermal_pressure': frozenset({'warning', 'critical'}),
    'coordinator_reachable': frozenset({'unreachable'}),
    'routing_eligible': frozenset({'ineligible'}),
    'attestation_state': frozenset({'expired', 'missing'}),
    'error_code': frozenset({'timeout', 'unavailable', 'invalid_state', 'permission_denied'}),
}


def render_overview(dashboard):
    """Render only the validated projection, with every newest source kept distinct."""
    def e(value):
        return escape(str(value), quote=True)

    columns = (('heartbeat_age_seconds', 'Reported heartbeat age (s)'),
               ('daemon_state', 'Provider liveness'), ('routing_eligible', 'Eligibility'),
               ('attestation_state', 'Attestation'), ('model_state', 'Model'),
               ('memory_pressure', 'Memory pressure'))
    attention, rows = [], []
    for host in dashboard['hosts']:
        identity = host['host_id']
        reasons = list(host['incidents'])
        for metric, items in host['latest'].items():
            for item in items:
                if 'conflicting_observations' in item:
                    reasons.append(metric + ': conflicting observations — unknown')
                elif item['state'] == 'stale':
                    reasons.append(metric + ': stale ' + item['source'] + ' report')
                elif item['state'] == 'blocked':
                    reasons.append(metric + ': blocked report; reason not supplied by v1')
                elif item['state'] == 'observed' and item['value'] in ADVERSE_VALUES.get(metric, ()):
                    reasons.append(metric + ': adverse reported value ' + str(item['value']))
        if host['diagnostics']['state'] == 'warning':
            reasons.append('coordinator diagnostic warning; cause and routing impact unknown')
        if reasons:
            attention.append('<li><a href="#host-' + e(identity) + '">' + e(identity)
                             + '</a><p>' + '; '.join(e(x) for x in dict.fromkeys(reasons)) + '</p></li>')
        cells = []
        for metric, _ in columns:
            items = host['latest'][metric]
            values = []
            for item in items:
                value = item['value'] if item['value'] is not None else 'unknown'
                if 'conflicting_observations' in item:
                    value = 'conflicting observations'
                display = ('<span class="adv">' + e(value) + '</span>'
                           if item['value'] in ADVERSE_VALUES.get(metric, ()) else e(value))
                values.append('<span class="ev-line"><span class="ev ev-' + e(item['state'])
                              + '">' + e(item['state']) + ' · ' + display + '</span><small>'
                              + e(item['source']) + ' · ' + e(item['timestamp']) + ' · TTL '
                              + e(item['freshness_seconds']) + 's</small></span>')
            cells.append('<td>' + (''.join(values) if values else
                                  '<span class="ev ev-unknown">unknown · No report</span>') + '</td>')
        rows.append('<tr><th scope="row" class="host"><a title="' + e(identity) + '" href="#host-' + e(identity) + '">'
                    + e(identity[:8] + '…' + identity[-4:]) + '</a></th>' + ''.join(cells) + '</tr>')
    return ('<section id="fleet-overview" aria-labelledby="overview-title">'
            '<h2 id="overview-title">Hosts and evidence</h2><p>' + str(len(dashboard['hosts']))
            + (' host' if len(dashboard['hosts']) == 1 else ' hosts') + ' in expected inventory or supplied reports. Each source stays distinct; '
            'there is no overall health score.</p><div class="legend evidence-legend" role="group" '
            'aria-label="Evidence legend">' + ''.join('<span class="ev ev-' + state + '">'
            + state + '</span>' for state in ('observed', 'stale', 'unknown', 'blocked'))
            + '<span class="adv">adverse reported value</span></div>'
            '<div class="table-wrap" tabindex="0" role="region" aria-label="Host overview table">'
            '<table class="fleet"><caption class="sr-only">Newest per-source evidence; inspect host for original reports</caption>'
            '<thead><tr><th scope="col">Host</th>' + ''.join('<th scope="col">' + label + '</th>'
            for _, label in columns) + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
            '<h3>Needs attention</h3><div class="attention">' + ('<ul>' + ''.join(attention) + '</ul>'
            if attention else '<p>No collector, correlation, stale, blocked, conflicting or adverse-report '
            'items detected in this projection. Missing fields and protocol confidence remain unknown; '
            'this is not a health verdict.</p>') + '</div></section>')


def render_dashboard(snapshots, expected_hosts, now=None):
    """Render a self-contained evidence view; input always crosses v1 validation."""
    dashboard = build_dashboard(snapshots, expected_hosts, now)
    def e(value):
        return escape(str(value), quote=True)
    def rows(metric, items):
        if not items:
            return f'<tr><th>{e(metric)}</th><td>unknown</td><td colspan="4">No report</td></tr>'
        return ''.join(f'<tr><th>{e(metric)}</th><td>{e(item["state"])} (reported: {e(item["reported_state"])})</td>'
                       f'<td>{e(item["value"] if item["value"] is not None else "—")}</td>'
                       f'<td>{e(item["source"])}</td><td>{e(item["timestamp"])}</td>'
                       f'<td>{e(item["collected_at"])}; TTL {e(item["freshness_seconds"])}s</td></tr>' for item in items)
    def table(content):
        return '<table><thead><tr><th>Metric</th><th>Evidence state</th><th>Value</th><th>Source</th><th>Source timestamp</th><th>Collection / freshness</th></tr></thead><tbody>' + content + '</tbody></table>'
    parts = [page_start('Gargoyl fleet evidence'),
             '<h1>Fleet evidence</h1><p>Read-only snapshot view. Regenerate after collection and at least every minute. Missing evidence never means healthy.</p>',
             f'<p>Evaluated at {e(dashboard["evaluated_at"])}</p>',
             render_overview(dashboard), '<div id="local-collection"></div>']
    if not dashboard['hosts']:
        parts.append('<p>unknown — No expected hosts or reports supplied.</p>')
    for host in dashboard['hosts']:
        parts.append(f'<section class="host-evidence" id="host-{e(host["host_id"])}"><h2 class="host-id">Host {e(host["host_id"])}</h2>')
        parts.append('<h3>Collector and correlation incidents</h3><ul>' + ''.join(f'<li>{e(item)}</li>' for item in host['incidents']) + '</ul>')
        if not host['incidents']:
            parts.append('<p>No collector or correlation incident detected; inspect individual evidence below. This is not an overall health verdict.</p>')
        parts.append('<h3>Local liveness and eligibility reports</h3>')
        parts.append('<p>Collector liveness does not prove provider liveness. Running and eligible '
                     'reports do not establish coordinator protocol compatibility or dispatch.</p><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, [item for item in host['latest'][metric]
                                                if item['source'] in LOCAL])
                                   for metric in ('daemon_state', 'launchd_state',
                                                  'routing_eligible', 'attestation_state'))))
        parts.append('</div><h3>Coordinator and protocol confidence</h3><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, [item for item in host['latest'][metric]
                                                if item['source'] == 'coordinator' or
                                                (metric == 'coordinator_reachable' and item['source'] == 'daemon')])
                                   for metric in ('coordinator_reachable', 'routing_eligible'))))
        parts.append('</div><p>Daemon-reported connection state is not independent coordinator confirmation.</p><p>Protocol confidence: <strong>unknown</strong>. '
                     'No supported protocol-compatibility evidence is collected. Reachability, '
                     'eligibility and a reported absence of errors cannot establish it.</p>')
        diagnostic = host['diagnostics']
        if diagnostic['state'] == 'warning':
            label = ('Repeated coordinator error observations' if diagnostic['recurrence'] == 'repeated_observations'
                     else 'Coordinator error observation; recurrence unknown')
            parts.append(f'<p><strong>Diagnostic warning: {e(label)}</strong>. '
                         f'Normalized codes: {e(", ".join(diagnostic["codes"]))}. '
                         'This is not a distinct error-event count or a restart trigger. '
                         'These retained observations do not establish a current service failure. '
                         'Root cause and impact on routing remain unknown.</p>')
        else:
            parts.append('<p>Coordinator diagnostic detail: <strong>unknown</strong>. '
                         'No unambiguous current normalized coordinator error observation is available. '
                         'This does not establish an error-free connection.</p>')
        parts.append('<p>This diagnostic assessment covers normalized error-code reports. Optional local '
                     'coordinator log-record counts are displayed separately.</p>')
        parts.append('<p>Low or zero traffic alone is not a failure signal. Demand and routing '
                     'effects cannot be distinguished from counters alone. No restart is inferred.</p>')
        parts.append('<h3>Model and memory evidence</h3><p>These observations are separate from '
                     'coordinator warnings and do not establish their cause.</p><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, host['latest'][metric]) for metric in
                                   ('model_state', 'memory_pressure', 'memory_headroom_bytes'))))
        parts.append('</div>')
        parts.append('<h3>Local / coordinator comparisons</h3><ul>' + ''.join(f'<li>{e(item["metric"])}: {e(item["state"])}</li>' for item in host['comparisons']) + '</ul>')
        parts.append('<details><summary>All normalized availability evidence</summary><h3>Availability, routing and host evidence</h3><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, items) for metric, items in host['latest'].items() if metric not in {'requests_total','tokens_total','confirmed_paid_microunits'})))
        parts.append('</div></details>')
        for metric, items in host['latest'].items():
            for item in items:
                if 'conflicting_observations' in item:
                    parts.append(f'<details open><summary>{e(metric)}: unknown — conflicting observations</summary>')
                    parts.append('<p>Reports from the same source at the same observation timestamp disagree in value, state or freshness. No report is selected as authoritative. Original evidence follows.</p><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
                    parts.append(table(rows(metric, item['conflicting_observations'])))
                    parts.append('</div></details>')
        parts.append('<h3>Local request / token history</h3><p>Cumulative observations; no inferred deltas, billing or earnings.</p><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, [item for item in host['history'][metric] if item['source'] in LOCAL]) for metric in ('requests_total','tokens_total'))))
        parts.append('</div><h3>Coordinator / console usage evidence</h3><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(''.join(rows(metric, [item for item in host['history'][metric] if item['source'] in {'coordinator','console'}]) for metric in ('requests_total','tokens_total'))))
        parts.append('</div><h3>Console-reported confirmed paid units</h3><p>Microunits only; currency and independent payment verification are not established by this view.</p><div class="scroll" tabindex="0" role="region" aria-label="Evidence table">')
        parts.append(table(rows('confirmed_paid_microunits', host['history']['confirmed_paid_microunits'])))
        parts.append('</div><details><summary>Recent failure evidence</summary>')
        parts.append(table(rows('error_code', host['history']['error_code'])))
        parts.append('</details></section>')
    return ''.join(parts) + PAGE_END
