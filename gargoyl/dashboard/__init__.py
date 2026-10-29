"""Read-only fleet evidence projection. No host access or repair capability."""
from datetime import datetime, timezone
from html import escape

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
                                "comparisons": comparisons, "incidents": incidents})
    return result


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
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Gargoyl fleet evidence</title>',
             '<style>body{font:16px system-ui;margin:2rem;color:#182330;background:#f7f9fc}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;border:1px solid #aebac8;padding:.5rem}section{margin:2rem 0}caption,h2{font-weight:bold} .scroll{overflow:auto}</style>',
             '<body><h1>Fleet evidence</h1><p>Read-only snapshot view. Regenerate after collection and at least every minute. Missing evidence never means healthy.</p>',
             f'<p>Evaluated at {e(dashboard["evaluated_at"])}</p>']
    if not dashboard['hosts']:
        parts.append('<p>unknown — No expected hosts or reports supplied.</p>')
    for host in dashboard['hosts']:
        parts.append(f'<section><h2>Host {e(host["host_id"])}</h2>')
        parts.append('<h3>Collector and correlation incidents</h3><ul>' + ''.join(f'<li>{e(item)}</li>' for item in host['incidents']) + '</ul>')
        if not host['incidents']:
            parts.append('<p>No collector or correlation incident detected; inspect individual evidence below. This is not an overall health verdict.</p>')
        parts.append('<h3>Local / coordinator comparisons</h3><ul>' + ''.join(f'<li>{e(item["metric"])}: {e(item["state"])}</li>' for item in host['comparisons']) + '</ul>')
        parts.append('<h3>Availability, routing and host evidence</h3><div class="scroll">')
        parts.append(table(''.join(rows(metric, items) for metric, items in host['latest'].items() if metric not in {'requests_total','tokens_total','confirmed_paid_microunits'})))
        parts.append('</div>')
        for metric, items in host['latest'].items():
            for item in items:
                if 'conflicting_observations' in item:
                    parts.append(f'<details open><summary>{e(metric)}: unknown — conflicting observations</summary>')
                    parts.append('<p>Reports from the same source at the same observation timestamp disagree in value, state or freshness. No report is selected as authoritative. Original evidence follows.</p><div class="scroll">')
                    parts.append(table(rows(metric, item['conflicting_observations'])))
                    parts.append('</div></details>')
        parts.append('<h3>Local request / token history</h3><p>Cumulative observations; no inferred deltas, billing or earnings.</p><div class="scroll">')
        parts.append(table(''.join(rows(metric, [item for item in host['history'][metric] if item['source'] in LOCAL]) for metric in ('requests_total','tokens_total'))))
        parts.append('</div><h3>Coordinator / console usage evidence</h3><div class="scroll">')
        parts.append(table(''.join(rows(metric, [item for item in host['history'][metric] if item['source'] in {'coordinator','console'}]) for metric in ('requests_total','tokens_total'))))
        parts.append('</div><h3>Console-reported confirmed paid units</h3><p>Microunits only; currency and independent payment verification are not established by this view.</p><div class="scroll">')
        parts.append(table(rows('confirmed_paid_microunits', host['history']['confirmed_paid_microunits'])))
        parts.append('</div><details><summary>Recent failure evidence</summary>')
        parts.append(table(rows('error_code', host['history']['error_code'])))
        parts.append('</details></section>')
    return ''.join(parts) + '</body></html>'
