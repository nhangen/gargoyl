"""Private account inventory presentation. Never a provider-control surface."""

import re
from html import escape

from gargoyl.dashboard import build_dashboard
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.fleet_identity import matching_provider
from gargoyl.fleet_state import evidence_state, provider_key, validate_inventory

FLEET_FILTERS = {
    "fleet": None,
    "fleet-recent": "recent",
    "fleet-older": "older",
    "fleet-unknown": "unknown",
}
HOST = "00000000-0000-4000-8000-000000000001"


def fleet_mode(view):
    return (
        view in FLEET_FILTERS
        or re.fullmatch(r"fleet-node-[a-f0-9]{64}", view) is not None
    )


def e(value):
    return escape(str(value), quote=True)


def render_fleet(view, inventory, evidence, local, alias, now, navigation):
    if not fleet_mode(view):
        raise ValueError("unsupported fleet view")
    if inventory is not None:
        validate_inventory(inventory)
    matched = matching_provider(inventory, local, now)
    body = "<h1>Your fleet</h1><p>Account-owned provider records. Coordinator reports and this Mac’s direct observations stay separate. No remote control or automatic repair.</p>"
    local_body = ""
    local_body += "<section><h2>This Mac · " + e(alias) + "</h2>"
    if evidence is None or not evidence["snapshots"]:
        local_body += "<p>Direct local observations unavailable. Local provider health is unknown.</p>"
    else:
        host = build_dashboard(evidence["snapshots"][-1:], [HOST], now)["hosts"][0]
        for metric, label, source in [
            ("daemon_state", "Native provider process", "host"),
            ("model_state", "Model residency report", "daemon"),
            ("routing_eligible", "Eligibility report", "daemon"),
        ]:
            rows = [r for r in host["latest"][metric] if r["source"] == source]
            if not rows:
                local_body += "<p>" + e(label) + ": unknown — no report.</p>"
            for row in rows:
                local_body += (
                    "<p>"
                    + e(label)
                    + ": <strong>"
                    + e(row["value"] if row["value"] is not None else "unknown")
                    + "</strong> · "
                    + e(row["state"])
                    + " · "
                    + e(row["source"])
                    + " · "
                    + e(row["timestamp"])
                    + "</p>"
                )
    local_body += (
        "<p>Account association: "
        + (
            e(matched) + " · unique matching public identity"
            if matched
            else "unknown — no fresh unique account identity match"
        )
        + '.</p><p class="muted">This hostname is a local alias, not a provider name or ID.</p></section>'
    )
    if inventory is None:
        body += "<section><h2>Connect your account</h2><p>No verified account inventory is available. Choose <strong>Connect fleet…</strong> in the native toolbar, then complete Darkbloom’s read-only approval in your browser. No provider grant fallback is accepted.</p><p>This is not an empty fleet result. Other machines have not been queried.</p></section>"
    else:
        rows = inventory["providers"]
        body += (
            "<section><h2>Owned provider inventory</h2><p>Source: Darkbloom account API · last successful read "
            + e(inventory["fetched_at"])
            + " · session last reported "
            + e(inventory["connection"])
            + ".</p>"
        )
        body += "<p>" + str(len(rows)) + " returned provider records"
        if inventory["reported_total"] is not None:
            body += " of " + str(inventory["reported_total"]) + " reported total"
        body += ". This is account-reported inventory, not independent remote process verification.</p>"
        if inventory["partial"]:
            body += '<div class="callout warn"><p>Partial inventory: some records or pages are unavailable. Missing machines must not be treated as absent or healthy.</p></div>'
        if inventory["connection"] != "connected":
            body += '<div class="callout warn"><p>Account collection is disconnected or unavailable. These are cached records; reconnect for current reports. Heartbeat timestamps are historical evidence.</p></div>'
        if view.startswith("fleet-node-"):
            selected = [
                r
                for r in rows
                if provider_key(r["id"]) == view.removeprefix("fleet-node-")
            ]
            if len(selected) != 1:
                body += "<p>Provider unavailable in this inventory. No substitute was selected.</p>"
            else:
                row = selected[0]
                report, heartbeat = evidence_state(inventory, row, now)
                body += "<h3>" + e(row["name"]) + '</h3><dl class="facts">'
                for label, value in [
                    ("Actual provider ID", row["id"]),
                    ("Label source", row["name_kind"]),
                    ("Reported status", row["reported_status"] or "unknown"),
                    ("Report freshness", report),
                    ("Last heartbeat", row["heartbeat_at"] or "unknown"),
                    ("Heartbeat recency", heartbeat),
                    ("Reported version", row["version"] or "unknown"),
                    (
                        "Local association",
                        "This Mac: " + alias
                        if matched == row["id"]
                        else "not independently observed locally",
                    ),
                ]:
                    body += (
                        "<div><dt>"
                        + e(label)
                        + '</dt><dd class="mono">'
                        + e(value)
                        + "</dd></div>"
                    )
                body += "</dl><p>No restart, enrollment or remote command authority is granted by this record.</p>"
        else:
            body += (
                '<nav aria-label="Fleet filters"><p>'
                + " · ".join(
                    '<a href="gargoyl-view://' + key + '/">' + label + "</a>"
                    for key, label in [
                        ("fleet", "All records"),
                        ("fleet-recent", "Recent heartbeat"),
                        ("fleet-older", "Older heartbeat"),
                        ("fleet-unknown", "Unknown heartbeat"),
                    ]
                )
                + "</p></nav>"
            )
            shown = [
                r
                for r in rows
                if FLEET_FILTERS[view] is None
                or evidence_state(inventory, r, now)[1] == FLEET_FILTERS[view]
            ]
            body += '<div class="scroll" tabindex="0" role="region" aria-label="Account provider inventory"><table><thead><tr><th>Provider / actual ID</th><th>Label source</th><th>Coordinator report</th><th>Heartbeat</th><th>Local evidence</th></tr></thead><tbody>'
            for row in shown:
                report, heartbeat = evidence_state(inventory, row, now)
                body += (
                    '<tr><th><a href="gargoyl-view://fleet-node-'
                    + provider_key(row["id"])
                    + '/">'
                    + e(row["name"])
                    + '</a><br><span class="mono">'
                    + e(row["id"])
                    + "</span></th><td>"
                    + e(row["name_kind"])
                    + "</td><td>"
                    + e(row["reported_status"] or "unknown")
                    + " · "
                    + e(report)
                    + "</td><td>"
                    + e(row["heartbeat_at"] or "unknown")
                    + "<br>"
                    + e(heartbeat)
                    + "</td><td>"
                    + (
                        "This Mac · " + e(alias)
                        if matched == row["id"]
                        else "not locally observed"
                    )
                    + "</td></tr>"
                )
            body += "</tbody></table></div>"
            if not shown:
                body += (
                    "<p>"
                    + (
                        "No records match this filter."
                        if rows
                        else "The account API returned no usable provider records; inspect connection and partial-coverage state above."
                    )
                    + "</p>"
                )
        body += "</section>"
    body += local_body
    body += '<p class="muted">Account metadata is private to the native app. The public loopback dashboard and existing export remain local-telemetry-only. Fleet reads use no financial, model-name or provider-control endpoints.</p>'
    return (
        page_start(
            "Your fleet · Gargoyl", extra_nav=navigation, badge="Private fleet manager"
        )
        + body
        + PAGE_END
    )
