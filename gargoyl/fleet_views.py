"""Private account inventory presentation. Never a provider-control surface."""

import re
from datetime import datetime
from html import escape

from gargoyl.dashboard import build_dashboard
from gargoyl.dashboard.theme import PAGE_END, page_start
from gargoyl.fleet_identity import matching_provider
from gargoyl.fleet_state import (
    TTL,
    evidence_state,
    provider_key,
    timestamp,
    validate_inventory,
)

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


def compact_time(value):
    return (
        datetime.fromisoformat(value.replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        )
        if value
        else None
    )


def e(value):
    return escape(str(value), quote=True)


HEARTBEAT_REASONS = {
    "not_reported": "Not reported",
    "unsupported_type": "Unsupported timestamp type",
    "invalid_timestamp": "Invalid timestamp",
}
LABEL_KINDS = {
    "source_name": "Source name",
    "hardware_label": "Hardware model",
    "provider_id": "Provider ID fallback",
}
# Evidence glyph per freshness word; the reported value is text beside it.
GLYPH = {"current": "ev-observed", "recent": "ev-observed", "stale": "ev-stale",
         "older": "ev-stale", "unknown": "ev-unknown"}
ADVERSE_STATUSES = {"offline", "stopped", "error", "failed", "unhealthy", "ineligible", "disconnected"}
FLEET_STYLE = (
    "<style>.fleet-inventory{min-width:860px}.fleet-inventory th[scope=row]{min-width:300px}"
    ".fleet-scroll-hint{display:none;font-size:12px;color:var(--text-faint)}"
    "@media(max-width:700px){.fleet-scroll-hint{display:block}}"
    ".fleet-keys{display:grid;gap:6px;font-size:12px;color:var(--text-muted)}"
    ".fleet-keys div{display:flex;flex-wrap:wrap;gap:10px;align-items:center}"
    ".fleet-keys b{color:var(--text);font-weight:600;min-width:74px}"
    ".fleet-adv-key{border:1px solid var(--mismatch);border-radius:4px;padding:0 5px}"
    ".fleet-filters{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0;padding:0;list-style:none;max-width:none}"
    ".fleet-filters li{margin:0}"
    ".fleet-filters a{display:inline-flex;gap:6px;align-items:center;padding:5px 12px;border-radius:999px;"
    "border:1px solid var(--line-strong);color:var(--text-muted);text-decoration:none;font-size:13px}"
    ".fleet-filters a[aria-current=page]{border-color:var(--text);color:var(--text);font-weight:600}"
    ".fleet-filters .n{font-family:var(--mono);font-size:12px;color:var(--text-faint)}"
    ".fleet-id{display:block;font-family:var(--mono);font-size:12px;color:var(--text-muted);"
    "margin-top:3px;overflow-wrap:anywhere;-webkit-user-select:all;user-select:all}"
    ".fleet-src,.fleet-sub{display:block;font-size:12px;color:var(--text-faint);margin-top:2px}"
    ".fleet-dup{display:block;font-size:12px;color:var(--stale);margin-top:2px}"
    ".fleet-here{display:inline-flex;padding:2px 8px;border-radius:999px;font-size:12px;"
    "font-weight:600;color:var(--accent-ink);background:var(--accent)}</style>"
)


def _age(seconds):
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} days"


def _heartbeat_cell(inventory, row, heartbeat):
    shown = compact_time(row["heartbeat_at"])
    if shown is None:
        reason = HEARTBEAT_REASONS.get(row.get("heartbeat_reason"), "Unknown cached evidence")
        return '<span class="ev ev-unknown">' + e(reason) + '</span><span class="fleet-sub">unknown</span>'
    sub = heartbeat
    gap = (timestamp(inventory["fetched_at"]) - timestamp(row["heartbeat_at"])).total_seconds()
    if gap >= 0:
        sub += " · " + _age(gap) + " before read"
    return ('<span class="ev ' + GLYPH[heartbeat] + ' mono">' + e(shown) + '</span><span class="fleet-sub">'
            + e(sub) + "</span>")


def _report_cell(row, report):
    status = row["reported_status"]
    text = e(status) if status else "status not reported"
    if status and status.lower() in ADVERSE_STATUSES:
        text = '<span class="adv">' + text + "</span>"
    return ('<span class="ev ' + GLYPH[report] + '">' + text + '</span><span class="fleet-sub">report '
            + e(report) + "</span>")


def render_fleet(
    view,
    inventory,
    evidence,
    local,
    alias,
    now,
    navigation,
    aliases=None,
    aliases_available=True,
):
    from gargoyl.fleet_aliases import validate_aliases

    aliases = validate_aliases(aliases or {})
    if not fleet_mode(view):
        raise ValueError("unsupported fleet view")
    if inventory is not None:
        validate_inventory(inventory)
    matched = matching_provider(inventory, local, now)
    body = (
        '<div class="page-head"><div><h1>Your fleet</h1><p>Provider records reported by your Darkbloom '
        "account. Coordinator reports and this Mac’s own observations stay separate. Nothing here controls "
        "remote machines or repairs anything.</p></div>"
        '<div class="fleet-keys" role="group" aria-label="Legend">'
        '<div><b>Report</b><span class="ev ev-observed">current</span><span class="ev ev-stale">stale</span>'
        '<span class="ev ev-unknown">unknown</span></div>'
        '<div><b>Heartbeat</b><span class="ev ev-observed">recent (≤ ' + str(TTL // 60) + ' min)</span>'
        '<span class="ev ev-stale">older</span><span class="ev ev-unknown">unknown</span></div>'
        '<div><b>Value</b><span><span class="fleet-adv-key">outlined</span> = adverse reported value</span></div>'
        "</div></div>"
    )
    if not aliases_available:
        body += '<div class="callout"><p>Local aliases unavailable. Actual provider IDs and source labels remain visible.</p></div>'
    local_body = (
        '<section id="this-mac" aria-labelledby="this-mac-title"><div class="section-head"><h2 id="this-mac-title">This Mac'
        + ("" if alias == "This Mac" else " · " + e(alias))
        + "</h2><p>Direct local observations, kept separate from the account report. This hostname is a "
        "local alias, not a provider name or ID.</p></div>"
    )
    facts = []
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
                facts.append((label, '<span class="ev ev-unknown">unknown</span> <span class="faint">· no report</span>'))
            for row in rows:
                state = row["state"] if row["state"] in ("observed", "stale", "unknown", "blocked") else "unknown"
                if row["value"] is None:
                    state = "unknown"
                facts.append((label, '<span class="ev ev-' + state + '">'
                              + e(row["value"] if row["value"] is not None else "unknown") + '</span> <span class="faint">'
                              + e(state) + " · " + e(row["source"]) + " · "
                              + e(compact_time(row["timestamp"]) or "unknown time") + "</span>"))
    facts.append((
        "Account association",
        ('<span class="mono">' + e(matched) + '</span><span class="fleet-sub">unique matching public identity</span>'
         if matched else "unknown — no fresh unique account identity match"),
    ))
    local_body += ('<dl class="facts">' + "".join("<div><dt>" + e(k) + "</dt><dd>" + v + "</dd></div>" for k, v in facts)
                   + "</dl></section>")
    if inventory is None:
        body += (
            "<section id='fleet-overview'><h2>Connect your account</h2><p>No verified account inventory is "
            "available. Choose <strong>Account → Connect fleet…</strong> in the toolbar, then complete "
            "Darkbloom’s read-only approval in your browser. No provider grant fallback is accepted.</p>"
            '<p class="muted">This is not an empty fleet result. Other machines have not been queried.</p></section>'
        )
    else:
        rows = inventory["providers"]
        count = str(len(rows)) + (" of " + str(inventory["reported_total"]) if inventory["reported_total"] is not None else "")
        body += (
            "<section id='fleet-overview' aria-labelledby='inventory-title'><div class='section-head'>"
            "<h2 id='inventory-title'>Owned provider inventory</h2><p>" + count + " reported records · read "
            + e(compact_time(inventory["fetched_at"])) + " · session last reported " + e(inventory["connection"])
            + ". This is account-reported inventory, not independent remote process verification.</p></div>"
        )
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
                body += (
                    "<h3>"
                    + e(aliases.get(row["id"], row["name"]))
                    + '</h3><dl class="facts">'
                )
                for label, value in [
                    ("Actual provider ID", row["id"]),
                    ("Local friendly alias", aliases.get(row["id"], "not set")),
                    ("Source label", row["name"]),
                    ("Label source", LABEL_KINDS[row["name_kind"]]),
                    ("Reported status", row["reported_status"] or "unknown"),
                    ("Report freshness", report),
                    ("Last heartbeat", compact_time(row["heartbeat_at"]) or "unknown"),
                    ("Heartbeat recency", heartbeat),
                    (
                        "Heartbeat evidence",
                        row.get("heartbeat_reason", "unclassified cached evidence"),
                    ),
                    (
                        "Heartbeat source field",
                        row.get("heartbeat_source", "unclassified cached evidence"),
                    ),
                    (
                        "Source fractional digits",
                        row.get("heartbeat_precision")
                        if row.get("heartbeat_precision") is not None
                        else "unknown",
                    ),
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
            states = {r["id"]: evidence_state(inventory, r, now) for r in rows}
            counts = {key: sum(1 for r in rows if FLEET_FILTERS[key] is None or states[r["id"]][1] == FLEET_FILTERS[key])
                      for key in FLEET_FILTERS}
            body += (
                '<nav aria-label="Fleet filters"><ul class="fleet-filters">'
                + "".join(
                    '<li><a href="gargoyl-view://' + key + '/"' + (' aria-current="page"' if key == view else "")
                    + ">" + label + ' <span class="n">' + str(counts[key]) + "</span></a></li>"
                    for key, label in [
                        ("fleet", "All records"),
                        ("fleet-recent", "Recent heartbeat"),
                        ("fleet-older", "Older heartbeat"),
                        ("fleet-unknown", "Unknown heartbeat"),
                    ]
                )
                + "</ul></nav>"
            )
            shown = [
                r
                for r in rows
                if FLEET_FILTERS[view] is None or states[r["id"]][1] == FLEET_FILTERS[view]
            ]
            labels = [aliases.get(r["id"], r["name"]) for r in rows]
            duplicated = {label for label in labels if labels.count(label) > 1}
            body += (
                '<p class="fleet-scroll-hint">Scroll the table sideways to see all evidence.</p>'
                '<div class="table-wrap" tabindex="0" role="region" aria-label="Account provider inventory">'
                '<table class="fleet-inventory"><thead><tr><th scope="col">Provider</th><th scope="col">Coordinator report</th>'
                '<th scope="col">Last heartbeat</th><th scope="col">Version</th><th scope="col">This Mac</th></tr></thead><tbody>'
            )
            for row in shown:
                report, heartbeat = states[row["id"]]
                label = aliases.get(row["id"], row["name"])
                kind = LABEL_KINDS[row["name_kind"]]
                source = (
                    "Local alias · " + kind.lower() + " “" + row["name"] + "”"
                    if row["id"] in aliases
                    else kind
                )
                body += (
                    '<tr><th scope="row"><a href="gargoyl-view://fleet-node-' + provider_key(row["id"]) + '/">'
                    + e(label) + '</a><span class="fleet-id">' + e(row["id"]) + '</span><span class="fleet-src">'
                    + e(source) + "</span>"
                    + ('<span class="fleet-dup">Same label as another record. Use Local aliases… in the toolbar to tell them apart.</span>'
                       if label in duplicated else "")
                    + "</th><td>" + _report_cell(row, report) + "</td><td>" + _heartbeat_cell(inventory, row, heartbeat)
                    + '</td><td>' + ('<span class="mono">' + e(row["version"]) + "</span>" if row["version"] else '<span class="faint">not reported</span>') + "</td><td>"
                    + ('<span class="fleet-here">This Mac</span><span class="fleet-sub">' + e(alias)
                       + " · unique identity match</span>" if matched == row["id"]
                       else '<span class="faint">not locally observed</span>')
                    + "</td></tr>"
                )
            body += "</tbody></table></div>"
            if not shown:
                body += (
                    "<p>"
                    + (
                        "No records match this filter."
                        if rows
                        else "The account API returned no usable provider records; check connection and partial coverage above."
                    )
                    + "</p>"
                )
            body += '<p class="muted">Aliases stay on this Mac. They never rename source records or change identity matching or action targets.</p>'
        body += "</section>"
    body += local_body
    body += (
        '<section id="needs-attention" aria-labelledby="limits-title"><h2 id="limits-title">Coverage and limits</h2>'
        '<p class="muted">Missing or older reports need fresh evidence; no health is inferred from them. Account status '
        "is a coordinator report, not independent remote health. No repair is inferred. Account metadata is private "
        "to the Mac app: the public loopback dashboard and existing export remain local-telemetry-only, and fleet "
        "reads use no financial, model-name or provider-control endpoints.</p></section>"
    )
    html = (
        page_start(
            "Your fleet · Gargoyl", extra_nav=navigation, badge="Private fleet manager"
        )
        + body
        + PAGE_END
    )
    return html.replace("</head>", FLEET_STYLE + "</head>", 1)
