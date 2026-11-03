"""Offline synthetic evidence of production label semantics; never live acceptance.

Builds synthetic host scenarios (missing/offline host, stale snapshot, clock skew
against a supplied reference time, coordinator disagreement), runs them through the
production collector, v1 telemetry encode/decode and dashboard projection/rendering
entry paths at a fixed reference time, and asserts hand-computed effective labels. Artifacts are
statically marked OFFLINE FIXTURE SOFTWARE EVIDENCE; no health inference, provider
action, network use or real fleet status is produced or implied. Exit nonzero if any
effective label deviates from the hand-computed expectation.
"""

import argparse
import json
import sys
from pathlib import Path

# A script starts with tools/ on sys.path; prioritize this checkout, never a stale
# editable installation elsewhere in the shared development environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gargoyl.collector import collect
from gargoyl.dashboard import build_dashboard, render_dashboard
from gargoyl.telemetry import decode_snapshot, encode_snapshot

MARKER = "OFFLINE FIXTURE SOFTWARE EVIDENCE"
NOTE = (
    MARKER + ": synthetic, machine-generated records of production label semantics at a fixed "
    "reference time. Not live acceptance evidence, not a screenshot, and not real "
    "fleet status. Missing host evidence stays unknown; scenarios imply no health, "
    "no diagnosis and no pilot acceptance."
)
REFERENCE_TIME = "2026-11-03T00:00:00Z"
LATER_EVALUATION = "2026-11-03T00:05:00Z"
MISSING_HOST = "00000000-0000-4000-8000-00000000000a"
STALE_HOST = "00000000-0000-4000-8000-00000000000b"
SKEW_HOST = "00000000-0000-4000-8000-00000000000c"
DISAGREE_HOST = "00000000-0000-4000-8000-00000000000d"
CORRELATED = ("daemon_state", "routing_eligible", "attestation_state", "model_state")
MEASURED_SKEW_SECONDS = 300


def check(records, label, expected, actual):
    matched = expected == actual
    records.append({"label": label, "expected": expected, "actual": actual, "matched": matched})


def missing_offline_host():
    snapshots, host, evaluated = [], MISSING_HOST, REFERENCE_TIME
    dashboard = build_dashboard(snapshots, [host], evaluated)
    page = render_dashboard(snapshots, [host], evaluated)
    records = []
    check(records, "host_appears_without_evidence", [MISSING_HOST],
          [host_id for host_id in (h["host_id"] for h in dashboard["hosts"])])
    check(records, "incidents", ["missing_collector_heartbeat"], dashboard["hosts"][0]["incidents"])
    check(records, "correlation_states_unknown", {m: "unknown" for m in CORRELATED},
          {c["metric"]: c["state"] for c in dashboard["hosts"][0]["comparisons"]})
    check(records, "expected_host_has_no_metric_reports", True,
          all(dashboard["hosts"][0]["latest"][metric] == [] for metric in dashboard["hosts"][0]["latest"]))
    check(records, "render_shows_unknown_no_report", True, "unknown · No report" in page)
    check(records, "render_keeps_missing_host_visible", True, MISSING_HOST in page)
    return snapshots, host, evaluated, dashboard, page, records


def stale_snapshot():
    snapshots = [collect(STALE_HOST, REFERENCE_TIME, {})]
    host, evaluated = STALE_HOST, LATER_EVALUATION
    dashboard = build_dashboard(snapshots, [host], evaluated)
    page = render_dashboard(snapshots, [host], evaluated)
    latest = dashboard["hosts"][0]["latest"]
    records = []
    check(records, "collector_heartbeat_incident_after_ttl",
          ["collector_heartbeat_not_current"], dashboard["hosts"][0]["incidents"])
    check(records, "heartbeat_effective_state", "stale", latest["heartbeat_age_seconds"][0]["state"])
    check(records, "unknown_report_becomes_stale_after_ttl", "stale", latest["daemon_state"][0]["state"])
    check(records, "reported_state_is_preserved", "unknown", latest["daemon_state"][0]["reported_state"])
    check(records, "render_shows_stale_glyph", True, "ev ev-stale" in page)
    return snapshots, host, evaluated, dashboard, page, records


def clock_skew_reference():
    snapshots = [collect(SKEW_HOST, LATER_EVALUATION, {}, reference_time=REFERENCE_TIME)]
    host, evaluated = SKEW_HOST, REFERENCE_TIME
    dashboard = build_dashboard(snapshots, [host], evaluated)
    page = render_dashboard(snapshots, [host], evaluated)
    records = []
    check(records, "skew_measured_against_supplied_reference", MEASURED_SKEW_SECONDS,
          snapshots[0]["fields"]["clock_skew_seconds"]["value"])
    check(records, "future_collected_reports_all_unknown", True,
          all(item["state"] == "unknown"
              for items in dashboard["hosts"][0]["latest"].values() for item in items))
    check(records, "collector_heartbeat_not_current",
          ["collector_heartbeat_not_current"], dashboard["hosts"][0]["incidents"])
    check(records, "collected_at_preserved", LATER_EVALUATION, snapshots[0]["collected_at"])
    check(records, "render_shows_unknown_glyph", True, "ev ev-unknown" in page)
    return snapshots, host, evaluated, dashboard, page, records


def coordinator_disagreement():
    local = collect(DISAGREE_HOST, REFERENCE_TIME, {
        "daemon_state": {"value": "running", "source": "daemon", "timestamp": REFERENCE_TIME,
                         "freshness_seconds": 300, "state": "observed", "sensitivity": "safe"}})
    first = {"schema_version": 1, "host_id": DISAGREE_HOST, "collected_at": REFERENCE_TIME,
             "fields": {
                 "daemon_state": {"value": "stopped", "source": "coordinator", "timestamp": REFERENCE_TIME,
                                  "freshness_seconds": 300, "state": "observed", "sensitivity": "safe"},
                 "routing_eligible": {"value": "eligible", "source": "coordinator", "timestamp": REFERENCE_TIME,
                                      "freshness_seconds": 300, "state": "observed", "sensitivity": "safe"}}}
    second = {"schema_version": 1, "host_id": DISAGREE_HOST, "collected_at": REFERENCE_TIME,
              "fields": {
                  "routing_eligible": {"value": "ineligible", "source": "coordinator", "timestamp": REFERENCE_TIME,
                                       "freshness_seconds": 300, "state": "observed", "sensitivity": "safe"}}}
    snapshots = [local, decode_snapshot(encode_snapshot(first)), decode_snapshot(encode_snapshot(second))]
    host, evaluated = DISAGREE_HOST, REFERENCE_TIME
    dashboard = build_dashboard(snapshots, [host], evaluated)
    page = render_dashboard(snapshots, [host], evaluated)
    conflict = dashboard["hosts"][0]["latest"]["routing_eligible"][0]
    comparisons = {c["metric"]: c["state"] for c in dashboard["hosts"][0]["comparisons"]}
    records = []
    check(records, "same_source_conflict_stays_unknown", "unknown", conflict["state"])
    check(records, "conflicting_value_not_resolved", None, conflict["value"])
    check(records, "conflicting_originals_preserved", ["eligible", "ineligible"],
          sorted(item["value"] for item in conflict["conflicting_observations"]))
    check(records, "coordinator_report_unresolved", "unknown", comparisons["routing_eligible"])
    check(records, "local_coordinator_report_mismatch", "mismatch", comparisons["daemon_state"])
    check(records, "mismatch_incident_recorded", ["daemon_state_mismatch"], dashboard["hosts"][0]["incidents"])
    check(records, "render_preserves_conflict_evidence", True,
          "routing_eligible: unknown — conflicting observations" in page)
    check(records, "render_marks_adverse_reported_value", True,
          "daemon_state: adverse reported value stopped" in page)
    return snapshots, host, evaluated, dashboard, page, records


SCENARIOS = (
    ("missing_offline_host", missing_offline_host),
    ("stale_snapshot", stale_snapshot),
    ("clock_skew_reference", clock_skew_reference),
    ("coordinator_disagreement", coordinator_disagreement),
)


def write_text(path, text):
    with path.open("w", encoding="utf-8") as stream:
        stream.write(text)
        stream.write("\n")


def banner():
    return '<div class="callout warn"><p><strong>' + MARKER + "</strong><br>" + NOTE + "</p></div>"


def build_artifacts(out):
    scenarios, all_matched = {}, True
    for name, build in SCENARIOS:
        snapshots, host, evaluated, dashboard, page, records = build()
        scenarios[name] = {
            "scenario": name,
            "evaluated_at": evaluated,
            "host_ids": [host],
            "snapshots": [encode_snapshot(snapshot).decode("utf-8") for snapshot in snapshots],
            "projected": dashboard,
            "checks": records,
            "all_matched": all(record["matched"] for record in records),
        }
        all_matched = all_matched and scenarios[name]["all_matched"]
        write_text(out / (name + ".html"),
                   page.replace("<h1>Fleet evidence</h1>", banner() + "<h1>Fleet evidence</h1>", 1))
    evidence = {"marker": MARKER, "note": NOTE, "reference_time": REFERENCE_TIME,
                "scenarios": scenarios, "all_matched": all_matched}
    write_text(out / "offline_acceptance_evidence.json", json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return scenarios, all_matched


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="directory for offline fixture artifacts")
    args = parser.parse_args(argv)
    out = Path(args.out)
    if out.exists() and not out.is_dir():
        print("Output path must be a directory; artifacts not written.", file=sys.stderr)
        return 2
    try:
        out.mkdir(parents=True, exist_ok=True)
        scenarios, all_matched = build_artifacts(out)
    except OSError as error:
        print("Offline fixture artifacts unavailable:", error, file=sys.stderr)
        return 2
    directory = out.resolve()
    if all_matched:
        print(f"{MARKER} scenarios match hand-computed labels; artifacts written under {directory}")
        return 0
    for scenario in scenarios.values():
        for record in scenario["checks"]:
            if not record["matched"]:
                print(f"mismatch [{scenario['scenario']}] {record['label']}: "
                      f"expected {record['expected']!r}, got {record['actual']!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
