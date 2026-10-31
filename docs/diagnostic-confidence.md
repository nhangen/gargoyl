# Diagnostic confidence from normalized evidence

The read-only dashboard separates local liveness/eligibility reports, coordinator
reachability/eligibility reports, and protocol confidence. It neither executes nor
recommends a restart from these observations. Missing evidence remains unknown.

## Evidence boundaries

| Area | Existing v1 evidence | What it establishes |
|---|---|---|
| Local process reports | `daemon_state`, `launchd_state` from local sources | Source-reported process state at its observation time; collector liveness alone supplies neither field. |
| Local eligibility/trust reports | Local `routing_eligible`, `attestation_state` | Reported eligibility or authorization, not successful dispatch or protocol compatibility. |
| Coordinator reports | Coordinator-source `coordinator_reachable`, `routing_eligible` | Their reported values and freshness; not protocol correctness or an overall healthy verdict. |
| Protocol confidence | No supported v1 compatibility field/adapter | Always unknown in this projection, even with reachable, eligible or `error_code=none` reports. |
| Coordinator diagnostic warnings | Coordinator-source normalized `error_code` observations | Retained current symptoms only; no raw text, error-event rate, root cause or restart authority. |
| Model and memory | `model_state`, `memory_pressure`, `memory_headroom_bytes` | Separate evidence; these symptoms do not explain coordinator warnings. |
| Traffic | Existing cumulative request/token observations | Counters, not failure or demand/routing diagnosis. Low or zero traffic is not classified as failure. |

All inputs cross existing v1 validation before projection. Per-source values,
observation/collection times, read-time freshness and original conflicting reports
remain visible. The detailed all-evidence table is a disclosure; no evidence is
removed. Existing collector/correlation incidents and repair safeguards are unchanged.

`build_dashboard` adds a derived `diagnostics` object per host: warning/unknown
state, canonical source observation times, fixed normalized codes, repeated
observations/unknown recurrence, and unknown protocol confidence/root cause. It
is presentation data, not a new telemetry field, availability score or repair plan.

## Repeated observations are not distinct errors

Only current observed `error_code` values other than `none`, explicitly sourced
as `coordinator`, contribute a warning. Duplicate collections of one observation
time count once, including equivalent UTC timestamp representations. Conflicting
reports at the same source time contribute no unambiguous observation. Stale,
unknown, blocked, future-observed or future-collected reports do not contribute.

Two or more distinct current source times mean **repeated observations**, not two
separate error events or a measured recurrence interval. A persistent last-error
value could be sampled repeatedly. A later `none` does not erase retained fresh
symptoms; the warning is explicitly not a current-service-failure verdict. No
qualifying errors means diagnostic detail is unknown, not an error-free connection.
Collector acquisition errors and doctor diagnostics are not reclassified as
coordinator errors. Warning state never enters repair preflight or triggers actions.

## Installed collection limitation

The local daemon-state reader currently normalizes counters and model-residency
claims only. It does not establish native provider liveness, routing eligibility,
coordinator connectivity, protocol compatibility or coordinator-error recurrence.
Its `error_code` describes the **collector source read**, not Darkbloom's protocol.
Consequently the running local view can have fresh counters and unknown local or
coordinator confidence. This change adds no collector, raw-log access, status/API
polling, credentials, permissions or upstream dependency. Fleet callers may already
supply additional supported normalized evidence; no synthetic evidence is inserted
into the live monitor.

## Motivation and attribution

Public third-party reports in Darkbloom issue400
([first report](https://github.com/Layr-Labs/d-inference/issues/400#issuecomment-6543399807),
[follow-up](https://github.com/Layr-Labs/d-inference/issues/400#issuecomment-6543856699))
describe v0.10.5 coordinator errors alongside reported authorization/eligibility,
low traffic and separate intermittent model-memory symptoms. The first reports
persistence across restart. These are user symptom reports, not a verified
protocol defect, a diagnosis of MBP-26, or proof of the cause of low traffic.
No frequency, report ID, hardware state or symptoms from those reports become
local telemetry. Gargoyl works with existing evidence without assuming an
upstream fix, provider restart or configuration workaround will resolve them.

## Verification

Controlled normalized fixtures exercise fresh/stale/unknown/conflicting/future
reports, local-vs-coordinator separation, repeated polling and equivalent UTC
times, warning coexistence with running/eligible reports, source errors, low/zero
traffic and separate model/memory symptoms. Raw error text and unsupported fields
remain rejected. Full integration, transport and monitor tests remain required;
fixtures do not establish a live coordinator fault or protocol compatibility.
