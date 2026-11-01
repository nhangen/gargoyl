# Read-only operator console

The live dashboard and local monitor reuse the visual language of `design/app/`:
dark/light system themes, an evidence legend, a host overview, attention items,
keyboard-focusable horizontal tables and per-host evidence anchors. The production
renderer consumes only the existing validated normalized projection. Prototype
host IDs, synthetic events, repair plans and audit history are never production
inputs. Source HTML remains labelled as a design prototype.

Every newest source is displayed separately; no source wins by presentation.
Effective evidence state and adverse reported value have separate visual channels
and explicit text. Unknown, stale, blocked, future-dated and conflicting reports
retain their existing semantics. The overview links to the full original
source/collection times, reported state, TTL, conflicts and usage evidence.
Attention lists collector incidents, mismatches, stale/blocked/conflicting reports,
explicit adverse values and normalized diagnostic warnings. An empty attention
list is not a health verdict; missing fields and protocol confidence remain unknown.
Heartbeat numbers are the reported age in seconds at the shown source timestamp,
not an independently measured uptime or continuous presence guarantee.

The local monitor keeps PR32's fresh contiguous counter-window comparison and
PR37's separately scoped coordinator-log metadata report. Counters are not earnings
or routing diagnosis. Visible error records do not prove root cause, outage or a
need to restart. Repairs remain disabled. Optional read-only process identity is
not operation-bound repair authorization or authoritative drain/replay safety.

There are no new HTTP routes, scripts, external resources, forms or repair controls.
The existing loopback Host/Origin/CSP and failure-to-503 behavior are preserved.
Host detail is an in-page anchor, not a new data-access endpoint. Existing repair
preview/receipt/audit pure renderers use the shared shell when explicitly called;
the local monitor does not load audit storage, invent repair history, or expose
those renderers as routes. Evaluation failures use the same shell and an explicit
unknown state; previous healthy output is never served as a fallback.

Run `python -m unittest discover -s tests -v` and `ruff check .`. Console tests
exercise per-source disagreement, stale/missing/blocked/conflicting evidence,
real anchor targets, absent prototype data, script/control/resource absence,
and the empty inventory. Runtime tests retain actual HTTP guards and stale/failure
semantics. Responsive browser verification uses an isolated ephemeral-loopback
preview with actual allowed state/native evidence and no extra log queries;
prototype fixtures must always remain distinct from live acceptance evidence.

Opt-in operator tools and a confirmed manual restart are described in
[operator tools](operator-tools.md); they add private routes only when enabled.

Installation does not enable any service. Stage a wheel before a separately
controlled monitor update; preserve its existing LaunchAgent arguments, IPv4
loopback binding and disabled repairs. No provider lifecycle action is needed.
