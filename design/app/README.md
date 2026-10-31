# Operator console: design prototype

Static, script-free HTML prototype of the Gargoyl operator console, built on
synthetic data. Open `index.html` in a browser. Nothing here is wired to the
evidence store; it's the target design for `gargoyl.dashboard` and
`gargoyl.repair_view`.

| Screen | File | Built on |
|---|---|---|
| Fleet overview | `index.html` | `build_dashboard`: latest evidence, incidents, comparisons, diagnostics |
| Host detail | `host-71aa.html` | one host with a local / coordinator mismatch and a diagnostic warning |
| Host, no heartbeat | `host-e5c2.html` | an expected host with no retained reports |
| Host, conflicting reports | `host-9d40.html` | same-source, same-time reports that disagree |
| Host, repair needing recovery | `host-3f9a.html` | fresh evidence alongside an outcome-unknown repair |
| Host, stale report | `host-b07d.html` | a current heartbeat with one stale field |
| Repair preview | `repair.html` | `RunbookCatalog.plan` / `render_preview`; the confirmation is a labelled mock-up |
| Audit history | `audit.html` | `render_receipt` / `render_audit_entry` |
| Unavailable | `unavailable.html` | the viewer's HTTP 503 state |

## Principles

- **Evidence, not verdicts.** No health score and no rolled-up host status. Each
  cell is one field from its newest report, as the contract defines it.
- **Two channels that never share meaning.** The glyph shows evidence state
  (filled dot observed, half-filled ring stale, dotted ring unknown, square
  blocked). A red outline marks an adverse *reported value* (ineligible,
  warning, expired…). A fresh "memory: warning" is a green dot with an outlined
  value, never a green "all good" pill. Blocked has its own violet, so the
  two channels never share a colour.
- **Absence stays visible.** Missing reports read "no report" or "unknown";
  conflicts and mismatches are named and explained, with no source picked as
  authoritative.
- **Say what the evidence can't prove.** Protocol confidence is always
  unknown; agreement isn't dispatch; counters aren't earnings; outcomes are
  reported history.
- **Repairs are explicit and bounded.** Three runbooks are blocked in v1
  whatever evidence exists, and say why. Previews show digests, checks,
  evidence and a 60-second expiry. Confirmation is single-use and bound to one
  host and one plan; typing the host prefix is a proposal, not something the
  contract implements.

## Constraints carried from the viewer

The loopback viewer (`gargoyl/dashboard/runtime.py`) loads no scripts or
external resources, has no forms, serves only `GET /`, and auto-refreshes
every 1–60 s. The prototype honours that: no JavaScript, system fonts only,
`<details>` for disclosure, and one shared stylesheet that can be inlined into
the renderer's `<style>`. The confirmation is a non-interactive mock-up until
authenticated confirmation exists (epic #4). Repair and audit pages say they
don't auto-refresh: re-rendering a plan someone is confirming would change it.

Dark is the default; a light theme follows `prefers-color-scheme`. During
design, axe-core (WCAG 2.2 AA plus best practices) reported no violations on
any screen at 1440 and 390 px in either theme. That check isn't automated in
CI.

Every page carries a "Design prototype · synthetic data" banner, and every
fleet row links to its host page.

## Open questions

- **Host labels:** operators will want names, but the contract rejects
  hostnames. A local-only alias stored on the viewer's machine would help.
- **Fleet scale:** the table suits the pilot's 3–16 hosts; larger fleets need
  sorting and filtering, which needs server-side query parameters (no JS).
- **Time display:** everything is UTC with a `Z` suffix. Add relative ages
  ("43 m ago") beside timestamps everywhere, or only for freshness?

## Porting

1. Inline `app.css` into `render_dashboard`'s `<style>`, replacing the current
   light table styles.
2. Re-render the existing per-host sections with the `ev`, `st`, `callout` and
   `facts` patterns. Most wording follows `gargoyl/dashboard/__init__.py`; the
   fleet table, the "Needs attention" list and the counter-reset label are new
   and need projection support.
3. Add the fleet overview as a new top-level projection, with one row per
   expected host, and surface audit entries needing recovery in it.
4. Multi-page navigation needs new read-only viewer routes (host, audit). The
   `repair_view` renderers add no routes today.
5. Apply the same shell to `repair_view` pages; keep them control-free until
   confirmation is authenticated.

## Live integration

The production single-page renderer now ports this shell and evidence vocabulary;
see [operator console](../../docs/operator-console.md). It uses validated real
normalized evidence, anchored host details and existing read-only HTTP boundaries.
These static pages remain synthetic design references, not runtime data sources.
Multi-page routes and authenticated confirmation remain outside this integration.
