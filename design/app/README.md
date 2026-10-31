# Operator console: design prototype

Static, script-free HTML prototype of the Gargoyl operator console, built on
synthetic data. Open `index.html` in a browser. Nothing here is wired to the
evidence store; it's the target design for `gargoyl.dashboard` and
`gargoyl.repair_view`.

| Screen | File | Built on |
|---|---|---|
| Fleet overview | `index.html` | `build_dashboard`: latest evidence, incidents, comparisons, diagnostics |
| Host detail | `host.html` | the same projection for one host, with per-source evidence and history |
| Repair preview | `repair.html` | `RunbookCatalog.plan` / `render_preview`; the confirm step is a planned interaction |
| Audit history | `audit.html` | `render_receipt` / `render_audit_entry` |
| Unavailable | `unavailable.html` | the viewer's HTTP 503 state |

## Principles

- **Evidence, not verdicts.** No health score and no rolled-up host status. Each
  cell is one field from its newest report, as the contract defines it.
- **Two channels that never share meaning.** The glyph shows evidence state
  (filled dot observed, half-filled ring stale, dotted ring unknown, square
  blocked). A red outline marks an adverse *reported value* (ineligible,
  warning, expired…). A fresh "memory: warning" is a green dot with an outlined
  value, never a green "all good" pill.
- **Absence stays visible.** Missing reports read "no report" or "unknown";
  conflicts and mismatches are named and explained, with no source picked as
  authoritative.
- **Say what the evidence can't prove.** Protocol confidence is always
  unknown; agreement isn't dispatch; counters aren't earnings; outcomes are
  reported history.
- **Repairs are explicit and bounded.** Blocked runbooks list their missing
  prerequisites. Previews show digests, checks, evidence and a 60-second expiry.
  Confirmation is typed, single-use and bound to one host and one plan.

## Constraints carried from the viewer

The loopback viewer (`gargoyl/dashboard/runtime.py`) loads no scripts or
external resources, has no forms, and auto-refreshes every 1–60 s. The
prototype honours that: no JavaScript, system fonts only, `<details>` for
disclosure, and one shared stylesheet that can be inlined into the
renderer's `<style>`. The confirm form is styled but inert, and labelled as
planned until authenticated confirmation exists (epic #4).

Dark is the default; a light theme follows `prefers-color-scheme`. axe-core
(WCAG 2.2 AA plus best practices) reports no violations on any screen at 1440
and 390 px in either theme.

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
2. Re-render the existing sections with the `ev`, `st`, `callout` and `facts`
   patterns; content and wording already match `gargoyl/dashboard/__init__.py`.
3. Add the fleet overview as a new top-level projection, with one row per
   expected host.
4. Apply the same shell to `repair_view` pages; keep them control-free until
   confirmation is authenticated.
