"""Self-contained operator-console styling, adapted from design/app. No assets or I/O."""

STYLE = r"""/* Gargoyl operator console: design prototype styles.
   No scripts: everything here must survive a server-rendered, script-free viewer. */

:root {
  --bg: #0c0e0d;
  --surface: #121514;
  --surface-2: #181c1a;
  --line: #262b29;
  --line-strong: #353b38;
  --text: #e7ebe8;
  --text-muted: #a3aca7;
  --text-faint: #8a948e;
  --accent: #3ee67f;
  --accent-ink: #06210f;
  --focus: #3ee67f;

  --observed: #3ee67f;
  --observed-soft: rgba(62, 230, 127, 0.1);
  --stale: #e8b04b;
  --stale-soft: rgba(232, 176, 75, 0.1);
  --unknown: #a3aca7;
  --unknown-soft: rgba(163, 172, 167, 0.1);
  --blocked: #c4a1f5;
  --blocked-soft: rgba(196, 161, 245, 0.12);
  --mismatch: #f08a7a;
  --mismatch-soft: rgba(240, 138, 122, 0.1);
  --selection: rgba(62, 230, 127, 0.28);
  --info: #8ab4f8;
  --info-soft: rgba(138, 180, 248, 0.1);

  --sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
  --radius: 8px;
  color-scheme: dark;
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f7f5;
    --surface: #ffffff;
    --surface-2: #f0f2ef;
    --line: #e1e5e1;
    --line-strong: #c9cfca;
    --text: #141816;
    --text-muted: #4d5651;
    --text-faint: #5f6863;
    --accent: #11823f;
    --accent-ink: #ffffff;
    --focus: #11823f;
    --observed: #0b6b32;
    --observed-soft: rgba(17, 130, 63, 0.09);
    --stale: #8a5a00;
    --stale-soft: rgba(176, 116, 0, 0.1);
    --unknown: #4d5651;
    --unknown-soft: rgba(77, 86, 81, 0.08);
    --blocked: #6d3ab0;
    --blocked-soft: rgba(109, 58, 176, 0.09);
    --mismatch: #b3321f;
    --mismatch-soft: rgba(179, 50, 31, 0.08);
    --selection: rgba(17, 130, 63, 0.2);
    --info: #2357b5;
    --info-soft: rgba(35, 87, 181, 0.08);
    color-scheme: light;
  }
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 var(--sans);
  -webkit-font-smoothing: antialiased;
}
::selection { background: var(--selection); }
a { color: inherit; text-underline-offset: 3px; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; border-radius: 4px; }
h1, h2, h3 { margin: 0; letter-spacing: -0.01em; }
p { margin: 0; }
code, .mono { font-family: var(--mono); font-size: 0.8125rem; font-variant-numeric: tabular-nums; }
.muted { color: var(--text-muted); }
.faint { color: var(--text-faint); }
.sr-only {
  position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.skip-link {
  position: absolute; left: 12px; top: -48px; z-index: 10; padding: 8px 12px;
  background: var(--accent); color: var(--accent-ink); border-radius: 6px; font-weight: 600; text-decoration: none;
}
.skip-link:focus { top: 8px; }

/* Shell */

.shell { display: grid; min-height: 100vh; grid-template-columns: minmax(0, 1fr); grid-template-rows: auto auto 1fr; }
@media (min-width: 1000px) {
  .shell { grid-template-columns: 216px minmax(0, 1fr); grid-template-rows: auto 1fr; }
  .topbar { grid-column: 1 / -1; }
}

.topbar {
  position: sticky; top: 0; z-index: 5;
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px 20px;
  padding: 10px 20px;
  background: var(--bg);
  border-bottom: 1px solid var(--line);
}
.brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 700; font-size: 15px; text-decoration: none; }
.brand svg { width: 20px; height: 20px; }
.brand-eyes { fill: var(--accent); }
.asof {
  display: flex; flex-wrap: wrap; align-items: center; gap: 4px 14px;
  margin-left: auto;
  color: var(--text-muted);
  font-size: 12.5px;
}
.asof strong { color: var(--text); font-weight: 600; }
.pill {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 1px 8px; border: 1px solid var(--line-strong); border-radius: 999px;
  font-size: 12px; color: var(--text-muted); white-space: nowrap;
}

.nav { border-bottom: 1px solid var(--line); }
.nav ul { display: flex; gap: 4px; margin: 0; padding: 6px 12px; list-style: none; overflow-x: auto; }
.nav a {
  display: flex; align-items: center; gap: 10px;
  min-height: 36px; padding: 0 12px; border-radius: 6px;
  color: var(--text-muted); text-decoration: none; white-space: nowrap;
}
.nav a:hover { background: var(--surface-2); color: var(--text); }
.nav a[aria-current] { background: var(--surface-2); color: var(--text); font-weight: 600; }
.nav .count { margin-left: auto; color: var(--text-faint); font-size: 12px; }
@media (min-width: 1000px) {
  .nav { border-bottom: 0; border-right: 1px solid var(--line); }
  .nav ul { flex-direction: column; padding: 16px 12px; position: sticky; top: 52px; }
}

main { min-width: 0; padding: 24px 20px 64px; }
@media (min-width: 1000px) { main { padding: 28px 36px 72px; } }
.page-head { display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between; gap: 12px 24px; margin-bottom: 20px; }
.page-head h1 { font-size: 22px; font-weight: 680; }
.page-head p { margin-top: 4px; color: var(--text-muted); max-width: 72ch; }
.crumbs { margin-bottom: 6px; color: var(--text-faint); font-size: 12.5px; }
.crumbs a { color: var(--text-muted); }

section + section { margin-top: 32px; }
.section-head { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 4px 16px; margin-bottom: 10px; }
.section-head h2 { font-size: 15px; font-weight: 650; }
.section-head p { color: var(--text-muted); font-size: 13px; max-width: 80ch; }

/* State tokens: color + glyph shape + text, never color alone */

.st {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 1px 8px 1px 7px; border-radius: 999px;
  font-family: var(--mono); font-size: 12px; font-weight: 500; white-space: nowrap;
}
.st::before { content: ""; width: 7px; height: 7px; flex: none; }
.st-observed { color: var(--observed); background: var(--observed-soft); }
.st-observed::before { border-radius: 50%; background: currentColor; }
.st-stale { color: var(--stale); background: var(--stale-soft); }
.st-stale::before { border-radius: 50%; border: 1.5px solid currentColor; background: linear-gradient(90deg, currentColor 50%, transparent 50%); }
.st-unknown { color: var(--unknown); background: var(--unknown-soft); }
.st-unknown::before { border-radius: 50%; border: 1.5px dotted currentColor; }
.st-blocked { color: var(--blocked); background: var(--blocked-soft); }
.st-blocked::before { border-radius: 1px; background: currentColor; }
.st-agreement { color: var(--observed); background: var(--observed-soft); }
.st-agreement::before { content: "="; width: auto; height: auto; }
.st-mismatch { color: var(--mismatch); background: var(--mismatch-soft); }
.st-mismatch::before { content: "≠"; width: auto; height: auto; }
.st-warning { color: var(--stale); background: var(--stale-soft); }
.st-warning::before { content: "!"; width: auto; height: auto; font-weight: 700; }
.st-info { color: var(--info); background: var(--info-soft); }
.st-failed { color: var(--mismatch); background: var(--mismatch-soft); }
.st-failed::before { content: "×"; width: auto; height: auto; font-weight: 700; }
.st-info::before { display: none; }

/* Evidence cells: the glyph (shape and colour) shows evidence state; the text is the
   reported value. A red outline marks an adverse reported value. Blocked uses its own
   violet so the two channels never share a colour. */
.ev { display: inline-flex; align-items: center; gap: 7px; font-family: var(--mono); font-size: 12.5px; white-space: nowrap; }
.ev::before { content: ""; width: 8px; height: 8px; flex: none; }
.ev-observed::before { border-radius: 50%; background: var(--observed); }
.ev-stale::before { border-radius: 50%; border: 1.5px solid var(--stale); background: linear-gradient(90deg, var(--stale) 50%, transparent 50%); }
.ev-stale { color: var(--text-muted); }
.ev-unknown::before { border-radius: 50%; border: 1.5px dotted var(--unknown); }
.ev-unknown { color: var(--text-muted); }
.ev-blocked::before { border-radius: 1px; background: var(--blocked); }
.adv { padding: 0 6px; border: 1px solid var(--mismatch); border-radius: 4px; color: var(--text); font-weight: 600; }
.ev .adv { margin-left: -1px; }

.legend { display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: center; color: var(--text-muted); font-size: 12.5px; }

/* Attention list */

.attention { border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
.attention li { display: grid; grid-template-columns: minmax(0, 1fr); justify-items: start; gap: 4px 12px; padding: 12px 16px; border-top: 1px solid var(--line); }
.attention li:first-child { border-top: 0; }
.attention ul { margin: 0; padding: 0; list-style: none; }
.attention .what { font-weight: 600; }
.attention .why { color: var(--text-muted); font-size: 13px; }
.attention .go { margin-top: 6px; }
@media (min-width: 760px) {
  .attention li { grid-template-columns: 130px minmax(0, 1fr) auto; align-items: baseline; justify-items: stretch; }
  .attention li > .st { justify-self: start; }
  .attention .why { grid-column: 2; }
  .attention .go { grid-column: 3; grid-row: 1 / span 2; align-self: center; margin-top: 0; }
}

/* Tables */

.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
table { width: 100%; border-collapse: collapse; }
caption { text-align: left; }
th, td { padding: 9px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
tbody tr:last-child > * { border-bottom: 0; }
thead th {
  background: var(--surface-2);
  color: var(--text-muted); font-size: 12px; font-weight: 600; white-space: nowrap;
}
tbody th { font-weight: 500; }
td .sub { display: block; margin-top: 2px; color: var(--text-faint); font-size: 12px; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.nowrap { white-space: nowrap; }

.fleet td, .fleet th { white-space: nowrap; }
.fleet tbody tr:hover > * { background: var(--surface-2); }
.fleet tbody th, .fleet thead th:first-child { position: sticky; left: 0; z-index: 1; background: var(--surface); box-shadow: 1px 0 0 var(--line); }
.fleet thead th:first-child { background: var(--surface-2); z-index: 2; }
.fleet .host a { font-family: var(--mono); font-size: 13px; font-weight: 600; text-decoration: none; }
.fleet .host a:hover { text-decoration: underline; }
.pair { display: inline-flex; gap: 6px; align-items: center; }
.pair .sep { color: var(--text-faint); font-size: 12px; }
.cell-note { display: block; margin-top: 3px; color: var(--text-faint); font-size: 12px; font-family: var(--sans); }

/* Callouts */

.callout {
  display: grid; gap: 4px;
  padding: 12px 16px; border: 1px solid var(--line);
  border-radius: var(--radius); background: var(--surface);
}
.callout-title { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-weight: 600; }
.callout p { color: var(--text-muted); font-size: 13px; }
.callout.warn { background: linear-gradient(var(--stale-soft), var(--stale-soft)), var(--surface); border-color: var(--stale); border-color: color-mix(in srgb, var(--stale) 35%, var(--line)); }
.callout.danger { background: linear-gradient(var(--mismatch-soft), var(--mismatch-soft)), var(--surface); border-color: var(--mismatch); border-color: color-mix(in srgb, var(--mismatch) 35%, var(--line)); }
.stack { display: grid; gap: 12px; }

/* Key-value facts */

.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--line); overflow: hidden; }
.facts div { padding: 10px 14px; background: var(--surface); min-width: 0; }
.facts dt { color: var(--text-faint); font-size: 12px; }
.facts dd { margin: 2px 0 0; overflow-wrap: anywhere; }

.grid-2 { display: grid; gap: 20px; }
@media (min-width: 1200px) { .grid-2 { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); } }

details { border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
details + details { margin-top: 10px; }
summary { display: flex; align-items: center; gap: 10px; min-height: 44px; padding: 0 14px; cursor: pointer; font-weight: 600; }
summary::-webkit-details-marker { display: none; }
summary::before { content: "▸"; color: var(--text-faint); transition: transform 0.15s; }
details[open] > summary::before { transform: rotate(90deg); }
details > .body { padding: 0 14px 14px; display: grid; gap: 10px; }
details > .body .table-wrap { border-radius: 6px; }

/* Repair */

.runbooks { display: grid; gap: 1px; margin: 0; padding: 0; list-style: none; border: 1px solid var(--line); border-radius: var(--radius); background: var(--line); }
.runbooks > li:first-child, .runbooks > li:first-child > .runbook { border-radius: 7px 7px 0 0; }
.runbooks > li:last-child, .runbooks > li:last-child > .runbook { border-radius: 0 0 7px 7px; }
.runbook:focus-visible { outline-offset: -2px; }
.runbook { display: grid; gap: 4px 16px; padding: 12px 16px; background: var(--surface); text-decoration: none; }
a.runbook:hover { background: var(--surface-2); }
.runbook[aria-current="true"] { background: var(--surface-2); box-shadow: inset 2px 0 0 var(--accent); }
.runbook .name { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-weight: 600; }
.runbook .desc { color: var(--text-muted); font-size: 13px; }
.runbook .st, .callout-title .st { justify-self: start; }
@media (min-width: 760px) { .runbook { grid-template-columns: minmax(0, 1fr) auto; align-items: center; } .runbook .desc { grid-column: 1; } .runbook .st { grid-column: 2; grid-row: 1 / span 2; } }

.confirm {
  display: grid; gap: 12px;
  padding: 16px; border: 1px dashed var(--line-strong); border-radius: var(--radius); background: var(--surface);
}
.confirm { margin: 0; }
.confirm .confirm-title { font-weight: 600; }
.mock { display: inline-flex; align-items: center; cursor: default; }
.input.mock { color: var(--text-muted); }
.btn.mock { border-style: dashed; color: var(--text-muted); }
.confirm .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.input {
  min-height: 40px; width: 12ch; padding: 0 10px;
  border: 1px solid var(--line-strong); border-radius: 6px; background: var(--bg); color: var(--text);
  font: 14px var(--mono);
}
.btn {
  display: inline-flex; align-items: center; min-height: 40px; padding: 0 16px;
  border-radius: 6px; border: 1px solid var(--line-strong); background: transparent; color: var(--text);
  font: 600 14px var(--sans); text-decoration: none;
}
.planned-tag { color: var(--info); font-size: 12px; font-weight: 600; }

.countdown { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.digest { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }

/* Unavailable */

.unavailable { max-width: 560px; margin: 10vh auto 0; display: grid; gap: 14px; }
.unavailable h1 { font-size: 22px; }

footer.page-foot { margin-top: 40px; color: var(--text-faint); font-size: 12.5px; max-width: 90ch; }

/* Live evidence adaptation: anchored single-page navigation; no prototype data. */
.topbar { position: static; }
main { min-width: 0; }
main > p { margin: 12px 0; max-width: 75ch; }
main > section, .host-evidence { margin: 28px 0; }
h1 { font-size: 28px; margin-bottom: 8px; }
h2 { font-size: 20px; margin-bottom: 12px; }
h3 { font-size: 16px; margin: 28px 0 10px; }
section > p, details > p, details > ul { margin: 10px 0; max-width: 75ch; }
.scroll { overflow-x: auto; margin: 12px 0; border: 1px solid var(--line); border-radius: var(--radius); background: var(--surface); }
.scroll th, .scroll td { min-width: 120px; overflow-wrap: anywhere; }
.scroll th:first-child { min-width: 150px; }
.scroll:focus-visible, .table-wrap:focus-visible { outline-offset: -3px; }
.ev-line { display: block; margin: 5px 0; }
.ev-line .ev { white-space: normal; }
.ev-line small { display: block; margin: 3px 0 8px 15px; color: var(--text-muted); }
.host-id { overflow-wrap: anywhere; }
.host-evidence { border-top: 1px solid var(--line-strong); padding-top: 28px; }
.attention li { display: block; }
.attention li a { font-family: var(--mono); }
.attention li p { margin-top: 4px; color: var(--text-muted); }
.evidence-legend { margin: 16px 0 24px; }
.local-summary { padding: 16px 0; border-top: 1px solid var(--line); }
.local-summary p { margin: 10px 0; max-width: 75ch; }
@media (max-width: 600px) { main { padding: 20px 14px; } .topbar { padding: 12px 14px; } .host-evidence h2 { font-size: 18px; } }
.jump-link { display: inline-flex; align-items: center; min-height: 44px; padding: 0 14px; margin-bottom: 8px; border: 1px solid var(--line-strong); border-radius: 6px; font-weight: 600; text-decoration: none; }
.jump-link:hover { background: var(--surface-2); }
#fleet-overview, #needs-attention { scroll-margin-top: 12px; }
@media (min-width: 1000px) { .jump-link { display: none; } }
.btn { cursor: pointer; }
button.btn { font: 600 14px var(--sans); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--accent-ink); }
.tool-form { display: inline-flex; margin: 0; }
.tool-result { margin-top: 8px; }
.tool-result small { display: block; color: var(--text-faint); }
.confirm label { font-weight: 600; }
.callout { margin: 12px 0; }
.btn { white-space: nowrap; }
.btn-danger { background: transparent; border-color: var(--mismatch); color: var(--text); }
.btn-danger:hover { background: var(--mismatch-soft); }
.tool-list { list-style: none; margin: 12px 0; padding: 0; display: grid; gap: 1px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--line); }
.tool { display: grid; gap: 8px 16px; padding: 14px 16px; background: var(--surface); }
.tool:first-child { border-radius: 7px 7px 0 0; } .tool:last-child { border-radius: 0 0 7px 7px; }
.tool h3 { margin: 0 0 2px; font-size: 15px; }
.tool p { margin: 0; color: var(--text-muted); max-width: 75ch; }
.tool .st { justify-self: start; white-space: normal; }
@media (min-width: 760px) { .tool { grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; } }
.unavailable-tools { margin: 16px 0; }
.unavailable-tools > .tool-list { margin: 0 14px 14px; }
main ul, main ol { max-width: 75ch; }
main ol li, main ul li { margin: 4px 0; }
.guarantee { margin: 16px 0 8px; }
.fine-print { margin: 0 0 16px; }
.fine-print > ul { padding: 0 32px 12px; }
.confirm .row .input { flex: 1 1 10ch; }
@media (max-width: 600px) { .confirm .row { flex-direction: column; align-items: stretch; } .confirm .row .input { width: 100%; } }
"""

def page_start(title, *, host_navigation=False, extra_nav=()):
    """host_navigation adds Hosts/attention links; only pages rendering the fleet overview set it.

    extra_nav is (href, label, current) for the private operator area; never prototype data.
    """
    from html import escape
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>' + escape(title, quote=True) + '</title><style>' + STYLE + '</style></head>'
            '<body><a class="skip-link" href="#main">Skip to content</a><div class="shell">'
            '<header class="topbar"><a class="brand" href="#main" aria-label="Gargoyl evidence">'
            '<svg viewBox="0 0 64 64" aria-hidden="true"><path d="M12 8 22 20h20L52 8l-3 22-8 14-9 12-9-12-8-14z" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linejoin="round"/><path d="M21 31l8 3-8 1z M43 31l-8 3 8 1z" fill="currentColor"/></svg>gargoyl</a>'
            + ('<span class="pill">Operator tools · private</span>' if extra_nav
               else '<span class="pill">Read-only evidence</span>') + '</header>'
            '<nav class="nav" aria-label="Sections"><ul>'
            + ('' if extra_nav else '<li><a href="#main">Evidence</a></li>')
            + ('<li><a href="#fleet-overview">Hosts</a></li><li><a href="#needs-attention">Needs attention</a></li>'
               if host_navigation else '')
            + ''.join('<li><a href="' + escape(href, quote=True) + '"' + (' aria-current="page"' if current else '')
                      + '>' + escape(label) + '</a></li>' for href, label, current in extra_nav)
            + '</ul></nav><main id="main">'
            + ('<a class="jump-link" href="#fleet-overview">Jump to hosts</a>' if host_navigation else ''))


PAGE_END = '</main></div></body></html>'

STYLE += "\n.fleet .host a { white-space: nowrap; } .fleet td { white-space: normal; min-width: 170px; } .fleet .ev-line small { overflow-wrap: anywhere; }\n"
