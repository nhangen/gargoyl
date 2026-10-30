# MBP-26 local monitor acceptance — 2026-10-30

Base: main `514e6796af585608262d3c6263c36bb27a48f5f8` (PR #29).
GitHub had no open PRs and only main when this work began. Source and project
contracts were inspected before composition; no AGENTS.md or .agents instructions
were present in the repository or applicable ancestor directories.

Environment: macOS 26.7.1 arm64, Python 3.13.5. The existing pilot venv remained
unchanged. A wheel was built and verified, then installed without dependencies
into a separate task-local virtual environment. A second pilot ran outside the
source checkout using that installed wheel.

## Real read-only pilot

The explicit owner-local daemon source under `/Users/nhangen/.darkbloom` was read
with expected UID 501. Its parent was already mode 0700; its file was mode 0644.
No permissions or daemon files were modified. No Darkbloom commands ran.

Both source and installed-wheel acceptance used two bounded foreground runs:

| Check | First run | Restart |
| --- | --- | --- |
| Completed polls observed through HTTP | 1 → 2 → 3 | 1 → 2 → 3 |
| Actual source evidence | observed | observed |
| Dashboard HTTP | 200 | 200 |
| Listener | numeric IPv4 loopback | numeric IPv4 loopback |
| Stop signal | SIGTERM | SIGINT |
| Exit status | 0 | 0 |
| Listener closed afterward | yes | yes |

Only normalized telemetry was rendered. No raw state, keys, credentials, model
names or sensitive source text are recorded here. This proves repeated polling
and observation of real evidence, not that provider traffic increased between
polls, or that daemon liveness, routing, attestation or earnings were established.

All acceptance processes were stopped. No monitor, LaunchAgent or login/boot
persistence remains running or enabled. The prepared plist is inactive.

## Automated verification

- Ruff and `git diff --check` pass.
- Full macOS suite: 337 tests pass with `TMPDIR=/private/tmp`.
- Seven monitor tests exercise repeated polling independently of HTTP requests,
  loopback responses and Host rejection, actual SIGINT/SIGTERM cleanup, restart,
  latest-read failure isolation, malformed/missing recovery, stale/future sources,
  source permission/symlink enforcement, retention and runtime-failure cleanup.
- Existing release artifact verifier passes for the built wheel; it checks fresh
  installation, imports, CLI inspection and bounded synthetic acquisition.
- `plutil -lint docs/examples/dev.gargoyl.monitor.plist` passes.

The default macOS temporary-directory spelling traverses `/var`, a symlink.
The initial full run had 21 failures and 11 errors in existing strict source and
release path tests. Repeating with canonical `/private/tmp` passed; no source,
release or TLS protections were changed to accommodate this environment.

A visual browser check of the saved normalized HTML was denied because browser
policy blocks file URLs. No bypass was attempted. HTTP and HTML assertions pass;
desktop/mobile visual appearance remains unverified. No separate design-review
approval is claimed.

## Scope and gates

This delivers continuous foreground local collection and a live read-only view.
History is intentionally memory-only (64 samples) and clears on restart. Durable
encrypted spooling, credentialed fleet delivery and multi-host enrollment remain
separate from this credential-free single-host runtime. Repairs are disabled.

The draft PR requires independent review before merge. Login persistence requires
an explicit activation choice; no new OS grants, keys, access settings or external
listener are required or requested by this foreground pilot. Website hosting at
gargoyl.dev was untouched.
