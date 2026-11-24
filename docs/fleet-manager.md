# Native account fleet manager

Gargoyl's native app reads actual owned-provider inventory from Darkbloom's
`GET /v1/me/providers`. Source IDs are preserved in every row and detail view.
The local collector observes this Mac directly; other machines currently have
coordinator reports, not independent remote process observations. A read-only
Tailscale peer telemetry library exists (`docs/tailscale-telemetry.md`) but isn't
wired into the app yet. The internal pilot UUID is never substituted for a Darkbloom
provider ID. No production view contains fixture fleet entries.

## Graphical operation

Choose **Account → Connect fleet…**, review the read-only scope and optional Remember
choice, then continue. Copy the private native sheet's one-time code and open the
official account page. Approve **Authorize Desktop** there. No terminal or secret
URL is part of normal operation. The grant can view Macs, summary and earnings;
Gargoyl requests only owned-provider metadata. It cannot control providers.

The fleet screen shows coverage, source labels, actual IDs, reported status,
retrieval freshness and source heartbeat evidence separately. Filter by heartbeat
recency or open a provider for details. Account reads run every 30 seconds, with
bounded backoff for transport errors. Refresh updates the visible view. Missing,
future, disconnected, stale or partial evidence never establishes healthy or zero
providers. Low traffic and coordinator warnings never trigger repair.

**Aliases…** lets you choose an actual provider ID and save a friendly
name on this Mac. Source labels and IDs remain visible. A hardware model is
explicitly a hardware label; a missing name falls back to the actual ID.
Known Apple Darwin model identifiers (`sysctl hw.model`, e.g. `Mac13,1`)
are displayed with the model name Apple prints on its identification pages,
such as "Mac Studio (2022, M1 Max)"; the raw identifier stays as the source
label in the provider details, and unknown identifiers keep the raw value. The version
column is labeled **Darkbloom version** because it is the provider's Darkbloom
release (e.g. `0.10.17`), not a macOS version. Aliases
never alter public identity matching, action targets, provider settings or source
records. Leave an alias blank to remove it. There is no inferred mapping of
`studio64-1`/`studio64-2` to identical-looking machines; the operator must identify
the actual IDs. Aliases stay out of the network dashboard and telemetry export.

## Heartbeat evidence

Version-matched Darkbloom 0.10.6 source at
`84ddfdba6bb704bf1c68f97c7060289079380ceb` reads textual `last_heartbeat`, falling
back to textual `last_seen` (`DesktopAccountCloud.swift`). It parses ISO-8601
with fractional seconds, then without fractions. Its cloud projection converts
that date to Unix seconds; this does not establish numeric units in the raw API.

The fleet-only adapter accepts bounded ISO-8601 timestamps with 1–9 fractional
digits and explicit timezone, converts to UTC and truncates sub-microsecond
precision for its normalized cache. The strict v1 telemetry timestamp validator
is unchanged. Numeric units are never guessed. The cache retains only fixed
reason/source enums and fractional-digit count, distinguishing not reported,
unsupported type, invalid timestamp and reported evidence. Older cached records
remain readable but are explicitly unclassified until refreshed. A successful
API read is not a provider heartbeat.

The prior three unknown timestamps were not enough to prove missing source data
or a precision mismatch. Live format metadata after the updated collector runs
must establish the cause; tests alone do not. No raw account payload is retained.

## Optional remembered sign-in

Remember is off by default. With explicit consent, the native app saves only its
validated read-only account session in a fixed generic-password item in this
Mac's **file-based login Keychain**. Swift owns Keychain access; the shared Python
interpreter receives no Keychain ACL or access group. No custom broad ACL,
iCloud synchronization, provisioning entitlement or new signing credential is
configured. The backend distinction follows [Apple’s Mac Keychain guidance](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains). Standard macOS app access controls apply; an ad-hoc app update may
cause a new access prompt or denial. Gargoyl fails closed rather than broadening
access. This does not claim data-protection `ThisDeviceOnly` semantics or automatic
locking when the screen locks.

A credential is saved only after acknowledged `desktop_account` authorization
and the first validated fleet read. Tokens move only over the trusted same-owner
native/worker private pipes for opted-in Remember/Resume, never through argv,
environment, HTML, URLs, diagnostics, logs or plaintext files. Stored purpose,
record identity and original expiry are validated before reuse. The local expiry
is conservatively bounded by the start of the original 30-day account grant; no
restore extends it. Memory-only sessions remain bounded to 24 hours. Opted-in and
restored readers stop at their original grant limit, without another device grant.

Quitting with a saved sign-in permits graphical resume on reopen.
**Account → Resume saved sign-in** retries a locked/denied Keychain read without creating a
new grant. A bounded read-only wait handles the previous reader still exiting;
it never retries device authorization. Denied/locked storage or network errors
never fall back to plaintext or erase a valid saved credential. Expired or
server-rejected sessions stop; cleanup targets only their matching saved record,
so a newer replacement is not deleted.

**Disconnect fleet** ends memory collection. It does not mean saved sign-in was
forgotten. **Account → Forget saved sign-in…** removes only Gargoyl's selected login Keychain
item after native confirmation; the current memory session may continue until
Disconnect or Quit. Local deletion does not claim remote grant revocation.

The previously installed memory-only worker has no supported credential handover.
Do not inspect its memory or invent a migration: preserve it during development,
then perform one fresh graphical sign-in after the reviewed update and approved
Keychain setup. Real storage/read/delete acceptance must be recorded separately
from fake-adapter tests; building the code does not activate persistence.

## Reader lifecycle, supervision and background durability

The account reader runs as an unprivileged child worker under the native macOS app
(`Gargoyl.app`). It records nonsecret lifecycle metadata to `reader_lifecycle.json`
(schema 1) with atomic file replacement and strict field validation. The record
tracks process incarnation (`pid`, `born_us` via kernel `proc_pidinfo`), observation
timestamp (`observed_at`), execution status, error classification, and retry state.
`gui_owner` records unverified parent PID and start time (`pid`, `born_us`), retained for
informational diagnostics only and omitted (null) when the parent start time is
unavailable or cannot be verified.
Actual credentials, authorization codes, tokens, and process arguments are strictly
excluded.

### Truthful state distinction

Gargoyl distinguishes operational display states from underlying on-disk lifecycle metadata, preventing misleading diagnostics or false inferences of credential revocation. The on-disk schema records explicit statuses (`READER_STATUSES`: `idle`, `starting`, `running`, `transient_failure`, `session_busy`, `stopped`, `exited`, `terminal_failure`) and exact exit reasons:

1. **Connected (`running`)**: Active reader process matches its recorded incarnation
   and is actively polling inventory every 30 seconds.
2. **Transient failure (`transient_failure`)**: Temporary transport error (timeout,
   DNS resolution, HTTP 5xx). The reader maintains its session and backs off
   automatically.
3. **Authentication required (`stopped` / `auth_required`)**: Darkbloom API explicitly rejected
   the token (HTTP 401/403). A fresh device-flow connection
   is required. Disconnected cache, pipe EOF, or missing processes never infer this state.
4. **Intentional stop (`stopped`)**: User clicked **Disconnect fleet** (`intentional_disconnect`)
   or explicitly quit the application process (**Gargoyl → Quit** / Command-Q, sending a
   quit token `quit\n` recorded as `intentional_quit`). The session was closed cleanly with explicit
    intent. Exit status is left null in the reader's self-record because a process cannot observe its
    own exit status from within. The native supervisor observes the child's actual exit status
    (exit code, or signal for uncaught-signal terminations) when the process terminates and shows it
    in the account status line at observation time; it is deliberately not persisted into
    `reader_lifecycle.json`, because a post-exit lifecycle write from the supervisor would need a new
    write authority and belongs to the declared durable-supervision blocker.
   Note that closing the Mac window does not stop collection: `applicationShouldTerminateAfterLastWindowClosed`
   returns `false`, keeping `Gargoyl.app` and its reader child process actively running in the background.
5. **Supervising pipe closed (`exited` / `pipe_eof`)**: Bare EOF on the private supervising pipe
   (including process crash, unexpected termination, or send-side `EPIPE` where the child broke
   before receiving an intent token) is cause-unknown. When reopening or launching the normal GUI, any unexpired saved session
   is restored via the established path (subject to standard macOS Keychain access controls).
6. **Read-only preview (`preview`)**: App is running in read-only preview mode (triggered by
   `previewOnly` via Info.plist or `previewOverride`, not internal worker flag `GARGOYL_PREVIEW=1`).
   The interface truthfully reports that saved-session restore and background collection are disabled in preview, rather than demanding reconnection.

A stale PID whose process start time (`born_us`) does not match the kernel's process
table (or where start time cannot be verified) is treated as an exited incarnation, reporting
`exit_reason="unknown"` rather than assuming credential rejection. Fail-closed behavior on
`born_us=None` is an intended trade-off to prioritize safety over unverified live claims.

### Normal GUI supervision and bounded recovery

In normal GUI mode, the native application supervises the reader process through a
private pipe:
- In-process automatic recovery covers only sessions begun from a restored credential
  (`savedFleetState.credential != nil`).
- If the reader terminates unexpectedly while a valid saved session exists, the native
  app initiates in-process automatic recovery using the in-memory session grant with
  exponential backoff (`delay = min(60.0, 3.0 * 2^retryCount)`).
- Recovery has a cumulative budget of 5 attempts across a recovery sequence before halting
  with a terminal failure message. Cumulative budget across successful recoveries is intended
  and conservative: it prevents unbounded auto-reconnect loops if connections repeatedly cycle or flap,
  halting with terminal status rather than spinning indefinitely. Swift's supervisor owns the `.terminal`
  exhaustion decision; the reader child process preserves its observed exit reason and leaves `exit_status = None`;
  the supervisor observes the child's termination status and surfaces it only in the status line, never as a
  persisted lifecycle field.
- In-process recovery reuses the unexpired in-memory session grant; no user consent
  or device authorization prompt is repeated.
- Intentional disconnection cancels active recovery timers and increments the session
  generation, preventing unwanted restarts. Quitting cancels recovery timers and sends
  a clean quit intent token (`quit\n`).
- Single-owner concurrency: the reader process confirms only one reader incarnation runs
  at any time via a POSIX file lock (`session.lock`).

### Background durability gap and detached supervision boundary

The reader process lifetime is coupled to the running native GUI application process.
Closing the Mac window keeps collection running: `applicationShouldTerminateAfterLastWindowClosed`
returns `false`, matching the connection sheet confirmation ("Closing the window keeps collection
running"). However, quitting `Gargoyl.app` (**Gargoyl → Quit** / Command-Q) sends a quit intent
token (`quit\n`), while unexpected app termination closes file descriptors and delivers bare EOF
on the reader's standard input pipe, prompting reader shutdown (`exit_reason="pipe_eof"`). The
existing local monitor LaunchAgent (`gargoyl monitor`) does not supervise the account reader: the
monitor is a local operational helper (not an OS sandbox) running local checks; its no login Keychain
access and no network egress to Darkbloom API endpoints are unverified design inputs.

Genuinely durable detached background supervision when the application process is not
running (outside GUI process lifetime) represents an authority blocker requiring explicit
approval:
- A dedicated user LaunchAgent (`dev.gargoyl.account-reader.plist`) running within the
  user's GUI login session.
- Explicit user opt-in and product consent for unattended background network egress to
  Darkbloom endpoints while no window or application is open.
- Resolution of Keychain access architecture for unattended background processes (unverified design
  inputs: whether the same signed app binary run via LaunchAgent requires Keychain Access Control
  List (ACL) changes is unverified, and ad-hoc builds and headless helpers cannot display interactive
  authorization prompts).

Gargoyl does not install background services or expand daemon permissions without approval.
The implementation provides bounded, in-process recovery within normal application lifetime,
while documenting detached background supervision as an explicit, reviewable architectural choice.

## Privacy and protocol boundaries

Fixed HTTPS authority and exact device-flow/owned-provider endpoints use verified
TLS, no redirects/cookies, bounded response bytes/depth, and caller deadlines.
Only acknowledged `desktop_account` grants and scoped token prefixes are accepted;
legacy provider grants are refused. The official verification page must be
`https://console.darkbloom.dev/link?purpose=desktop_account`. Bare `/link` selects
provider linking and causes “authorization purpose does not match this code”.
Darkbloom 0.10.6's CHANGELOG and desktop external-link tests document that context.
Gargoyl constructs only the fixed nonsecret purpose URL; it never forwards
server-supplied codes/query values and refuses contradictory/repeated purposes.

Inventory and aliases are separate owner-private contracts, not v1 ingestion or
export extensions. Only allowlisted IDs/names/status/version/heartbeat evidence
and a public-identity digest survive normalization. Financial values, model names,
IPs, credentials and arbitrary payload detail are dropped. Duplicate IDs fail
closed; unknown records/pagination make coverage partial. The private inventory
cache uses same-owner/no-symlink checks, atomic 0700/0600 storage, at most 256 records
and 512KiB, and 24-hour maximum usable age with deletion on next read. Nothing can
run cleanup while the app is stopped. Aliases have separate bounded private
storage and persist until edited/removed.

Local association requires fresh protected daemon public attestation identity,
verified native process identity and an exact unique account match. Hostnames
and aliases never establish association or authorize repair. The public loopback
dashboard remains local-telemetry-only, and automatic repair stays disabled.

## Management and local history

Open **Fleet management** in the sidebar for a provider-by-provider coverage and
operator-workflow view. Account reports alone do not connect a collector. A local
association requires a fresh, connected, complete account inventory and one unique
public-identity match to this Mac's fresh verified process. Names and aliases never
supply that association. Partial, stale, disconnected or ambiguous inventory leaves
association and per-provider history unavailable; no substitute provider is chosen.

For the matched Mac, the view links to local history and explains how to review
**Restart local…** through the native toolbar. It does not pre-authorize
the restart; fresh preflight and Mac confirmation still apply. Other records show
why remote collection, history and control are unavailable. No fake enrollment or
remote restart controls are provided. **Aliases…**, Refresh, Export local…
and Gargoyl's own Start/Stop monitoring remain graphical native tools.

**Local traffic** shows the retained sample count/range and newest observations
first. It derives counter changes only from fresh ordered observations with
consistent timestamps, no observed collection error and no detected counter
decrease. An undetected reset between observations can still affect the comparison. Sparse, future,
stale or reset evidence yields an explicit unknown change. Zero observed traffic
is not failure, a billing measure or proof about demand/routing. At most64samples
are held in monitor memory. Restart clears them. No durable history key is created
or enrollment activated by opening these views.
