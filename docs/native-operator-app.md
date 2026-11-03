# Gargoyl Mac application

Normal operation is graphical. Open **Gargoyl.app** to see the existing live
console in a standard resizable Mac window with close, minimize, zoom and full-screen controls. Closing the window leaves the background monitor and provider running; reopening the app shows the window again. The window's native title-bar toolbar has an **Account** menu (Connect fleet…, Resume saved
sign-in, Disconnect fleet, Forget saved sign-in…), **Local aliases…**, **Refresh**,
**Start local monitor**, **Stop local monitor**, **Export local report…**, then
**Operation status**, **Record reconciliation…** and **Restart local provider…** set apart at
the end. Narrow windows move extra items into the toolbar's overflow menu. Status messages
appear in the small status area at the bottom of the window. Start/Stop affects only the
existing Gargoyl monitoring job, never Darkbloom. Export opens a Mac save dialog
for bounded normalized evidence; raw provider logs and credentials are excluded.
The public browser dashboard remains read-only, and the app needs no pairing
command or secret URL. Separately, `gargoyl monitor --operator-tools
--enable-restart` serves an opt-in private browser console (an admin panel behind
a per-start secret URL) that can request the same manual restart; it shares the
app's and CLI's journal and gate, so only one restart can be in flight and an
unresolved one blocks all three until reconciled. See
[operator console tools](operator-tools.md).

The yellow titlebar control and **Window → Minimize** (Command-M) use the native
window minimization action. Reopening restores a minimized window explicitly.
**Help → Window diagnostics…** shows the last 16 in-memory window events, including
actual AppKit minimize/restore callbacks and reopening. This separates successful
minimization followed by reopening from a failed action. It contains no provider
data and does not write logs or change monitoring.

The **Gargoyl** application menu provides native **Hide Gargoyl** (Command-H),
**Hide Others** (Option-Command-H) and **Show All** actions. Hiding leaves the
application, background monitor and any accepted operation running. Ordinary
application activation restores its window. Window diagnostics include bounded
AppKit hide/unhide events and the application's hidden state.

## Manual restart

Choose **Restart provider…**. Gargoyl verifies the current MBP-26 installation
and shared operation journal before showing the target process/version and
interruption/recovery effects. Continue to the Mac authentication dialog; macOS
handles Touch ID or the existing Mac password. Cancelling, expiry, unavailable
authentication, a changed owner/target or unresolved earlier operation blocks
execution. Gargoyl never receives or stores the password or biometric data.

After confirmation, one supported graceful Darkbloom restart may run. Progress
explicitly distinguishes the request, waiting on Darkbloom, and verified
replacement evidence. There is no force or automatic retry. Closing the app
after acceptance does not cancel the worker or retry the request. Reopen the app
and choose **Operation status** to inspect the durable shared CLI/app journal.
An interrupted or unverified outcome blocks further attempts. Use **Operation
status → Record reconciliation…** for an explicit read-only review; it never
clears a Darkbloom guard, invokes the provider or retries the prior request. CLI success and replacement
evidence do not independently establish coordinator or protocol health.

Automatic provider repair remains disabled. Existing Gargoyl KeepAlive is
separate. The optional advanced CLI is retained for compatibility, but is not
required in the normal application flow.

## Implementation and packaging

The unprivileged native shell uses AppKit, WKWebView and LocalAuthentication.
Its native controls cannot be called by page scripts or HTTP requests. JavaScript,
popups, external navigation and network subresources outside the two fixed
IPv4 loopback evidence endpoints are blocked. The webview has an ephemeral data
store. Localhost is not treated as owner identity. Native confirmation uses a
fresh OS authentication context bound to one expiring private-pipe request;
the worker independently verifies the active UID and installation and reuses
the existing journal lock, durable intent and unknown-outcome gate. Malicious
code already running as the same OS user is outside this boundary.

For maintainers, `tools/build_macos_app.py` builds a local **Gargoyl.app** against
the Apple SDK with an owner-local isolated Python containing the matching
reviewed package. The builder ad-hoc signs the completed local bundle after writing
its metadata and verifies its resource seal before reporting success. This is
local integrity packaging, not developer notarization, a new permission grant,
or an override of execution approval. Its default is a read-only preview with lifecycle and restart
buttons disabled. Release preparation can enable native controls with the build
option `--enable-native-actions`; this does not grant permissions, authenticate
or invoke a restart. It must not be mistaken for live repair activation.
The current pilot recognizes only UID 501 on MBP-26, the existing fixed monitor
LaunchAgent/configuration, loopback port 8766 and supported pinned Darkbloom
versions. It does not install a privileged helper, enroll a machine, create
credentials or modify the LaunchAgent.

Compiled fixture tests do not exercise real Touch ID/password prompts or a live
provider restart. Native visual/OS permission acceptance must be recorded
separately. If macOS requests new protected-file/network access, stop that step
and obtain the specific permission; do not broaden app entitlements, grant Full
Disk Access, disable protections or move files to evade a denial.

## Native admin views

The Mac app opens **Operator tools**, using the merged operator-console layout,
sidebar, tool rows and evidence styling. Navigate within the window to **Live
evidence**, **Traffic history**, **Manual operation**, or **Local details**. Views
are read-only; Refresh loads the current normalized monitor report and evaluates
freshness at viewing time. It does not force a source poll. Pages explicitly say
that they do not refresh automatically. History retains at most 64 samples in
monitor memory and is lost when the monitor restarts.

Use the native toolbar for Start/Stop local monitor, Refresh, Export local report…,
Operation status, and Restart local provider…. Export opens the standard Mac Save dialog. Start
and Stop affect only Gargoyl's configured monitor. Restart local provider opens the
existing exact-target/interruption review followed by Mac owner authentication;
no page link can invoke it. Progress stays in the native status area and outcome
in the shared journal. Intent and unknown records remain blocked by the shared native/CLI/browser gate.
The **Record reconciliation…** native button is available only for intent/unknown
records outside preview mode and while no manual worker is active. It reviews the
original operation/target and current observed identity, then requires fresh Mac
owner confirmation. It refuses while the exact recorded command is alive; if no
child identity was saved, the existing conservative 15-minute command bound must
have elapsed. That bound does not prove upstream work ended. The journal and
observation are checked again after confirmation; changes cancel the request.
This records current evidence and reopens Gargoyl’s manual gate for a later
separately confirmed attempt, across app/CLI/browser. It does not prove the prior
attempt succeeded, guarantee exactly-once behavior, clear a backend guard, or
invoke a provider command. Expiry, broken pipes, failed writes and owner changes
never trigger an automatic retry. No terminal interaction is required.
Actual provider restart is not exercised by UI acceptance tests.

The read-only pages are reconstructed by a fixed same-owner worker from validated
normalized evidence and, only for Manual operation, the private fixed journal.
No arbitrary HTML, raw logs or subprocess output is rendered. The WebView has
JavaScript disabled, nonpersistent storage and a block-all network-resource rule.
Only finite internal read-only navigation links are intercepted. There is no
registered external URL scheme, action bridge, browser secret link, pairing step
or new credential. The public loopback dashboard gains no journal or mutation
route. A failed acquisition replaces evidence with an unavailable/unknown view;
old healthy content is not treated as a successful refresh.

Provider version/build command acquisition, status and doctor commands are not
run by these views. Status/doctor may read configuration or use network/helpers;
merged browser support does not activate them in the Mac app. Automatic repair,
provider stop/start, force, clear guard, and provider update remain unavailable.
This does not affect Gargoyl's existing own-process background recovery.

Native in-page links name four fixed document anchors. WebKit reports these
opaque-document navigations as `about:blank%23…`; absolute URLs alone did not
restore scrolling. The native delegate rejects navigation and uses a fixed DOM
scroll command for an exact allowlist of main-frame clicked links. URL/page text
never becomes script, unknown links remain blocked, and missing elements or DOM
errors have no navigation fallback. Page scripts remain disabled; this native
scroll operation grants no action, file or network access.

The compiled regression activates a real anchor and asserts nonzero scroll under
the production scroll policy, in addition to a rendered document title and actual
anchor URL. It also verifies delivery/completion of a 23KB view through the real
worker using a controlled fake executable on the active pilot account. Help →
Window diagnostics shows bounded in-memory loading phase, rule readiness and
WebView dimensions; document-title presence alone is not a visual verdict.

All six native actions remain visible in two compact rows at the 390px minimum
window width. Narrow native views retain the theme but compact the navigation
and display timestamps to whole seconds. Terminal operation warnings are kept
when refreshing a view; loading text never replaces an unknown/no-retry outcome.
