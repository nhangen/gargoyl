# Gargoyl Mac application

Normal operation is graphical. Open **Gargoyl.app** to see the existing live
console in a standard resizable Mac window with close, minimize, zoom and full-screen controls. Closing the window leaves the background monitor and provider running; reopening the app shows the window again. Use **Start monitoring**, **Stop monitoring**, **Refresh**, **Export…**
and **Operation status** in its native toolbar. Start/Stop affects only the
existing Gargoyl monitoring job, never Darkbloom. Export opens a Mac save dialog
for bounded normalized evidence; raw provider logs and credentials are excluded.
The browser dashboard remains read-only. No pairing command or secret URL is
part of this flow.

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
An interrupted or unverified outcome blocks further attempts; this app cannot
clear it. Read-only reconciliation is required. CLI success and replacement
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
reviewed package. Its default is a read-only preview with lifecycle and restart
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
