# Darkbloom 0.10.5 restart evidence

Verified on MBP-26 on 2026-10-31. Darkbloom has a supported graceful manual
restart, with real target, drain and duplicate-request safeguards. The inspected
interfaces do **not** establish the complete Gargoyl policy for a pre-drained,
fence-preserving, cleanup-inclusive 30-second restart that remains at-most-once
across interruption. Gargoyl live repair stays disabled.

## Installed and source provenance

| Evidence | Observed value |
|---|---|
| CLI entry | `/Users/nhangen/.darkbloom/bin/darkbloom` |
| Symlink target | `../Darkbloom.app/Contents/MacOS/darkbloom` |
| Canonical executable | `/Users/nhangen/.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom` |
| Executable architecture | Mach-O arm64 |
| CLI `--version` and bundle short/build versions | `0.10.5` |
| Installed executable SHA-256 | `f568a3de578664bbc4246a3e51688aa9595fe51b7aaac8e26bbd829b8733b85d` |
| Published release | [v0.10.5](https://github.com/Layr-Labs/d-inference/releases/tag/v0.10.5), published 2026-10-30T17:21:22Z |
| Release archive | `darkbloom-bundle-macos-arm64.tar.gz`, 281248542 bytes |
| Downloaded archive SHA-256, matching GitHub asset digest | `c614a0109befb211bbab8c215a1b953576ab52c57d7170937d1e5f5567d49cf1` |
| Executable hash inside archive | Exactly matches installed executable above |
| Annotated release tag object | `5f1a76377083a3e8fd1f9db82649896675756b5a` (GitHub reports signature verified) |
| Tag's source commit | `d3bbcd064ea290fbeb500e5c51c7870e3695741c` |
| Source version authority | [ProviderCore.swift:8](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/ProviderCore.swift#L8) is `0.10.5` |

This binds the installed bytes to the published release artifact and the release's
source tag. It is not a reproducible-build proof that those bytes were compiled
from that source. No embedded build commit was established. No claim is made
about a currently running provider's executable mapping, loaded configuration,
model identity, coordinator deployment, or live drain correctness. Only CLI
`--version` and help were executed; no status/control API was contacted and no
restart, drain or provider mutation was performed.

The prior assessment cited `6a78624...`, not the installed release commit. That
was insufficient provenance. Claims that Darkbloom lacks target identity,
accepted-work drain, request IDs, any deduplication, or durable operation history
would be incorrect; the narrower distinctions below replace them. The source
review includes CLI lifecycle, local-only lifecycle, desktop control dispatch,
mailboxes, process locks, provider drain and their focused upstream tests. Those
upstream tests were read, not executed; Gargoyl's tests use controlled fixtures.

## Supported entry points

Installed `darkbloom restart --help` exposes `--timeout` (default 600, 0–3600),
`--startup-timeout` (default 180, 1–3600), `--force`, and `--config`. It explicitly
drains accepted requests, reuses the existing selection and starts an installed
but stopped service. Source: [RestartCommand.swift:4–59](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/RestartCommand.swift#L4).
This is a legitimate manual restart mechanism; it is not inherently an unsafe
command. Gargoyl must not substitute its presence for the approved narrower policy.

The installed CLI also exposes `darkbloom desktop restart-local`. Its
[implementation](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopLocalLifecycle.swift#L7) verifies the
local runtime owner, holds an update lease during stop, requests graceful
termination and waits up to 620 seconds, then reloads the existing launch agent.
It is not a 30-second pre-drained operation or durable restart transaction.

The source exposes authenticated numeric-loopback desktop
`POST /control/v1/actions` ([DesktopHTTP.swift:15–76](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopHTTP.swift#L15)).
A validated `restart` action dispatches either ordinary `restart` or
`desktop restart-local` ([DesktopBackend.swift:192–209](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopBackend.swift#L192)).
This API is source capability, **not verified installed/running API availability**:
no discovery token, credentials or API requests were used. Existing authentication
is a safeguard, not authorization for Gargoyl to obtain or reuse those credentials.

## Guarantee assessment

| Guarantee | Matching source evidence | Policy conclusion |
|---|---|---|
| Correct process, including PID reuse | [ProcessIdentity.swift:6–57](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/ProcessIdentity.swift#L6) reads kernel PID + start time; [WatchdogProbe.providerIdentity](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/WatchdogProbe.swift) prefers matching live birth identity, otherwise launchd; [ServiceDrain.prepare:23–35](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/ServiceDrain.swift#L23) rejects unconfirmed non-forced live owners. | Present identity safeguards. CLI has no caller-supplied expected birth/image/config digest atomically bound through the final launchd reload. Gargoyl's independent UID/image/birth proof is not supplied by counters. Live target remains unverified here. |
| Owner-local control | [LifecycleMailbox.swift:5–22, 60–106](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/LifecycleMailbox.swift#L5) binds filenames to birth identity, checks owner/private paths and bounds/no-follows reads. | Present. This is owner-local IPC, not a provider-signed v2 attestation or cross-replacement control ledger. |
| New work refused during old-process drain | [ProviderLoop+Lifecycle.swift:4–22](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/ProviderLoop+Lifecycle.swift#L4) closes local acceptance and refuses admission; [ProviderDrain.swift:12–43](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/ProviderDrain.swift#L12) prevents other owners reopening lifecycle drain. | Present for current process. Not evidence of a persistent fence inherited by its replacement. |
| Accepted work has actually drained | [ProviderLoop+Lifecycle.swift:19–22, 78–127](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/ProviderLoop+Lifecycle.swift#L19) counts accepted/inflight work and local reservations/writers, retires native owners, then waits for terminal/usage acknowledgement. [CoordinatorClient+Drain.swift:8–42](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Coordinator/CoordinatorClient+Drain.swift#L8) places a FIFO barrier and checks the same registered connection. | Substantial existing drain, stronger than inference-active or cumulative counters. Live behavior/coordinator implementation unverified. Source may report `drained` without actual coordinator ack when no registered connection remains (lines103–109); approved Gargoyl policy requires a matching actual ack and rejects that exception. |
| Matching drain identity | [ProviderDrainRequest](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/ProviderDrain.swift#L75) contains UUID, target birth identity, creation time; [ServiceDrain.wait:122–145](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/ServiceDrain.swift#L122) matches `requestID`, refuses busy/timeout and exited target. | Present drain identity and stale-request checks. No caller-stable restart ID spanning stop, replacement and terminal outcome. A new CLI invocation creates a new drain UUID. |
| Concurrent/repeated requests | [UpdateProcessLock.swift:8–15](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Update/UpdateProcessLock.swift#L8) uses crash-released close-on-exec flock; [ServiceDrain.prepare:20–23](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/ServiceDrain.swift#L20) takes lifecycle lease. [ProviderLoop+Lifecycle.swift:25–43,142–156](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/ProviderLoop+Lifecycle.swift#L25) coalesces active same-ID drains and remembers last handled ID in memory. | Present serialization/coalescing, not a durable cross-restart restart-ID ledger. [RestartCommand.swift:52–56](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/RestartCommand.swift#L52) releases lease before fresh-authorization confirmation; sequential invocations can each restart. |
| Desktop duplicate safety and history | [DesktopBackend.swift:15–19,47–89](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopBackend.swift#L15) deduplicates identical retained requests in the same instance, rejects ID payload changes, serializes mutation and persists up to32 operation records. Reload marks running entries `interrupted`. [DesktopStorage.swift:25–43](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopStorage.swift#L25) synchronizes file and atomically renames. | History is durable, but request map is not restored. After API restart the old ID is absent from `requests`; `interrupted` does not block the mutation slot. A same-ID resubmission can be accepted anew; retention eviction also removes dedup. No durable permanent terminal/no-pending proof across child/API/provider interruption is exposed. This is source control-flow evidence, not a live exploit/restart reproduction. |
| Same model/settings | [LaunchAgent.restartAfterDrain:187–208](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/LaunchAgent.swift#L187) reloads existing plist, changes termination allowance, preserves arguments. | Existing installed selection reused. Not a compare-and-swap against the observed **active** config/model digests, which may differ from files or concurrent settings. |
| Fence retained and no automatic recovery | [RestartCommand.swift:40–56](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/RestartCommand.swift#L40) reloads then rearms watchdog before authorization wait; [LaunchAgent.swift:517–538](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/LaunchAgent.swift#L517) has RunAtLoad; new [ProviderDrain](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/ProviderDrain.swift#L10) starts serving. | Normal manual restart intentionally restores service. No persistent caller-selected admission fence or explicit separately authorized unfence is carried across replacement by these interfaces. |
| One cleanup-inclusive 30-second bound | [ServiceDrain.swift:124–126,159–181](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/ServiceDrain.swift#L124) has drain timeout+10 and separate startup timeout; stop path can wait30 separately. [LaunchAgent.swift:200–208](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/Service/LaunchAgent.swift#L200) sets ExitTimeOut3660. Desktop worker defaults3600 ([DesktopWorker.swift:50–51](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/Desktop/DesktopWorker.swift#L50)). | Missing shared end-to-end bound. Setting both CLI timeout flags to30 does not establish total30 or prove termination/cancellation of all already accepted side effects. |
| Unknown/interrupted outcome and retry | [ServiceDrain.waitForRestart](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/darkbloom/ServiceDrain.swift#L159) explicitly reports launched-but-unconfirmed, not a second restart. Drain tasks are intentionally unstructured so interrupting CLI does not cancel accepted inference ([ProviderLoop+Lifecycle.swift:25–27](https://github.com/Layr-Labs/d-inference/blob/d3bbcd064ea290fbeb500e5c51c7870e3695741c/provider-swift/Sources/ProviderCore/ProviderLoop+Lifecycle.swift#L25)). | Good single-call conservative reporting. No supported permanent reconciliation record proves an old restart cannot execute later and makes resubmission at-most-once across crashes. Killing a CLI is not rollback. |

No inspected entry point meets **all** approved requirements. This conclusion is
limited to the matched release/source and inspected supported interfaces, not a
claim that no future/private capability can exist. Stock CLI/API must not be
wrapped with a client timeout and described as satisfying the missing guarantees.

## Gargoyl capability and installed state

Merged Gargoyl v2 code verifies signed scoped proofs, independent native process
identity, zero accepted work, matching drain ack, fixed fence/config/model and
per-action authority. Its encrypted journal consumes intent and retains a host gate
through unknown outcomes; only signed read-only permanent terminal reconciliation
can release it. No production mutating backend ships. See
[the v2 protocol](pre-drained-restart-v2.md) for its trust and deadline limitations.

The local monitor has no execution route. Its dashboard now states the target,
drain, repeated/interrupted request and authorization reasons separately, without
inferring them from telemetry or probing credentials. Fresh, stale, missing and
source-supplied `drained` flags never enable repair. GET of an action path and POST
remain rejected. This change is source-only: the installed monitor remains on
`e666247e99147087b47e2dc717a73d0dd5d1402c` and is not updated by merging this PR.
Thus the running dashboard will not show the new explanation until an independently
authorized package update. Live repair remains disabled in both versions.

## Smallest upstream addition and acceptance

Extend the existing owner-local lifecycle authority, drain barrier and update
lease; do not add a second arbitrary command runner or replace working drain logic.
Add one conditional restart transaction with:

- Caller-stable request ID plus immutable digest, expected installation/process
  birth/image/config/model, already-established fence and matching drain evidence.
- Durable claim **before** launchd effects, surviving API/CLI/provider death. Same ID
  returns its existing state; changed payload or unresolved prior host transaction
  refuses. Eviction must retain durable replay tombstones or use bounded fail-closed capacity.
- One replacement with existing selection and preserved admission fence; no force,
  retry or blind recovery/unfence. Verify current authority and compare expected
  state at the mutation boundary under existing lifecycle serialization.
- One deadline covering acceptance, stop, launch, confirmation and owned cleanup;
  expired requests cannot execute later. Unknown state remains unresolved.
- A read-only lookup proving terminal/no-pending outcome for the exact request,
  including late arrivals and claimed-but-not-dispatched requests. No `not found`
  or age-based clearance. Return authoritative bindings suitable for a local
  adapter; Gargoyl's v2 signed protocol may be implemented by an approved bridge
  rather than forcing a new trust format into upstream.

Controlled upstream tests should crash/interrupt at claim, drain, stop, launch,
reply and persistence boundaries; repeat before/after control-process restart and
history capacity; race a second request and state/config changes; assert one
replacement at most, no acceptance while fenced, no force, and conservative
unknown outcomes. Reuse existing native drain/terminal-delivery tests. A local
issue draft accompanies the task handoff; it has not been posted or sent upstream.
No upstream modification or credential setup is part of this change.
