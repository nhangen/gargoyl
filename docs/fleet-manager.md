# Native account fleet manager

Gargoyl's native app reads actual owned-provider inventory from Darkbloom's
`GET /v1/me/providers`. Source IDs are preserved in every row and detail view.
The local collector observes this Mac directly; other machines currently have
coordinator reports, not independent remote process observations. The internal
pilot UUID is never substituted for a Darkbloom provider ID. No production view
contains fixture fleet entries.

## Graphical operation

Choose **Connect fleet…**, review the read-only scope and optional Remember
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

**Edit local aliases…** lets you choose an actual provider ID and save a friendly
name on this Mac. Source labels and IDs remain visible. A hardware model is
explicitly a hardware label; a missing name falls back to the actual ID. Aliases
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
**Resume saved sign-in** retries a locked/denied Keychain read without creating a
new grant. A bounded read-only wait handles the previous reader still exiting;
it never retries device authorization. Denied/locked storage or network errors
never fall back to plaintext or erase a valid saved credential. Expired or
server-rejected sessions stop; cleanup targets only their matching saved record,
so a newer replacement is not deleted.

**Disconnect fleet** ends memory collection. It does not mean saved sign-in was
forgotten. **Forget saved sign-in…** removes only Gargoyl's selected login Keychain
item after native confirmation; the current memory session may continue until
Disconnect or Quit. Local deletion does not claim remote grant revocation.

The previously installed memory-only worker has no supported credential handover.
Do not inspect its memory or invent a migration: preserve it during development,
then perform one fresh graphical sign-in after the reviewed update and approved
Keychain setup. Real storage/read/delete acceptance must be recorded separately
from fake-adapter tests; building the code does not activate persistence.

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
