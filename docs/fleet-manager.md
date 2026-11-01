# Account fleet manager foundation

The installed Gargoyl monitor currently collects one Mac, `MBP-2026.local`.
The pilot plan names MBP26, `studio64-1` and `studio64-2`, but those names are not
an enrolled inventory and have no verified mapping to Darkbloom provider IDs.
The existing pilot UUID is an internal telemetry label, not an account provider ID.
No other Mac is currently monitored by Gargoyl.

This change adds a native graphical account connection, inventory filters and
provider details, backed by a bounded account protocol, private metadata cache,
session lifecycle and public-identity association. The native app opens on Your
fleet; local evidence remains a separate view. No production view contains
fixture fleet entries. The network dashboard remains local-telemetry-only.

Choose Connect fleet in the native toolbar. The native sheet shows a one-time
code with Copy code and Open official Darkbloom sign-in controls. Review the
read-only scope on the official site and approve there; the app then loads actual
owned-provider IDs. Disconnect fleet ends only account reads. Refresh updates the
visible view; account collection polls every 30 seconds with bounded backoff.
No terminal or copied secret URL is part of normal operation.

## Verified service and grant

The official provider documentation identifies `api.darkbloom.dev` and the console
at `console.darkbloom.dev`. Live bounded negotiation with
`POST /v1/device/code` acknowledged `purpose=desktop_account` and a scoped
`desktop-account-` device code; the verification origin was the official console.
Codes were discarded, not approved or persisted. A refreshed, already signed-in
official console showed four owned records, three reported online. Names on that
surface were hardware labels, not the planned studio aliases. This verifies the
account has inventory; Gargoyl API acceptance still requires completion of its
scoped graphical grant. No browser cookies or existing tokens were extracted.

Version-matched Darkbloom 0.10.6 source is commit
`84ddfdba6bb704bf1c68f97c7060289079380ceb`. Its documented account grant permits
fleet/summary/earnings reads and self-revocation, not provider control. Gargoyl
only requests the owned-provider endpoint. Coordinator enforcement is documented
upstream; it has not been tested by attempting any forbidden mutation.

Both the device-code response and resulting token must acknowledge
`desktop_account`, with their scoped prefixes. A missing/downgraded purpose or
legacy provider token is refused. The transport permits only the two device-flow
POSTs and authenticated `GET /v1/me/providers`, fixed HTTPS authority, verified TLS,
no redirects/cookies and bounded response bytes/depth. A caller deadline includes
stalled DNS/body reads. At most one daemon IO can remain outstanding; no replacement
starts until it ends. The private session process exits on GUI pipe EOF.

The intended normal flow is graphical: Connect Darkbloom, review the read-only
scope, open the official linking page, and complete account approval there. Codes
are shown only in the private native sheet, never a secret URL or terminal flow.
No provider setup, enrollment, configuration or lifecycle command is involved.

## Separate metadata contract

Account inventory is a separate owner-local contract, not an extension to v1
host telemetry, ingestion or export. Actual `id` values are preserved. A source
name is retained only if supplied; a hardware model is explicitly a hardware
label, and a missing name falls back to the actual provider ID. Hostnames and
pilot UUIDs never stand in for provider IDs.

Only allowlisted ID/name/status/version/heartbeat fields and a digest of the
public attestation identifier survive normalization. Raw account payloads,
credentials, financial values, model names, IP addresses and arbitrary detail
fields are not persisted. Unknown/malformed records make coverage partial;
duplicate IDs fail closed. Pagination indicators are not silently treated as a
complete inventory. No routing failure or restart is inferred from these reports.

Retrieval freshness and source heartbeat freshness are independent. Missing,
future, disconnected, stale or incomplete data never establishes healthy or zero
providers. Source-reported status is not independent remote process liveness.

A fixed private cache directory uses same-owner/no-symlink checks, atomic writes,
0700/0600 modes, at most 256 records/512KiB and a 24-hour maximum usable age. Expired
metadata is removed on the next read; nothing can run cleanup while the app is
not running. A new account connection clears the previous cache. The cache is
owner-private local metadata, not the encrypted v1 telemetry spool; it is not
exposed on the public loopback dashboard or included in existing telemetry export.
User-requested account labels remain private and are not exported by default.

Access tokens stay in session-process memory only. No credentials, device codes,
refresh tokens or keys are persisted. Closing the window may preserve collection
while the application remains running. Quitting, disconnecting, losing the active
owner or reaching the 24-hour session limit discards access; another sign-in is
required. Client disconnect does not claim server revocation of an unused grant.
No login-persistence settings or existing credentials are changed.

## Local association and acceptance

Protected daemon public attestation identity is read through existing strict
ownership, no-symlink, size/freshness and native process checks. The current Mac's
public identity was available in a bounded live read; raw identity was withheld.
An exact, unique identity-digest match with fresh authenticated inventory may
associate the local Mac. Missing/stale/ambiguous evidence remains unmatched.
Association is for display only and never authorizes a repair or remote command.

Tests use controlled account responses and temporary caches. Live evidence so far
covers scope negotiation, protected local public identity availability and the
fresh official console inventory. A completed Gargoyl grant/API inventory and
rendered native real-data acceptance must be recorded separately before claiming
the installed fleet manager is connected. Controlled tests do not prove a live
account grant or remote process health.

## Account linking purpose

The official verification page must be opened as
`https://console.darkbloom.dev/link?purpose=desktop_account`. The non-secret
purpose parameter selects the read-only account approval; opening bare `/link`
selects provider linking and rejects an account code with “authorization purpose
does not match this code”. This behavior is documented in Darkbloom 0.10.6
commit `84ddfdba6bb704bf1c68f97c7060289079380ceb`, `CHANGELOG.md` under
“Console desktop sign-in approval”, and its desktop external-link tests.

Gargoyl constructs only this fixed official URL. It never forwards server-supplied
query values, codes or tokens to a URL. A contradictory or duplicated purpose in
a verification response is refused. After a rejected attempt, cancel it and use
a fresh scoped graphical connection after the corrected app is installed; never
switch to a provider-purpose grant to work around a mismatch.
