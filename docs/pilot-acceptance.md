# Current pilot deployment and acceptance

Verified on MBP-26 on November 1, 2026. This records deployment evidence rather
than treating a tested library or a roadmap goal as an activated feature.

| Capability | Installed or verified | Remaining limit |
|---|---|---|
| Direct host collection | One Mac, `MBP-2026.local`; bounded owner-local state and selected normalized diagnostics | No independent process observation on the other machines |
| Account fleet inventory | Four actual account-owned provider records through the read-only account API | Status and heartbeats are coordinator reports, not independent remote health |
| Friendly identity | An editable local alias is associated with an actual provider ID; source hardware label is retained | Studio aliases have not been guessed; the pilot UUID is not a provider ID |
| Saved sign-in | Native login Keychain save and actual quit/reopen restore succeeded without another authorization | The original account grant expiry still applies; no refresh or provider-control grant was added |
| Local monitor lifecycle | User LaunchAgent, loopback-only port 8766, automatic restart of Gargoyl itself | This does not restart Darkbloom or authorize unattended repair |
| Recent traffic history | Up to 64 normalized samples in monitor memory | Lost on monitor restart; no deployed encrypted spool or independently configured clock reference |
| Manual provider restart | Native confirmation, owner authentication, fresh target checks and shared durable journal implemented; controlled fixture tests pass | No live provider restart/drain was executed; upstream provides no durable request ledger or exactly-once guarantee |
| Signed v1/v2 repair libraries | Synthetic policy, signature, journal and transport tests | Not the native manual-action backend: v1 refuses, v2 has no shipped provider backend |
| Encrypted spool and mTLS ingestion | Library APIs and controlled tests | No pilot spool-key provisioning, certificate enrollment, remote listener or deployed round trip |

## Authority boundary

The native GUI and its manual-action worker are separate processes under the same
Mac user. The installed monitor has browser operator tools and browser restart
disabled. The optional `--operator-tools --enable-restart` composition combines
viewer, collector and manual execution in one owner process. Application-level
confirmation and journal checks are not OS privilege separation. Same-user code
is outside that custody boundary. Separate OS/service identities remain a target
for a different deployment, not an existing pilot guarantee.

## Outstanding audit work

- #54 and #55: shared restart admission and non-TTY capability-output fixes merged
  in PR #64. Reconciliation permits a new confirmed attempt; it never proves the
  historical outcome or retries automatically.
- #60: test-only SQLite connection cleanup is in contributor PR #63; its restart
  changes overlap #64 and need reconciliation before that PR merges.
- #57: pilot host/UID/version and installation-path restrictions remain. Moving
  them into configuration must preserve fail-closed identity and compatibility
  checks. Recorded binary hashes are provenance, not restart authorization.
- #61: CI action pinning, more interpreter coverage, macOS coverage and dependency
  auditing remain CI hardening work.
- #56/#58/#59/#62: this page separates current coverage from the authority,
  persistence and deployment goals. It does not close their implementation or
  pilot acceptance requirements.

A new encryption-key source, credential enrollment, remote observation or real
provider restart is a separate consequential action. Existing account-session
Keychain consent does not authorize new spool keys or broader account access.
Nothing in this acceptance record activates those actions.
