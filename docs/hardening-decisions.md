# Remaining architecture and deployment choices

These recommendations do not activate features or request broad access. Continue
ordinary local development and tests without grants; obtain the specific consent
only when performing a consequential deployment action.

| Ticket | Recommendation | Actual user choice or approval needed |
|---|---|---|
| #56 authority separation | Keep the current loopback read-only monitor plus local native owner-confirmed actions, and state the same-user boundary honestly. Do not add privileged helpers just to claim isolation. | A different deployment that enforces OS isolation needs an explicit selected-host/service topology and approval for any new OS identity/helper/permissions. No such change is needed to keep today's pilot working. |
| #58 repair stacks | Keep v1/v2 marked integration-only and preserve their public APIs until a concrete backend exists. Share pure validation/presentation utilities incrementally; do not force the manual path into a protocol whose upstream proofs are unavailable. | Product choice to add remote/distributed repair, or retire an externally used API. Routine internal refactoring does not require making the user choose a security architecture. |
| #59 durable history | Implement local normalized history first, with a distinct app-bound login-Keychain encryption key, bounded seven-day/100MiB retention and explicit deletion rules. Do not conflate this key with account sign-in. | Approve creation/storage/use of that new encryption key and the retention policy before live activation. Existing read-only account-session Keychain approval is not this grant. Remote mTLS enrollment is separate and unnecessary for local-only history. |
| #62 pilot acceptance | Keep one directly observed Mac plus coordinator-reported inventory explicit. Next independent coverage should be selected read-only collectors, not inferred remote health. | Explicitly select and authorize installation/source access on each additional machine before connecting it. Any certificate/key enrollment requires its own concrete approval. A real provider restart requires a separately requested maintenance action with exact target, impact and native confirmation; none is performed for these hardening tickets. |

For a future live manual acceptance run, recommend an operator-selected quiet
maintenance window, fresh verified local target, the existing supported graceful
drain/startup timeouts and one attempt. No force, unattended retry or blind gate
clearing. If interrupted or unverified, retain the journal and reconcile read-only
before considering another separately confirmed attempt. This is a recommendation,
not authorization to test a live workload.
