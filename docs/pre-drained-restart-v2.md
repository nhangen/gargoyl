# MBP-26 pre-drained restart protocol v2

This implements the approved **implementation-only** policy: a single restart of
an already drained provider, using its existing active model/configuration, with
new work fenced, zero outstanding accepted work and fresh matching coordinator
acknowledgement. There is no force, CLI fallback, drain initiation, automatic
unfencing, retry or resume. Success means **a verified replacement still fenced**,
not restored serving availability.

The v2 path is separate from the existing v1 repair contracts/runtime/audit. V1
remains unchanged and continues to block disruptive operations. No CLI, HTTP
repair endpoint, service change, network listener or automatic repair loop is
added. No production mutating backend ships; `backend=None` refuses before claim.
No live provider restart, credentials or enrollment were performed for this work.

## Authoritative preflight and consent

`RestartPolicy` pins one explicit local host UUID, one backend installation/ledger
UUID, provider public keys, the existing signed/pinned runbook catalog and an
independent local process verifier. Only a pinned `drained_provider_restart`
runbook version **2**, timeout 1–30 seconds, is eligible. Old v1 operator signatures,
plans and confirmations cannot authorize v2.

A domain-separated signed provider state binds all of:

- Host, backend installation, challenge, fixed v2 policy and issue/expiry times.
- Current PID, owner UID and native process birth microseconds; not a PID alone.
- Drain and admission-fence identities; matching drain acknowledgement and process.
- `admission_fenced=true`, `outstanding_work=0`, coordinator acknowledgement true.
- Digests of the **active** configuration and model selection, not raw names/paths.

Outstanding work must include accepted requests and unfinished terminal delivery.
Cumulative usage counters, file presence, an empty status response, logs and a
claimed offline coordinator exception are never substitutes. Missing/invalid
proof, any unfinished work, changed identity/fence/configuration or missing
acknowledgement refuses planning/execution. No override fields exist.

Proofs and signed v2 confirmations have at most five seconds of validity. They
are not redated. `RestartAuthorization` uses the existing detached
`OperatorRegistry` and exact `(host_uuid, drained_provider_restart)` grant, with a
new v2 operator-signature domain and backend audience. Intent binds the complete
plan digest, runbook digest/version, actor, click, host and policy. It rereads
current grants; a collector identity, unsigned boolean or provider key is not
operator authorization. A signature does not itself prove a human click.

`MacOSProcessVerifier` uses read-only Darwin `libproc` birth/UID/image queries.
It is explicitly configured for the current user's UID and canonical provider
image; it checks identity before and after reading the image path. Denied,
missing, zombie, mismatched image/UID/birth or unsupported-platform queries refuse.
There is no `ps`, signalling, fallback, permission change or process discovery.
Native tests inspect only their own test process, never an installed provider.
Other process-verifier callbacks are trusted application capabilities, not wire
inputs. Neither these callbacks nor Python objects constitute an OS sandbox.

## Atomic host gate and one dispatch

`RestartJournal.create(...)` is explicit provisioning of an empty private store,
not a runtime recovery operation. `RestartJournal(...)` opens **existing** state
only (SQLite `mode=rw`); missing directory/database, wrong key, corruption,
file replacement, unsafe protection or capacity exhaustion refuses. Never call
`create` to recover missing state. Parent/store directories are private owned
local directories; database files are regular, owned, single-link, mode 0600.

In one SQLite FULL-synchronous transaction the journal authenticates inventory
and records, consumes the click ID and reserves the single host. Concurrent
runtimes/processes cannot reserve different clicks for the same host. A concurrent
call on the same runtime refuses immediately rather than queueing outside its
execution budget. The separate
v2 AES-GCM domain binds the host; the supplied 32-byte key is never persisted here.
Records are bounded (1–1000 configured capacity, 64 KiB each), and consumed IDs are
never evicted/reset. Owner deletion or whole-store rollback is not made
impossible by encryption; recovery must not silently initialize a new store.

After the claim, the runtime rereads provider state, rechecks signed intent,
current grants, original proof/intent expiry, process identity, fence and active
configuration. It makes at most **one** `restart_once` call. Any subsequent attempt
needs a fresh plan and separately signed intent.

The host gate remains held after **every** claim, including success and a
pre-dispatch cancellation/refusal. This is intentionally stronger than gating only
unknown outcomes. Finalization failure, interrupted call, lost reply, invalid
proof, expired result, late completion or incomplete cleanup never permits retry.
An accepted effect cannot be rolled back by this client.

## Required provider backend (activation blocker)

The backend is an explicitly supplied trusted local capability with fixed policy,
`total_timeout_seconds <= 30`, `cleanup_inclusive=True`, and three methods:

```python
observe(challenge, *, deadline, stop_event) -> signed_state_bytes
restart_once(request_bytes, *, deadline, stop_event) -> RestartBackendResult
reconcile(request_bytes, challenge, *, deadline, stop_event) -> signed_resolution_bytes
```

`observe` and `reconcile` must be read-only for provider state. `restart_once` must
independently authenticate the caller/intent and enforce expiry; atomically compare
process/fence/configuration at the mutation point; durably consume the attempt in
a surviving lifecycle ledger; stop only the identified already-drained process;
start the existing configuration/model selection with admission **still fenced**;
and enforce the shared deadline internally, including its owned cleanup. It must
never force, retry, unfence or let an old request execute after its deadline.
The installation/ledger identity and fence must survive process replacement.

A successful domain-separated signed result binds request digest and attempt,
old and replacement birth identities, unchanged fence/model/configuration, fresh
replacement authorization and permanently terminal/no-pending ledger state. The
client independently verifies the replacement's native process identity and
rechecks freshness/budget after verification. A client timeout or boolean cleanup
claim alone does not establish provider completion.

The stock provider CLI is **not a compatible backend**. At pinned upstream
[RestartCommand](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/darkbloom/RestartCommand.swift)
and [ServiceDrain](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/darkbloom/ServiceDrain.swift), restart can create a new drain request and rearm recovery before
confirmation; it does not provide this atomic fence-preserving ledger protocol.
It must not be wrapped as if it met these guarantees. A compatible provider-side
implementation and its own durable-ledger/deadline acceptance tests remain required.

Client real/logical clock checks detect lateness and report uncertainty. They
cannot preempt a lying callback or forcibly bound SQLite/filesystem/kernel calls.
The UTC request deadline is no later than the signed confirmation time plus the
pinned timeout; the runtime also supplies a shared monotonic deadline. A production
backend must correctly translate/enforce that deadline, including cancellation and
cleanup, rather than relying on post-return checks or continuing work in a thread.
No hard production 30-second guarantee is claimed without that backend acceptance.

## Read-only reconciliation before another attempt

`runtime.reconcile(challenge=..., stop_event=...)` queries only the exact active
attempt. A fresh signed reconciliation must bind host/backend, request digest,
attempt ID/gate generation, current verified process/fence/configuration, zero
work and matching drain acknowledgement. It must prove the old request
**permanently terminal and unable to execute later**, not merely absent from a
ledger. The journal atomically records that proof and clears only that gate;
the original receipt/unknown state and consumed click remain in history.
An old proof cannot clear a newer gate. Reconciliation never invokes restart.

A request claimed then refused before dispatch may have no backend ledger entry.
The gate still holds. `not found`, age, an operator retry, file deletion or an
unsigned inspection cannot clear it. A real backend/recovery design must be able
to establish an irreversible terminal/no-pending fact, including enforced request
expiry, without mutating provider state. If it cannot, the host stays blocked for
separately reviewed recovery. There is no gate-reset or force-clear operation.

## Remaining activation approvals

No production keys are generated/loaded. Activation needs a separately authorized
local composition and compatible backend, then explicit choices for:

1. A pinned version-2 runbook and provider verification key scoped to MBP-26 and
   its stable backend/ledger identity. The provider signing key belongs to that
   surviving control authority, not the collector or an automatically reused
   upstream attestation key.
2. An operator key/registry with exactly MBP-26's restart grant, and a trustworthy
   per-action confirmation/signing surface. No wildcard or other-host grant.
3. Dedicated journal-key custody outside the database and a private directory,
   for example `~/Library/Application Support/Gargoyl/restart-v2/`. Explicit
   creation is provisioning; ordinary startup must open existing state only.

Private signer/key custody (for example an approved Keychain/hardware boundary),
public pins and encrypted storage locations require separate approval. No new OS
privacy grants, external access or multi-host enrollment are implied. These choices
are not made by the implementation-policy approval.

## Test evidence and limits

Controlled tests use ephemeral keys, private temporary encrypted journals and an
**in-memory simulated** provider/ledger. They exercise conditional replacement,
revocation/expiry around claims, concurrent clicks, stale/replayed proofs, lost
replies, pending/unknown effects, journal corruption and ambiguous commits,
read-only reconciliation and inability to reset consumed IDs. They do not measure
a durable production backend or restart a live provider.

The native verifier test measures only the test process. A separate owned child
fixture measures transport termination/reaping with a 0.6-second requested budget
and a 1.5-second assertion; it is not evidence of a hard production 30-second bound.
Neither fixture authorizes production activation. Existing v1 and monitor tests
remain required and their code is unchanged.
