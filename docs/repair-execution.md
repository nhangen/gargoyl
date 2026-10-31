# Repair execution and local audit (synthetic integration)

`RepairRuntime(catalog=..., audit=..., authorization=..., evidence=...,
wall_clock=..., adapter=None, monotonic_clock=...)` exposes
`execute(plan, confirmation, *, stop_event) -> RepairReceipt`. The wall clock
returns strict UTC text. `evidence(target_host)` supplies current telemetry.
`authorization.authorize(plan, confirmation)` is a separately supplied trusted
boundary: authenticate the actual user action and authorize its exact actor,
host, operation, version and plan. Return None only on success; raise on denial.
A caller-supplied boolean, confirmation object or collection identity is not proof.
OperatorAuthorization in `repair_operator.py` verifies explicitly supplied operator
signatures and current scoped grants; see [operator-auth.md](operator-auth.md).
No production enrollment or human-click proof is supplied.

Catalog signatures/pins and confirmation binding are revalidated, and current
preflight evidence/checks must match the confirmed plan. Evaluation time alone
may advance. After the durable claim (which can wait on SQLite), runtime obtains
current evidence again and rechecks time, confirmation and catalog. It then rechecks user authorization
immediately before invocation, and validates time/expiry/catalog/preflight again
after authorization returns so a slow authorizer cannot extend intent validity.
Revocation during claim produces a durable claim-stage refusal with no invocation. Expiry or changed preflight leaves the claim consumed and stores
a claim-stage refusal; slow authorization/evidence cannot extend intent validity.
Missing disruptive-operation preconditions remain blocked. The
shipped RefusingAdapter supports no operations and refuses before claiming.
Only self-authored synthetic adapters are used in tests. No host commands,
restart, model loading, reconciliation or automatic telemetry-triggered repairs.

Adapters follow docs/repair-contract.md. They must enforce their declared total
cleanup-inclusive deadline and truthfully report uncertainty. Runtime checks
elapsed time using real and injected monotonic clocks after return; it does not
forcibly stop arbitrary Python callbacks or claim sandbox containment. Trusted
authorization, evidence, clocks and adapters must themselves be bounded. Stop
is cooperative. Timeout, interruption, invalid result or uncertain cleanup yields
outcome_unknown; no retry, resume, rollback or background repair is attempted.
Backward finish time yields clock_invalid with the last validated start time.

RepairAuditStore uses a separate AES-GCM repair domain, private newly created
files, SQLite FULL synchronous transactions and an authenticated record count.
SQL row-count/type/length checks precede ciphertext materialization and decryption;
oversized or wrongly typed storage fails closed. Every transaction authenticates
the inventory and every bounded record, including
for absent lookups. Existing corrupt databases, wrong keys, missing rows and
capacity exhaustion fail closed. Claims consume click IDs before invocation;
terminal envelopes are size-checked beforehand. Finalization is exact-idempotent
and cannot overwrite another result. Concurrent store connections serialize claims.
No replay eviction, pruning, automatic key loading or provisioning is provided.
The caller must supply a private local directory and key. Trusted owner deletion
or rollback of the entire store is outside these local durability guarantees;
this is not a tamper-proof external audit service.

Lookup validates historical schema/authentication without current catalog expiry.
A started entry after restart means outcome_unknown/recovery_required and must
remain consumed. Lookup never executes. A final audit failure reports
outcome_unknown/audit_unavailable even if the adapter reported success; a commit
whose outcome is uncertain must be inspected read-only, never retried as repair.
Returned receipts alone do not establish durable storage or executor identity.

Epic #4 remains open for authenticated clicks, authoritative host preflight,
actual bounded host adapters, production identity separation and live acceptance.
These tests prove local synthetic control flow only. Parent coordinates review,
CI and integration; no installation or live repair is authorized here.

The separately versioned [pre-drained restart v2](pre-drained-restart-v2.md)
implements policy gating, signed proof verification and an atomic host journal for
controlled integration. It does not unlock v1 plans or ship a production backend.
