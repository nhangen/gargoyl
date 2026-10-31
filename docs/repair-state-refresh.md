# Owner-local daemon-state refresh through the repair runtime

`DaemonStateRefreshAdapter` implements only the existing `status_refresh` operation.
It reads the explicit owner-local daemon JSON and publishes fresh normalized
observations into an explicitly supplied encrypted `EvidenceStore`. It launches
no provider command, writes no source file, contacts no service, discovers no
configuration and loads or creates no credentials.

This is an observation refresh, not provider restart, model recovery or proof of
liveness. It adds no CLI, repair HTTP route, enable flag or automatic repair loop.
The live read-only monitor remains independent and does not construct this adapter.

## Composition and authority

```python
from gargoyl.repair_state_adapter import DaemonStateRefreshAdapter
from gargoyl.repair_runtime import RepairRuntime

adapter = DaemonStateRefreshAdapter(
    target_host,
    source_path=explicit_canonical_path,
    expected_owner_uid=explicit_uid,
    store=encrypted_evidence_store,
    wall_clock=utc_clock,
    total_timeout_seconds=6,
)
runtime = RepairRuntime(
    catalog=verified_pinned_catalog,
    audit=encrypted_one_shot_audit,
    authorization=scoped_operator_authorization,
    evidence=current_evidence_reader,
    wall_clock=utc_clock,
    adapter=adapter,
)
receipt = runtime.execute(plan, confirmation, stop_event=stop_event)
```

All objects above are separately supplied trusted dependencies, not caller-provided
booleans or wire capabilities. The constructor validates source configuration,
store identity membership, clocks and budget before reading anything. Invoke only
through `RepairRuntime`: the adapter itself is not an authorization endpoint and
does not independently authenticate a plan or a human click.

Existing signed/pinned runbooks, exact host/operation/operator grants, expiring
signed intent, current preflight rechecks and durable one-shot audit claims are
unchanged. A successful result is possible only after the encrypted evidence store
returns exactly `True`. Production activation requires an explicitly authorized
composition supplying catalog trust, operator verification, evidence encryption
and audit keys. This change neither provisions those identities nor permits a
collector identity to stand in for operator authorization. New persistent keys,
trust enrollment or access grants require separate approval. No such activation
has been performed.

## Fail-closed source and publication behavior

The shared JSON reader retains its no-symlink traversal, private owner-matched
parent, owned regular single-link file, strict schema and 64 KiB checks. No
permissions are changed. Source configuration uses the same pure validation as
inspection and the monitor. There is no process-command fallback.

At least one selected reading must be present, and every selected reading must
remain observed at publication. Missing, malformed, future, stale, empty or
inaccessible evidence produces `failed/operation_failed` with no publication.
The adapter revalidates the fixed metric allowlist, daemon provenance, original
observation timestamp and TTL 60. Source timestamps are never refreshed. Missing
metrics stay unknown; counts/model residency never establish provider liveness,
in-flight work, drain acknowledgement or earnings. Raw identities, model names,
extra JSON and exception text are not persisted or returned.

Calls serialize by nonblocking adapter lock. Cancellation before publication
performs no write. Logical monotonic and real elapsed clocks check the declared
budget (positive, at most 30 seconds and no greater than the signed manifest).
Source and store filesystem operations are not forcibly bounded or sandboxed.
An exceeded budget prevents publication when detected beforehand. Freshness and elapsed budget are checked again after acceptance. Evidence that
expires during a commit returns `outcome_unknown/invalid_result`, retaining the
original record and consumed intent. A late accepted
write, cancellation during acceptance, storage error, clock rollback or audit
finalization failure can leave durable evidence: report `outcome_unknown`, keep
intent consumed, and never roll back or automatically retry. The caller retains
store ownership and must close it after adapter use.

## Broader repair policy remains unresolved

The other existing state-changing runbooks remain blocked and gain no adapter.
The pinned upstream [restart command](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/darkbloom/RestartCommand.swift)
and [drain implementation](https://github.com/Layr-Labs/d-inference/blob/6a78624b4b46329a6d1535435f7cd9d7f4ebb4c6/provider-swift/Sources/darkbloom/ServiceDrain.swift)
show why a generic bounded command wrapper is insufficient: drain disables the
watchdog and automatic startup before waiting, and timeout may leave serving
fenced. Defaults allow 600 seconds for drain and 180 for startup confirmation,
plus shutdown time, exceeding the existing 30-second repair contract. No force
flag, timeout policy, in-flight/drain proof or recovery override is invented here.
A provider restart needs an explicit policy for its maintenance/drain window and
an authoritative host-specific execution/preflight contract before implementation.
Model retry and reconciliation likewise require their existing missing inputs.

## Verification

`python -m unittest discover -s tests -p test_repair_state_adapter.py -v` uses only
private temporary synthetic sources, ephemeral test signing/encryption keys and
real encrypted stores. It proves durable normalized refresh without source writes,
commands or network; strict failures; source ageing; cancellation; real/logical
budgets; signed authorization; claim-before-read; revocation during claim; replay
protection and uncertain publication/audit failure. It also verifies that all three
signed disruptive plans remain blocked. These are controlled fixtures, not live
provider repair or production enrollment evidence.
