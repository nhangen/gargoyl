# Explicit local observation adapters

`StatusRefreshAdapter(target_host, *, acquirer, store, wall_clock,
monotonic_clock=time.monotonic, total_timeout_seconds=6.0)` connects the existing
BoundedAcquirer to EvidenceStore.accept. It implements the repair adapter protocol:
read-only total_timeout_seconds, supported_operations containing only
status_refresh, and execute(plan, *, stop_event) returning OperationResult.

`DiagnosticsCaptureAdapter` has the same constructor and execution protocol,
but supports only `diagnostics_capture`, invoking fixed `doctor` acquisition.
Both adapters share one private execution path; operation, source and metric
choices are fixed per adapter, never supplied as arbitrary command arguments.

The acquirer and store are explicit, trusted concrete dependencies and remain
caller-owned. Construction checks host membership in EvidenceStore's fixed cipher
inventory through its read-only `configured_hosts` frozenset,
clock callability and finite budgets. Total budget must cover the acquirer's full
execution/cleanup budget and fit the signed manifest timeout. The adapter rejects
wrong-host, blocked, mismatched-operation and disruptive requests before launching. The
adapter is not an authorization endpoint: call it through RepairRuntime with the
verified catalog, separate operator authorization, current preflight and durable
one-shot claim. It does not authenticate signatures or human clicks independently.

StatusRefreshAdapter acquires only darkbloom_status_text_v1. Exact normalized daemon provenance,
TTL 60 and acquisition-start timestamps are retained in the existing v1 snapshot;
missing metrics remain unknown. A valid stopped observation is a successful
refresh when durably accepted, not a claim that the daemon is healthy. Raw output,
paths, exception messages and environment contents are never published.

DiagnosticsCaptureAdapter acquires only darkbloom_doctor_text_v1. The existing
strict parser requires all eight consistent checks and their summary. Complete
failed checks produce observed doctor_state=failed and can be successfully captured;
this is not a successful repair or a healthy-host claim. Malformed/missing/duplicate
checks, inconsistent totals, nonzero exit, timeout and output overflow never produce
evidence. Non-evidence footer advice may be incomplete after a complete report.
Only doctor_state/source=doctor is persisted, with the original observation time;
raw diagnostic text and advice are discarded. No fix commands run.

Cancellation and elapsed deadlines are checked before publication. A timeout or
incomplete cleanup never publishes partial output. Incomplete cleanup disables
this adapter instance. The borrowed acquirer also preserves its own cleanup halt.
The adapter does not close the store or create background lifecycle threads.

EvidenceStore.accept must return exactly True before success. Filesystem and
SQLite latency cannot be forcibly bounded: a late durable acceptance or a stop
arriving during acceptance returns outcome_unknown, and the accepted evidence
remains. No rollback, cancellation of a committed record, replay or retry is
implied. Storage failure maps to outcome_unknown/audit_unavailable using the
existing fixed result enums. Wall-clock rollback is clock_invalid. Trusted clock
callbacks must return promptly; this is not a hard real-time or OS sandbox API.

Only synthetic subprocesses and temporary encrypted stores are tested here.
Real Darkbloom status/doctor perform network/configuration/account/security reads;
see collector_acquisition_README.md for pinned-source side effects. No real
producer invocation, host enrollment, signing-key provisioning, deployment,
installation, credential reads, access changes or repair has been performed.
The operator must separately authorize an actual target and trust its executable,
environment, working directory and dependencies before any real invocation.

For owner-local JSON refresh without any producer command, see
[`DaemonStateRefreshAdapter`](repair-state-refresh.md). It uses the same
`status_refresh` identity and unchanged runtime authority/audit requirements.
