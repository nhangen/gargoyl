# Read-only repair presentation

This slice adds three pure HTML renderers in `gargoyl.repair_view`. They do not read
stores, issue tokens, execute adapters, authenticate people, or change HTTP routes.
There are no forms, buttons, action links, scripts or retry/resume operations.

- `render_preview(plan, catalog, *, now, confirmation=None)` requires exact shared
  RepairPlan/RunbookCatalog types, reconstructs the plan through shared validators,
  and revalidates signatures, current pins, plan time and recorded checks. An optional
  RepairConfirmation is independently reconstructed and checked for exact host,
  runbook/version/digest, plan digest and time binding. That establishes intent-data
  consistency only, never identity, an actual click, or permission.
- `render_receipt(receipt)` reconstructs shared RepairReceipt data and renders the
  reported result and bound preflight. It deliberately has no current catalog/time
  dependency: revoked artifacts and expired previews must not erase historical data.
- `render_audit_entry(entry)` reconstructs shared RepairAuditEntry data. A started
  claim is explicitly outcome unknown/recovery_required with no retry/reset/resume.
  None means no entry supplied, not proof that execution or side effects are absent.

Every public renderer returns a complete standalone HTML string. Invalid shape,
forged preview checks/signatures, wrong confirmation bindings, invalid time, or a
validator error returns a fixed unavailable/unknown page without exception text or
partial validated details. All displayed values pass through HTML escaping.

## Evidence and safety boundaries

Preview shows exact opaque host, runbook ID/version/digest, original plan digest,
operation/timeout, original evaluation/expiry, all preflight checks, and each evidence
value/state/source/observation time/collection time/TTL. Contradictory observations
remain visible. A second assessment uses catalog.plan at current display time,
without replacing the original plan or confirmation binding. Evidence that expired
within the plan's 60-second lifetime is therefore shown unknown in current checks,
while the recorded preflight remains historical evidence.

Status refresh and diagnostics capture can have no blocking required catalog checks
even with unknown evidence: evidence freshness is informational for these operations.
The page says preview only and explicitly leaves authenticated confirmation and
adapter availability unestablished. Restart, model load retry and reconciliation
remain blocked on their missing authoritative prerequisites. No in-flight count,
drain acknowledgement, selected model, memory threshold or approved reconciliation
scope is invented. Unknown evidence never grants authority.

Historical data is not an authentication channel. A well-shaped receipt may be
fabricated by a caller; class identity or a reported succeeded value does not prove
execution, durable storage, signature verification, or a legitimate user click.
The renderer validates historical shape/bindings and labels all outcomes/checks as
reported historical data, without presenting them as independently verified facts.
Cryptographic audit authentication belongs to the separate store/runtime boundary;
current catalog membership is neither a substitute nor a prerequisite for historical
lookup. Trusted in-process Python code is not sandboxed by these APIs.

Failed, blocked or cancelled results grant no retry permission. Outcome_unknown
explicitly warns that side effects may have occurred. Clock-invalid outcomes explain
that finished_at is a fallback bound rather than a trustworthy completion time.
Even successful reported outcomes cannot authorize another operation.

## Verification and limitations

Foundation pin: `dc811aee5e7b7b34a0733a228e43f2d0a20eb84c` (PR #15).

Run `python -m ruff check .` and `python -m unittest discover -s tests -v`.
`tests/test_repair_view.py` generates ephemeral signing keys and synthetic fixtures;
it verifies all five runbook previews, missing prerequisites, original/current
freshness, conflicting/future/unknown evidence, exact confirmation binding, tampered
preview proofs, historical receipt display after catalog replacement/expiry, missing
or interrupted claims, safe failure text and absence of actionable controls.

Actual catalog-to-runtime-to-encrypted-audit-to-view acceptance awaits the executor
lane's pinned handoff. No production key, real repair, upstream command, host install,
credential/permission/access/DNS change or deployment is part of this implementation.
Epic #4 remains open for authenticated click integration, actual host preflight and
operations, and deployed separation from collector identities. No one-click repair
capability is claimed by a read-only preview.
