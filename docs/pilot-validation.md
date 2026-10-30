# Operator report and pilot validation

This code slice is a read-only report, not a deployed operator console. It adds no
HTTP route, form, execution control, identity enrollment or credential loader.
Production setup and a three-host pilot remain separate, target-authorized work.
Synthetic tests cannot establish live fleet health, paid earnings, operator
identity enrollment or proof that a human clicked a confirmation.

## Report boundary

`render_operator_report` accepts the shared `OperatorReadAuthorization`, an
evidence reader exposing `snapshots(now=...)`, an audit reader exposing
`lookup(click_id)`, explicit expected hosts, audit IDs and an evaluation timestamp.
Authorization is checked before reading and again immediately before returning.
A changed or expired scope discards the result. The caller supplies a trustworthy
evaluation clock; authorization independently uses its configured wall clock.

Evidence grants and audit grants are independent. Evidence outside the grant is
omitted, including host identifiers, counts and incidents. An audit grant permits
reading the host's historical preflight embedded in its audit record, but does not
grant its current evidence stream. A missing audit and a denied audit have the same
generic unavailable presentation. Neither result establishes absence of effects.

Inventory is an explicit list or tuple of at most 16 distinct canonical host UUIDs.
Audit selection is a list or tuple of at most 32 distinct canonical UUIDs; duplicate,
noncanonical and lazy inputs are rejected. Readers return at most 256 snapshots;
canonical snapshot and audit payload bytes together must not exceed 1 MiB.
All supplied records are validated, including records later omitted by scope.
Corrupt data, failed storage reads, invalid input or failed authorization returns a
single generic unavailable page, without a partial apparently healthy report or
raw exception content. These limits bound accepted data, not arbitrary reader
implementation work or filesystem latency.

Existing dashboard semantics remain authoritative: missing, stale, future and
conflicting observations never become health. Source and observation/collection
timestamps remain visible. Historical started claims remain outcome unknown;
receipts confer no retry permission and do not establish current catalog trust.
The HTML is static. Refresh wording is not a browser scheduler: callers must
regenerate reports to reevaluate freshness and read authorization.

## Synthetic acceptance checklist

The composed suite must use ephemeral Ed25519 keys, temporary encrypted evidence
and audit stores, opaque fixture identities and synthetic adapters only:

1. Sign a bounded read request with the shared signing contract. Verify evidence
   and audit grants independently, including an audit-only host and an omitted
   evidence host with a distinctive incident.
2. Verify wrong keys, audience, expiry, registry revocation and grants changed
   during reads discard all output. No proof or private key is rendered.
3. Restart the real stores and render durable evidence and receipts. Check stale,
   missing and contradictory evidence, and started claims requiring recovery.
4. Exercise missing/denied audit equivalence, damaged encrypted data, lookup
   failure and malformed/binding-mismatched wrappers. Never return partial health.
5. Exercise snapshot, canonical byte, inventory and audit-count limits. Verify
   safe fixed errors and no controls, scripts or routes.

These are acceptance requirements; completion is reported with the actual test
commands and results in the PR, not inferred from this checklist.

## Before any separately authorized live pilot

Record the exact reviewed code revision, target inventory, enrolled operator
registry and revocation procedure through the approved setup process. Establish
who may read evidence, who may read audit history and who may request each exact
host/runbook operation. A signed intent is not proof of a human click.

Compare actual source evidence with dashboard timestamps and observe expiration
after collection stops. A bounded transport failure must retain pending evidence;
it does not establish continuous collection cadence while synchronous work blocks.
Check stopped/failed/incomplete shutdown reports without claiming child containment
or successful cleanup from an interrupted process.

For status refresh, distinguish source observation from durable publication.
Filesystem latency is not forcibly bounded. Publication that finishes after its
budget must remain `outcome_unknown`; cancellation does not roll back an accepted
record. Started claims and uncertain outcomes must not trigger automatic retry.
No disruptive operation, model load, reconciliation or installation is authorized
by this report or checklist.

## Local acceptance evidence for this slice

`python -m unittest discover -s tests -p 'test_operator_report*.py' -v`
executes 11 report tests. Nine use real signed read intents and temporary stores;
the successful execution and finalize-failure cases also compose the actual
operator authorization, repair runtime, bounded acquisition and status adapter.
The only executable is a test-authored script printing synthetic status text.
Ciphertext corruption is injected into the local SQLite stores and restored to
verify unavailable output and subsequent recovery. No production key or host is
involved. These checks do not satisfy the separate live-pilot acceptance criteria.
