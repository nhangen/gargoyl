# Operator intent verification (local integration, no enrollment)

This module verifies possession of an explicitly trusted operator signing key and
current grants. It does not establish a human click, production identity enrollment,
OS/service identity separation, hardware-backed key custody, or a trustworthy browser.
No private-key loader, signing service, credential configuration, HTTP endpoint or
production adapter is provided. Tests generate temporary synthetic keys only.
Existing repair/telemetry/receipt/audit schemas and catalog trust stay unchanged.

## Pinned Python API

```python
from gargoyl.repair_operator import (
    OperatorPrincipal, OperatorKey, OperatorRegistry,
    OperatorAuthorization, OperatorReadAuthorization, OperatorReadScope,
    repair_intent_bytes, read_intent_bytes,
)

OperatorPrincipal(
    actor_id, repair_grants=frozenset(),
    evidence_hosts=frozenset(), audit_hosts=frozenset(),
)
OperatorKey(public_key, principal)
OperatorRegistry(keys_by_id)
OperatorAuthorization(
    proof, *, registry_provider, audience, wall_clock,
).authorize(plan, confirmation)  # None on success, safe PolicyError on denial
OperatorReadAuthorization(
    request, proof, *, registry_provider, audience, wall_clock,
).read_scope()  # OperatorReadScope
```

`OperatorPrincipal`, `OperatorKey`, `OperatorRegistry` and `OperatorReadScope` are
frozen, detached data. Principal actor_id and all hosts/audience/request IDs are
canonical opaque UUIDs. Grants are exact `(host_uuid, runbook_id)` tuples in a
frozenset, not a host/runbook Cartesian product. Runbooks are the existing five
allowlisted IDs; granting one never overrules catalog/runtime preconditions.
Read scopes are two independent frozensets, evidence_hosts and audit_hosts. A repair
grant implies neither read scope; read permission never implies repair permission.
The union of all host IDs in one principal is capped at 16. Empty grants are valid.
No wildcard, tenant expansion, hostname or customer identifier is accepted.

Registry constructor takes a dict of 1..64 key IDs to `OperatorKey`. IDs use existing
`[a-z0-9][a-z0-9_-]{0,63}` grammar. Public keys are raw immutable 32-byte Ed25519 bytes.
Duplicate public keys under multiple IDs are rejected to avoid ambiguous identity
bindings. Multiple distinct keys may map to one actor for externally managed rotation.
The registry copies and revalidates all entries; caller mutation cannot change it.
Replace the entire registry to change grants/revoke keys; no enrollment/update API.
`registry_provider()` returns the current exact OperatorRegistry instance on each
verification. It is an explicitly trusted bounded local read callback, not request data.
Provider failure, missing key, forged registry/principal contents or invalid signature
fail closed with fixed text. There is no cached authorization result.

Proof is a plain dict with exactly `key_id: str` and `signature: bytes` (64 bytes).
It is detached at authorizer construction; no base64/hex wire format is introduced.
Callers with an existing external signing boundary obtain exact bytes with:

```python
repair_intent_bytes(audience, confirmation: RepairConfirmation) -> bytes
read_intent_bytes(audience, request: dict) -> bytes
```

These helpers validate data but do not sign or authorize it. Repair bytes are
`b"gargoyl:operator:repair:v1\x00" + canonical({"audience": audience,
"confirmation": confirmation.as_dict()})`. Read bytes use distinct
`b"gargoyl:operator:read:v1\x00"` context and canonical `{"audience": audience,
"request": request}`. Canonical encoding is the existing bounded repair convention.
Runbook signatures, read signatures and repair signatures are not interchangeable.
Audience is an explicit opaque verifier/service identifier, never derived from a
request URL. Wrong audience, actor, host, operation, click, plan/runbook digest or
version invalidates repair verification or its exact grant/binding checks.

Read request is exactly:

```json
{"schema_version":1,"actor_id":"00000000-0000-4000-8000-000000000002",
 "request_id":"00000000-0000-4000-8000-000000000010",
 "issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:01:00Z"}
```

Lifetime must be positive and <=60 seconds. Read verification requires
issued_at <= now < expires_at and registry actor match. Output is exactly:
`OperatorReadScope(actor_id, evidence_hosts, audit_hosts, expires_at)`; the expiry
attribute is named **expires_at**. Sets come exclusively from the current registry.
A fabricated scope is not authorization. Read requests may repeat within validity;
reading cannot consume repair intent or authorize execution. Repair replay protection
remains the existing durable one-use click claim in RepairAuditStore.

Each authorizer serializes calls, checks time after provider/signature verification,
and rejects backwards time relative to its own last completed clock read. This does
not provide persistent clock rollback protection across process restarts. Trusted
provider/clock callbacks must return promptly; the library cannot preempt arbitrary
in-process callbacks. Public authorize/read_scope failures return fixed
`PolicyError("operator authorization unavailable")`, without private exception text.

## Runtime and report consumer requirements

RepairRuntime must still validate catalog and current preflight and durably claim the
click. Use OperatorAuthorization as its separately supplied authorization boundary.
The runtime rechecks authorization after its post-claim current preflight/time checks,
immediately before invoking an adapter; revocation during claim consumes the claim
and records refusal rather than running an operation. No retry/reset/resume follows.
This callback is permission validation, not a second click or claim consumption.

The read-only report accepts OperatorReadAuthorization and calls read_scope itself.
It filters expected hosts to evidence_hosts and audit entries to audit_hosts before
rendering any associated fields, identifiers, counts or incidents. Unauthorized hosts
are omitted. Missing and unauthorized audit entries share one generic unavailable
presentation; do not disclose existence or owner. Corruption/storage/authorization
failure returns unavailable, never healthy partial data. Recheck authorization before
returning: if scope changes, fail closed rather than return data assembled under stale
grants. A read scope does not confer authority to enumerate audit IDs.
Report inputs are separately bounded: <=16 expected hosts, <=32 distinct supplied
canonical audit UUIDs, <=256 snapshots and <=1 MiB aggregate canonical evidence.
No execution forms, action links or HTTP route changes belong to this report.

## Scope and verification

Run `python -m ruff check .` and `python -m unittest discover -s tests -v`.
Tests use ephemeral Ed25519 keys, opaque synthetic IDs and fixed clocks. Signing
key possession cannot prove a human action. Audit attribution remains an assertion
of the authenticated runtime; existing audit records do not store operator signature
proof and are not independent proof of the original signed request. No audit schema
migration is performed. Production enrollment/revocation operations and deployment
remain separately authorized work; epics #4/#5 remain open.

The status-refresh adapter is a separate lane. Its actual acquisition has bounded
process cleanup, but synchronous local filesystem operations are not forcibly timed
out. Late/uncertain durable publication must return outcome_unknown; cancellation
cannot roll back an accepted record. This milestone makes no hard total filesystem
deadline or live-host readiness claim.
