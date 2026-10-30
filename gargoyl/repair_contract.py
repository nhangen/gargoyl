"""Bounded repair v1 data, never a user authentication or execution capability."""

import hashlib
import json
import re
from dataclasses import dataclass

from gargoyl.telemetry import PolicyError, host_id, timestamp, validate_snapshot

MAX_REPAIR_BYTES = 65536
MAX_EVIDENCE_RECORDS = 16
RUNBOOK_IDS = frozenset({
    "status_refresh", "diagnostics_capture", "drained_provider_restart",
    "model_load_retry", "stale_state_reconciliation",
})
OUTCOMES = frozenset({"succeeded", "blocked", "failed", "cancelled", "outcome_unknown"})
REASONS = frozenset({
    "completed", "preconditions_blocked", "authorization_denied", "confirmation_expired",
    "plan_changed", "catalog_rejected", "already_claimed", "audit_unavailable",
    "operation_unavailable", "operation_failed", "deadline_exceeded", "cancelled",
    "cleanup_incomplete", "interrupted", "invalid_result", "recovery_required", "clock_invalid",
})
STAGES = frozenset({"preflight", "claim", "execution", "completion"})
CHECK_IDS = frozenset({
    "artifact_verified", "evidence_fresh", "in_flight_work", "drain_acknowledgement",
    "selected_model", "model_memory_requirement", "reconciliation_scope",
})
_DIGEST = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def require(ok):
    if not ok:
        raise PolicyError("repair data rejected by v1 policy")


def digest(value):
    require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    return value


def key_id(value):
    require(type(value) is str and _KEY_ID.fullmatch(value) is not None)
    return value


def canonical(value):
    """Internal bounded JSON encoding; public consumers use typed validators."""
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False, ensure_ascii=True).encode("ascii")
        require(len(payload) <= MAX_REPAIR_BYTES)
        return payload
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise PolicyError("invalid repair encoding") from None


def parse(payload):
    try:
        require(type(payload) is bytes and 0 < len(payload) <= MAX_REPAIR_BYTES)

        def unique(pairs):
            result = {}
            for name, value in pairs:
                require(name not in result)
                result[name] = value
            return result

        return json.loads(payload.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda value: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise PolicyError("invalid repair payload") from None


def exact(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def enum(value, choices):
    require(type(value) is str and value in choices)


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)


def validate_manifest(value):
    exact(value, "schema_version runbook_id version operation timeout_seconds")
    integer(value["schema_version"], 1, 1)
    enum(value["runbook_id"], RUNBOOK_IDS)
    require(value["operation"] == value["runbook_id"])
    integer(value["version"], 1, 2**31 - 1)
    integer(value["timeout_seconds"], 1, 30)
    return parse(canonical(value))


def manifest_bytes(value):
    return canonical(validate_manifest(value))


def validate_proof(value):
    exact(value, "manifest key_id signature")
    validate_manifest(value["manifest"])
    key_id(value["key_id"])
    require(type(value["signature"]) is str
            and re.fullmatch(r"[0-9a-f]{128}", value["signature"]) is not None)
    return parse(canonical(value))


def _plan_shape(value):
    exact(value, "schema_version target_host runbook evidence evaluated_at expires_at checks blocked")
    integer(value["schema_version"], 1, 1)
    host_id(value["target_host"])
    validate_proof(value["runbook"])
    now, expires = timestamp(value["evaluated_at"]), timestamp(value["expires_at"])
    require(0 < (expires - now).total_seconds() <= 60)
    require(type(value["evidence"]) is list and len(value["evidence"]) <= MAX_EVIDENCE_RECORDS)
    for snapshot in value["evidence"]:
        validate_snapshot(snapshot)
        require(snapshot["host_id"] == value["target_host"])
    require(type(value["checks"]) is list and 1 <= len(value["checks"]) <= len(CHECK_IDS))
    seen = set()
    for check in value["checks"]:
        exact(check, "check_id state required")
        enum(check["check_id"], CHECK_IDS)
        require(check["check_id"] not in seen)
        seen.add(check["check_id"])
        enum(check["state"], {"passed", "blocked", "unknown"})
        require(type(check["required"]) is bool)
    require(type(value["blocked"]) is bool)
    return value


@dataclass(frozen=True)
class RepairPlan:
    """Immutable canonical data, NOT proof that catalog or preconditions are valid.

    Call catalog.validate_plan at every trust boundary; never trust isinstance.
    """

    payload: bytes

    def __post_init__(self):
        value = _plan_shape(parse(getattr(self, "payload", None)))
        object.__setattr__(self, "payload", canonical(value))

    def as_dict(self):
        return _plan_shape(parse(getattr(self, "payload", None)))

    @property
    def digest(self):
        return hashlib.sha256(canonical(self.as_dict())).hexdigest()


def _confirmation(value):
    exact(value, "schema_version actor_id click_id target_host runbook_id version runbook_digest plan_digest confirmed_at expires_at impact_acknowledged")
    integer(value["schema_version"], 1, 1)
    for field in ("actor_id", "click_id", "target_host"):
        host_id(value[field])
    enum(value["runbook_id"], RUNBOOK_IDS)
    integer(value["version"], 1, 2**31 - 1)
    digest(value["runbook_digest"])
    digest(value["plan_digest"])
    start, end = timestamp(value["confirmed_at"]), timestamp(value["expires_at"])
    require(0 < (end - start).total_seconds() <= 60)
    # This slice cannot authorize busy-work overrides, even from a signed artifact.
    require(value["impact_acknowledged"] is False)
    return value


@dataclass(frozen=True)
class RepairConfirmation:
    """User-intent DATA only. Must be authenticated by a separate trusted boundary."""

    payload: bytes

    def __post_init__(self):
        object.__setattr__(self, "payload", canonical(_confirmation(parse(getattr(self, "payload", None)))))

    def as_dict(self):
        return _confirmation(parse(getattr(self, "payload", None)))


def validate_confirmation(confirmation, plan, *, now):
    """Check binding and time, not user authentication; plan needs catalog validation."""
    require(type(confirmation) is RepairConfirmation and type(plan) is RepairPlan)
    c, p = confirmation.as_dict(), plan.as_dict()
    current = timestamp(now)
    require(timestamp(p["evaluated_at"]) <= timestamp(c["confirmed_at"]) <= current
            < timestamp(c["expires_at"]) <= timestamp(p["expires_at"]))
    manifest = p["runbook"]["manifest"]
    require(c["target_host"] == p["target_host"] and c["plan_digest"] == plan.digest
            and c["runbook_id"] == manifest["runbook_id"] and c["version"] == manifest["version"]
            and c["runbook_digest"] == hashlib.sha256(manifest_bytes(manifest)).hexdigest())
    return RepairConfirmation(canonical(c))



def validate_outcome(outcome, reason, cleanup_complete, *, stage):
    """Validate semantic consistency only, never authority or actual side effects.

    Adapter results use stage=completion because they describe a returned call;
    runtime receipts additionally record the real control-flow stage.
    """
    enum(outcome, OUTCOMES)
    enum(reason, REASONS)
    enum(stage, STAGES)
    require(type(cleanup_complete) is bool)
    refusals = {
        "preconditions_blocked", "authorization_denied", "confirmation_expired",
        "plan_changed", "catalog_rejected", "already_claimed", "operation_unavailable",
    }
    if reason == "completed":
        require(outcome == "succeeded" and cleanup_complete and stage == "completion")
    elif reason in refusals:
        require(outcome == "blocked" and cleanup_complete and stage in {"preflight", "claim"})
    elif reason == "operation_failed":
        require(outcome == "failed" and cleanup_complete and stage in {"execution", "completion"})
    elif reason == "cancelled":
        require(outcome in {"cancelled", "outcome_unknown"})
        require(outcome != "cancelled" or cleanup_complete)
    elif reason == "audit_unavailable":
        require((outcome == "blocked" and cleanup_complete and stage in {"preflight", "claim"})
                or (outcome == "outcome_unknown" and stage in {"claim", "execution", "completion"}))
    else:
        # Clock regression, interruption, unresolved claims, invalid results and
        # deadline/cleanup uncertainty must never be presented as definite failure.
        enum(reason, {"clock_invalid", "interrupted", "recovery_required",
                      "deadline_exceeded", "cleanup_incomplete", "invalid_result"})
        require(outcome == "outcome_unknown")
        if reason in {"deadline_exceeded", "cleanup_incomplete", "invalid_result"}:
            require(stage in {"execution", "completion"})
        if reason == "recovery_required":
            require(stage in {"claim", "completion"})
        if reason == "cleanup_incomplete":
            require(not cleanup_complete)
    if not cleanup_complete:
        require(outcome == "outcome_unknown")

def _receipt(value):
    exact(value, "schema_version actor_id click_id target_host runbook_id version runbook_digest plan_digest preflight started_at finished_at stage outcome reason cleanup_complete")
    integer(value["schema_version"], 1, 1)
    for field in ("actor_id", "click_id", "target_host"):
        host_id(value[field])
    enum(value["runbook_id"], RUNBOOK_IDS)
    integer(value["version"], 1, 2**31 - 1)
    for field in ("runbook_digest", "plan_digest"):
        digest(value[field])
    preflight = RepairPlan(canonical(value["preflight"]))
    p = preflight.as_dict()
    manifest = p["runbook"]["manifest"]
    require(value["plan_digest"] == preflight.digest and value["target_host"] == p["target_host"]
            and value["runbook_id"] == manifest["runbook_id"] and value["version"] == manifest["version"]
            and value["runbook_digest"] == hashlib.sha256(manifest_bytes(manifest)).hexdigest())
    require(timestamp(value["finished_at"]) >= timestamp(value["started_at"]))
    validate_outcome(value["outcome"], value["reason"], value["cleanup_complete"], stage=value["stage"])
    if value["outcome"] == "succeeded":
        require(not p["blocked"])
    return value


@dataclass(frozen=True)
class RepairReceipt:
    """Validated safe receipt DATA; durability/authenticity are runtime concerns."""

    payload: bytes

    def __post_init__(self):
        object.__setattr__(self, "payload", canonical(_receipt(parse(getattr(self, "payload", None)))))

    def as_dict(self):
        return _receipt(parse(getattr(self, "payload", None)))


@dataclass(frozen=True)
class OperationResult:
    """Safe adapter result, validated again by the runtime after invocation."""

    outcome: str
    reason: str
    cleanup_complete: bool

    def validate(self):
        require(type(self) is OperationResult)
        enum(getattr(self, "outcome", None), {"succeeded", "failed", "cancelled", "outcome_unknown"})
        validate_outcome(self.outcome, getattr(self, "reason", None),
                         getattr(self, "cleanup_complete", None), stage="completion")
        return OperationResult(self.outcome, self.reason, self.cleanup_complete)


def _audit_entry(value):
    exact(value, "schema_version state plan confirmation started_at receipt")
    integer(value["schema_version"], 1, 1)
    enum(value["state"], {"started", "finished"})
    plan = RepairPlan(canonical(value["plan"]))
    confirmation = RepairConfirmation(canonical(value["confirmation"]))
    validate_confirmation(confirmation, plan, now=value["started_at"])
    if value["state"] == "started":
        require(value["receipt"] is None)
    else:
        receipt = RepairReceipt(canonical(value["receipt"])).as_dict()
        c = confirmation.as_dict()
        require(receipt["preflight"] == plan.as_dict()
                and receipt["started_at"] == value["started_at"]
                and receipt["actor_id"] == c["actor_id"]
                and receipt["click_id"] == c["click_id"])
    return value


@dataclass(frozen=True)
class RepairAuditEntry:
    """Immutable durable claim/terminal data; authentication belongs to audit store."""

    payload: bytes

    def __post_init__(self):
        object.__setattr__(self, "payload", canonical(_audit_entry(parse(getattr(self, "payload", None)))))

    def as_dict(self):
        return _audit_entry(parse(getattr(self, "payload", None)))
