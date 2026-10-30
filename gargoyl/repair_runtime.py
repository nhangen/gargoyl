"""Explicit synchronous repair control flow; shipped adapter never executes."""

import math
import threading
import time

from gargoyl.repair_catalog import VerifiedRunbook
from gargoyl.repair_contract import (
    OperationResult,
    RepairAuditEntry,
    RepairConfirmation,
    RepairPlan,
    RepairReceipt,
    canonical,
    require,
    validate_confirmation,
)
from gargoyl.telemetry import PolicyError, timestamp


class RefusingAdapter:
    supported_operations = frozenset()
    total_timeout_seconds = 1.0

    def execute(self, plan, *, stop_event):
        raise PolicyError("repair operation unavailable")


class RepairRuntime:
    """Trusted authorization/evidence/adapter dependencies, never supplied by wire data.

    authorization.authorize(plan, confirmation) must return None on authenticated,
    host-scoped user intent or raise. A boolean is never an authorization result.
    evidence(target_host) returns current snapshots. Dependencies must be bounded;
    this synchronous library cannot sandbox or forcibly stop arbitrary Python code.
    """

    def __init__(self, *, catalog, audit, authorization, evidence, wall_clock,
                 adapter=None, monotonic_clock=time.monotonic):
        require(callable(getattr(authorization, "authorize", None)))
        require(callable(evidence) and callable(wall_clock) and callable(monotonic_clock))
        self.catalog, self.audit, self.authorization = catalog, audit, authorization
        self.evidence, self.wall_clock = evidence, wall_clock
        self.adapter = RefusingAdapter() if adapter is None else adapter
        self.monotonic_clock = monotonic_clock
        self._lock = threading.Lock()

    def execute(self, plan, confirmation, *, stop_event):
        with self._lock:
            return self._execute(plan, confirmation, stop_event)

    def _execute(self, plan, confirmation, stop_event):
        # Invalid shape cannot produce an attributable receipt; reject safely.
        require(type(plan) is RepairPlan and type(confirmation) is RepairConfirmation)
        plan, confirmation = RepairPlan(plan.payload), RepairConfirmation(confirmation.payload)
        now = self.wall_clock()
        timestamp(now)
        c = confirmation.as_dict()
        p = plan.as_dict()

        def receipt(outcome, reason, *, stage="preflight", cleanup=True, finished=None):
            return RepairReceipt(canonical(dict(
                schema_version=1, **{name: c[name] for name in (
                    "actor_id", "click_id", "target_host", "runbook_id", "version",
                    "runbook_digest", "plan_digest")}, preflight=p, started_at=now,
                finished_at=now if finished is None else finished, stage=stage,
                outcome=outcome, reason=reason, cleanup_complete=cleanup,
            )))

        # Bind before reporting even a rejection (wrong-host data is not attributable).
        validate_confirmation(confirmation, plan, now=now)
        try:
            self.catalog.validate_plan(plan, now=now)
        except Exception:
            return receipt("blocked", "catalog_rejected")
        if p["blocked"]:
            return receipt("blocked", "preconditions_blocked")
        try:
            require(self.authorization.authorize(plan, confirmation) is None)
        except Exception:
            return receipt("blocked", "authorization_denied")
        try:
            refreshed_at = self.wall_clock()
            require(timestamp(refreshed_at) >= timestamp(now))
            evidence = self.evidence(p["target_host"])
            checked_now = self.wall_clock()
            require(timestamp(checked_now) >= timestamp(refreshed_at))
            current = self.catalog.plan(VerifiedRunbook(canonical(p["runbook"])),
                                        p["target_host"], evidence,
                                        now=checked_now).as_dict()
            require(all(current[key] == p[key] for key in
                        ("target_host", "runbook", "evidence", "checks", "blocked")))
            self.catalog.validate_plan(plan, now=checked_now)
            validate_confirmation(confirmation, plan, now=checked_now)
            now = checked_now
        except Exception:
            return receipt("blocked", "plan_changed")
        try:
            operations = self.adapter.supported_operations
            budget = self.adapter.total_timeout_seconds
            require(type(operations) is frozenset and c["runbook_id"] in operations)
            require(type(budget) in (int, float) and 0 < budget <= 30
                    and math.isfinite(budget)
                    and budget <= p["runbook"]["manifest"]["timeout_seconds"])
        except Exception:
            return receipt("blocked", "operation_unavailable")
        if stop_event.is_set():
            return receipt("cancelled", "cancelled")
        # Reserve the largest terminal envelope before consuming intent or invoking.
        reserve = receipt("outcome_unknown", "cleanup_incomplete", stage="completion",
                          cleanup=False, finished="9999-12-31T23:59:59.999999+00:00")
        RepairAuditEntry(canonical(dict(schema_version=1, state="finished", plan=p,
                                       confirmation=c, started_at=now, receipt=reserve.as_dict())))
        try:
            if not self.audit.claim(plan, confirmation, now=now):
                return receipt("blocked", "already_claimed", stage="claim")
        except Exception:
            return receipt("outcome_unknown", "audit_unavailable", stage="claim")
        result = OperationResult("outcome_unknown", "interrupted", False)
        try:
            started = time.monotonic()
            injected_start = self.monotonic_clock()
            require(type(injected_start) in (float, int) and abs(injected_start) < 1e100)
            require(math.isfinite(injected_start))
            if stop_event.is_set():
                result = OperationResult("cancelled", "cancelled", True)
            else:
                candidate = self.adapter.execute(plan, stop_event=stop_event)
                require(type(candidate) is OperationResult)
                result = candidate.validate()
                if result.outcome == "failed":
                    require(result.reason == "operation_failed" and result.cleanup_complete)
                elif result.outcome == "cancelled":
                    require(result.reason == "cancelled" and result.cleanup_complete)
                if result.reason in {"clock_invalid", "deadline_exceeded", "interrupted",
                                     "cleanup_incomplete", "invalid_result"}:
                    require(result.outcome == "outcome_unknown")
            injected_end = self.monotonic_clock()
            require(type(injected_end) in (float, int) and abs(injected_end) < 1e100)
            require(math.isfinite(injected_end) and injected_end >= injected_start)
            if max(time.monotonic() - started, injected_end - injected_start) > budget:
                result = OperationResult("outcome_unknown", "deadline_exceeded", result.cleanup_complete)
            elif stop_event.is_set():
                result = OperationResult("outcome_unknown", "cancelled", result.cleanup_complete)
        except (KeyboardInterrupt, SystemExit):
            result = OperationResult("outcome_unknown", "interrupted", False)
        except Exception:
            result = OperationResult("outcome_unknown", "invalid_result", False)
        finished = now
        try:
            finished = self.wall_clock()
            require(timestamp(finished) >= timestamp(now))
        except Exception:
            finished = now
            result = OperationResult("outcome_unknown", "clock_invalid", result.cleanup_complete)
        terminal = receipt(result.outcome, result.reason, stage="completion",
                           cleanup=result.cleanup_complete, finished=finished)
        try:
            self.audit.finalize(c["click_id"], terminal)
        except Exception:
            return receipt("outcome_unknown", "audit_unavailable", stage="completion",
                           cleanup=result.cleanup_complete, finished=finished)
        return terminal
