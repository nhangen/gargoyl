"""V2 pre-drained restart orchestration; no shipped mutating provider backend.

Backends are explicitly supplied trusted local capabilities, never request data.
They must enforce atomic expected-state comparison, durable at-most-once ledger,
fence preservation and the shared cleanup-inclusive deadline internally. A client
clock check cannot preempt a lying callback or roll back an accepted restart.
"""

import math
import threading
import time
from dataclasses import dataclass

from gargoyl.repair_contract import canonical, parse, require
from gargoyl.repair_restart_contract import (
    POLICY,
    ProviderProof,
    RestartConfirmation,
    RestartPlan,
    RestartReceipt,
    bind_confirmation,
    operator_proof,
    request_bytes,
)
from gargoyl.repair_restart_journal import RestartJournal, RestartPending
from gargoyl.repair_restart_policy import RestartAuthorization, RestartPolicy
from gargoyl.telemetry import PolicyError, timestamp


class _ClockInvalid(PolicyError):
    pass


class _DeadlineExceeded(PolicyError):
    pass


@dataclass(frozen=True)
class RestartBackendResult:
    payload: bytes | None
    cleanup_complete: bool


class PreDrainedRestartRuntime:
    def __init__(
        self,
        *,
        policy,
        authorization,
        journal,
        wall_clock,
        backend=None,
        monotonic_clock=time.monotonic,
    ):
        require(
            type(policy) is RestartPolicy
            and type(authorization) is RestartAuthorization
            and type(journal) is RestartJournal
            and journal.target_host == policy.target_host
            and authorization.audience == policy.backend_id
        )
        require(callable(wall_clock) and callable(monotonic_clock))
        if backend is not None:
            budget = getattr(backend, "total_timeout_seconds", None)
            require(
                type(budget) in (int, float)
                and math.isfinite(budget)
                and 0 < budget <= 30
                and getattr(backend, "policy", None) == POLICY
                and getattr(backend, "cleanup_inclusive", None) is True
                and all(
                    callable(getattr(backend, name, None))
                    for name in ("observe", "restart_once", "reconcile")
                )
            )
        self.policy, self.authorization, self.journal = policy, authorization, journal
        self.backend, self._wall, self._mono = backend, wall_clock, monotonic_clock
        self._lock = threading.Lock()

    def execute(self, plan, confirmation, operator, *, stop_event):
        require(
            type(plan) is RestartPlan
            and type(confirmation) is RestartConfirmation
            and callable(getattr(stop_event, "is_set", None))
        )
        plan, confirmation = (
            RestartPlan(plan.payload),
            RestartConfirmation(confirmation.payload),
        )
        operator = operator_proof(operator)
        # Serialize one runtime, while the encrypted transactional gate also
        # protects separate runtimes/processes using the same host journal.
        if not self._lock.acquire(blocking=False):
            raise PolicyError("restart operation already active")
        try:
            return self._execute(plan, confirmation, operator, stop_event)
        finally:
            self._lock.release()

    def _execute(self, plan, confirmation, operator, stop):
        p, c = plan.as_dict(), confirmation.as_dict()
        started = self._wall()
        timestamp(started)
        previous = timestamp(started)
        real_start, logical_start = time.monotonic(), self._mono()
        require(
            type(logical_start) in (int, float)
            and abs(logical_start) <= 2**53
            and math.isfinite(logical_start)
        )
        logical_previous = logical_start
        request = request_bytes(plan, confirmation, operator)
        deadline_utc = timestamp(parse(request)["deadline_at"])
        budget = min(
            p["runbook"]["manifest"]["timeout_seconds"],
            max(0, (deadline_utc - previous).total_seconds()),
            self.backend.total_timeout_seconds if self.backend is not None else 30,
        )
        deadline = real_start + budget
        claimed = False

        def now():
            nonlocal previous, logical_previous
            try:
                value = self._wall()
                current = timestamp(value)
                require(current >= previous)
                logical = self._mono()
                require(
                    type(logical) in (int, float)
                    and abs(logical) <= 2**53
                    and math.isfinite(logical)
                    and logical >= logical_previous
                )
            except Exception:
                raise _ClockInvalid("restart clock unavailable") from None
            previous, logical_previous = current, logical
            if (
                max(time.monotonic() - real_start, logical - logical_start) >= budget
                or current >= deadline_utc
            ):
                raise _DeadlineExceeded("restart deadline exceeded")
            return value

        def receipt(outcome, reason, clean=True, proof=None):
            nonlocal previous
            try:
                finished = self._wall()
                current = timestamp(finished)
                require(current >= previous)
                previous = current
            except Exception:
                finished = previous.isoformat()
                outcome, reason = "outcome_unknown", "clock_invalid"
            value = RestartReceipt(
                canonical(
                    dict(
                        schema_version=2,
                        target_host=p["target_host"],
                        attempt_id=c["click_id"],
                        plan_digest=plan.digest,
                        outcome=outcome,
                        reason=reason,
                        cleanup_complete=clean,
                        started_at=started,
                        finished_at=finished,
                        provider_result=proof.as_dict() if proof is not None else None,
                    )
                )
            )
            if claimed:
                try:
                    self.journal.finish(value)
                except Exception:
                    return RestartReceipt(
                        canonical(
                            dict(
                                value.as_dict(),
                                outcome="outcome_unknown",
                                reason="audit_unavailable",
                            )
                        )
                    )
                # A commit can finish late. The gate is deliberately still held,
                # including after known success, until explicit reconciliation.
                try:
                    now()
                except Exception as error:
                    return RestartReceipt(
                        canonical(
                            dict(
                                value.as_dict(),
                                outcome="outcome_unknown",
                                reason="clock_invalid"
                                if isinstance(error, _ClockInvalid)
                                else "deadline_exceeded",
                            )
                        )
                    )
            return value

        if self.backend is None:
            return receipt("blocked", "operation_unavailable")
        if stop.is_set():
            return receipt("cancelled", "cancelled")
        try:
            self.policy.validate_plan(plan, now())
        except Exception:
            return receipt("blocked", "preconditions_blocked")
        try:
            require(self.authorization.authorize(plan, confirmation, operator) is None)
        except Exception:
            return receipt("blocked", "authorization_denied")

        def preflight():
            self.policy.validate_plan(plan, now())
            proof = ProviderProof(
                self.backend.observe(p["challenge"], deadline=deadline, stop_event=stop)
            )
            self.policy.current_matches(plan, proof, now())
            require(self.authorization.authorize(plan, confirmation, operator) is None)
            # After potentially slow reads/authorization, old confirmation and
            # provider observation must still be live. The backend additionally
            # verifies expiry and atomically compares state at mutation time.
            checked = now()
            bind_confirmation(plan, confirmation, checked)
            self.policy.proof(
                ProviderProof(canonical(p["preflight"])),
                "state",
                checked,
                challenge=p["challenge"],
            )

        try:
            preflight()
            if stop.is_set():
                return receipt("cancelled", "cancelled")
        except Exception:
            return receipt("blocked", "preconditions_blocked")
        try:
            if not self.journal.claim(plan, confirmation, operator, now=now()):
                return receipt("blocked", "already_claimed")
            claimed = True
        except RestartPending:
            return receipt("blocked", "recovery_required")
        except Exception:
            # Ambiguous journal commit may already have reserved the host.
            return receipt("outcome_unknown", "audit_unavailable")
        try:
            preflight()
            if stop.is_set():
                return receipt("cancelled", "cancelled")
        except Exception:
            return receipt("blocked", "preconditions_blocked")
        # Exactly one mutation-capable call. Never run stock CLI, force, unfence,
        # resume, fallback or retry. An exception may follow backend acceptance.
        result = None
        try:
            result = self.backend.restart_once(
                request, deadline=deadline, stop_event=stop
            )
            require(
                type(result) is RestartBackendResult
                and type(result.cleanup_complete) is bool
            )
            if not result.cleanup_complete:
                return receipt("outcome_unknown", "cleanup_incomplete", False)
            if stop.is_set():
                return receipt("outcome_unknown", "cancelled")
            try:
                checked = now()
            except _ClockInvalid:
                return receipt("outcome_unknown", "clock_invalid")
            except _DeadlineExceeded:
                return receipt("outcome_unknown", "deadline_exceeded")
            proof = ProviderProof(result.payload)
            self.policy.result(proof, plan, confirmation, operator, checked)
            # Process verification itself can consume freshness or budget.
            checked = now()
            self.policy.proof(proof, "result", checked, challenge=p["challenge"])
            if stop.is_set():
                return receipt("outcome_unknown", "cancelled", proof=proof)
            return receipt("succeeded", "completed", proof=proof)
        except _ClockInvalid:
            return receipt(
                "outcome_unknown",
                "clock_invalid",
                type(result) is RestartBackendResult
                and result.cleanup_complete is True,
            )
        except _DeadlineExceeded:
            return receipt(
                "outcome_unknown",
                "deadline_exceeded",
                type(result) is RestartBackendResult
                and result.cleanup_complete is True,
            )
        except (KeyboardInterrupt, SystemExit):
            return receipt("outcome_unknown", "interrupted", False)
        except Exception:
            return receipt(
                "outcome_unknown",
                "invalid_result",
                type(result) is RestartBackendResult
                and result.cleanup_complete is True,
            )

    def reconcile(self, *, challenge, stop_event):
        """Read-only provider query; journal-only resolution, never restart/retry.

        The backend must prove its old attempt permanently terminal and unable
        to execute later. 'Not found', age or a client timeout is insufficient.
        A new repair always requires a new plan and separately signed intent.
        """
        from gargoyl.telemetry import host_id

        host_id(challenge)
        require(
            self.backend is not None and callable(getattr(stop_event, "is_set", None))
        )
        if not self._lock.acquire(blocking=False):
            raise PolicyError("restart operation already active")
        try:
            entry = self.journal.pending()
            if entry is None:
                return None
            plan = RestartPlan(canonical(entry["plan"]))
            confirmation = RestartConfirmation(canonical(entry["confirmation"]))
            operator = dict(
                key_id=entry["operator_proof"]["key_id"],
                signature=bytes.fromhex(entry["operator_proof"]["signature"]),
            )
            request = request_bytes(plan, confirmation, operator)
            budget = min(self.backend.total_timeout_seconds, 30)
            start = time.monotonic()
            deadline = start + budget
            require(not stop_event.is_set())
            proof = ProviderProof(
                self.backend.reconcile(
                    request, challenge, deadline=deadline, stop_event=stop_event
                )
            )
            require(not stop_event.is_set() and time.monotonic() < deadline)
            body = proof.as_dict()["body"]
            require(body["challenge"] == challenge)
            self.journal.reconcile(proof, policy=self.policy, wall_clock=self._wall)
            return proof
        finally:
            self._lock.release()
