"""Strict v2 pre-drained restart data; no v1 schema or authority changes."""

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from gargoyl.repair_contract import (
    canonical,
    digest,
    enum,
    exact,
    integer,
    key_id,
    parse,
    require,
    validate_proof,
)
from gargoyl.telemetry import host_id, timestamp

POLICY = "mbp26-pre-drained-fenced-restart-v2"
OPERATION = "drained_provider_restart"
PROVIDER_CONTEXT = b"gargoyl:provider:pre-drained-restart:v2\x00"
INTENT_CONTEXT = b"gargoyl:operator:pre-drained-restart:v2\x00"


def process_identity(value):
    exact(value, "pid owner_uid born_us")
    integer(value["pid"], 1, 2**31 - 1)
    integer(value["owner_uid"], 0, 2**32 - 2)
    integer(value["born_us"], 1, 2**53 - 1)
    return value


def _common(body):
    integer(body["schema_version"], 2, 2)
    for key in ("host_id", "backend_id", "challenge"):
        host_id(body[key])
    require(body["policy"] == POLICY)
    begin, end = timestamp(body["observed_at"]), timestamp(body["expires_at"])
    require(0 < (end - begin).total_seconds() <= 5)


def state_shape(body):
    exact(
        body,
        "schema_version policy host_id backend_id challenge observed_at expires_at "
        "process drain_id ack_drain_id ack_process fence_id admission_fenced "
        "outstanding_work coordinator_acknowledged config_digest model_digest",
    )
    _common(body)
    process_identity(body["process"])
    process_identity(body["ack_process"])
    for key in ("drain_id", "ack_drain_id", "fence_id"):
        host_id(body[key])
    for key in ("admission_fenced", "coordinator_acknowledged"):
        require(type(body[key]) is bool)
    integer(body["outstanding_work"], 0, 2**53 - 1)
    digest(body["config_digest"])
    digest(body["model_digest"])
    return body


def proof_shape(value):
    exact(value, "kind key_id body signature")
    enum(value["kind"], {"state", "result", "reconciliation"})
    key_id(value["key_id"])
    require(type(value["signature"]) is str and len(value["signature"]) == 128)
    try:
        require(
            len(bytes.fromhex(value["signature"])) == 64
            and value["signature"] == value["signature"].lower()
        )
    except ValueError:
        require(False)
    body = value["body"]
    if value["kind"] == "state":
        state_shape(body)
    elif value["kind"] == "result":
        exact(
            body,
            "schema_version policy host_id backend_id challenge observed_at expires_at "
            "attempt_id request_digest previous_process process fence_id config_digest "
            "model_digest admission_fenced outstanding_work authorization_at terminal no_pending_restart",
        )
        _common(body)
        host_id(body["attempt_id"])
        digest(body["request_digest"])
        process_identity(body["previous_process"])
        process_identity(body["process"])
        host_id(body["fence_id"])
        digest(body["config_digest"])
        digest(body["model_digest"])
        timestamp(body["authorization_at"])
        integer(body["outstanding_work"], 0, 2**53 - 1)
        for name in ("admission_fenced", "terminal", "no_pending_restart"):
            require(type(body[name]) is bool)
    else:
        exact(
            body,
            "schema_version policy host_id backend_id challenge observed_at expires_at "
            "attempt_id request_digest terminal no_pending_restart state",
        )
        _common(body)
        host_id(body["attempt_id"])
        digest(body["request_digest"])
        for name in ("terminal", "no_pending_restart"):
            require(type(body[name]) is bool)
        state_shape(body["state"])
        for name in ("host_id", "backend_id", "challenge", "observed_at", "expires_at"):
            require(body[name] == body["state"][name])
    return value


def plan_shape(value):
    exact(
        value,
        "schema_version policy target_host challenge runbook preflight planned_at expires_at",
    )
    integer(value["schema_version"], 2, 2)
    require(value["policy"] == POLICY)
    host_id(value["target_host"])
    host_id(value["challenge"])
    validate_proof(value["runbook"])
    manifest = value["runbook"]["manifest"]
    require(
        manifest["runbook_id"] == manifest["operation"] == OPERATION
        and manifest["version"] == 2
    )
    proof_shape(value["preflight"])
    require(value["preflight"]["kind"] == "state")
    state = value["preflight"]["body"]
    require(
        state["host_id"] == value["target_host"]
        and state["challenge"] == value["challenge"]
    )
    now, end = timestamp(value["planned_at"]), timestamp(value["expires_at"])
    require(
        timestamp(state["observed_at"]) <= now < end <= timestamp(state["expires_at"])
    )
    return value


def confirmation_shape(value):
    exact(
        value,
        "schema_version policy actor_id click_id target_host runbook_id version "
        "runbook_digest plan_digest confirmed_at expires_at",
    )
    integer(value["schema_version"], 2, 2)
    require(value["policy"] == POLICY and value["runbook_id"] == OPERATION)
    integer(value["version"], 2, 2)
    for key in ("actor_id", "click_id", "target_host"):
        host_id(value[key])
    digest(value["runbook_digest"])
    digest(value["plan_digest"])
    require(
        0
        < (
            timestamp(value["expires_at"]) - timestamp(value["confirmed_at"])
        ).total_seconds()
        <= 5
    )
    return value


@dataclass(frozen=True)
class _Document:
    payload: bytes

    def __post_init__(self):
        object.__setattr__(self, "payload", canonical(self._shape(parse(self.payload))))

    def as_dict(self):
        return self._shape(parse(self.payload))

    @property
    def digest(self):
        return hashlib.sha256(self.payload).hexdigest()


class ProviderProof(_Document):
    _shape = staticmethod(proof_shape)


class RestartPlan(_Document):
    _shape = staticmethod(plan_shape)


class RestartConfirmation(_Document):
    _shape = staticmethod(confirmation_shape)


def bind_confirmation(plan, confirmation, now):
    require(type(plan) is RestartPlan and type(confirmation) is RestartConfirmation)
    p, c = plan.as_dict(), confirmation.as_dict()
    require(
        timestamp(p["planned_at"])
        <= timestamp(c["confirmed_at"])
        <= timestamp(now)
        < timestamp(c["expires_at"])
        <= timestamp(p["expires_at"])
    )
    require(c["target_host"] == p["target_host"] and c["plan_digest"] == plan.digest)
    require(
        c["runbook_digest"]
        == hashlib.sha256(canonical(p["runbook"]["manifest"])).hexdigest()
    )


def intent_bytes(audience, confirmation):
    host_id(audience)
    require(type(confirmation) is RestartConfirmation)
    return INTENT_CONTEXT + canonical(
        dict(audience=audience, confirmation=confirmation.as_dict())
    )


def operator_proof(value):
    exact(value, "key_id signature")
    key_id(value["key_id"])
    require(type(value["signature"]) is bytes and len(value["signature"]) == 64)
    return dict(value)


def request_bytes(plan, confirmation, proof):
    p, c = plan.as_dict(), confirmation.as_dict()
    proof = operator_proof(proof)
    deadline = timestamp(c["confirmed_at"]) + timedelta(
        seconds=p["runbook"]["manifest"]["timeout_seconds"]
    )
    return canonical(
        dict(
            schema_version=2,
            policy=POLICY,
            plan=p,
            confirmation=c,
            operator_proof=dict(
                key_id=proof["key_id"], signature=proof["signature"].hex()
            ),
            deadline_at=deadline.isoformat(),
        )
    )


def state_binding(body):
    state_shape(body)
    return {
        key: value
        for key, value in body.items()
        if key not in {"observed_at", "expires_at"}
    }


def receipt_shape(value):
    exact(
        value,
        "schema_version target_host attempt_id plan_digest outcome reason cleanup_complete "
        "started_at finished_at provider_result",
    )
    integer(value["schema_version"], 2, 2)
    host_id(value["target_host"])
    host_id(value["attempt_id"])
    digest(value["plan_digest"])
    require(timestamp(value["finished_at"]) >= timestamp(value["started_at"]))
    require(type(value["cleanup_complete"]) is bool)
    enum(value["outcome"], {"succeeded", "blocked", "cancelled", "outcome_unknown"})
    if value["outcome"] == "succeeded":
        require(value["reason"] == "completed" and value["cleanup_complete"])
        proof_shape(value["provider_result"])
        require(value["provider_result"]["kind"] == "result")
    elif value["outcome"] == "blocked":
        enum(
            value["reason"],
            {
                "preconditions_blocked",
                "authorization_denied",
                "operation_unavailable",
                "already_claimed",
                "recovery_required",
                "audit_unavailable",
            },
        )
        require(value["cleanup_complete"] and value["provider_result"] is None)
    elif value["outcome"] == "cancelled":
        require(
            value["reason"] == "cancelled"
            and value["cleanup_complete"]
            and value["provider_result"] is None
        )
    else:
        enum(
            value["reason"],
            {
                "deadline_exceeded",
                "interrupted",
                "invalid_result",
                "cleanup_incomplete",
                "audit_unavailable",
                "clock_invalid",
                "cancelled",
                "recovery_required",
            },
        )
        if value["provider_result"] is not None:
            proof_shape(value["provider_result"])
            require(value["provider_result"]["kind"] == "result")
        if value["reason"] == "cleanup_incomplete":
            require(not value["cleanup_complete"])
    return value


class RestartReceipt(_Document):
    _shape = staticmethod(receipt_shape)
