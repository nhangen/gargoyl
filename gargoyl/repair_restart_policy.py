"""Explicit runbook/provider/operator trust for the separate v2 restart protocol."""

import hashlib
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gargoyl.repair_catalog import RunbookCatalog, VerifiedRunbook
from gargoyl.repair_contract import canonical, key_id, require
from gargoyl.repair_operator import OperatorRegistry
from gargoyl.repair_restart_contract import (
    OPERATION,
    POLICY,
    PROVIDER_CONTEXT,
    ProviderProof,
    RestartPlan,
    bind_confirmation,
    intent_bytes,
    operator_proof,
    request_bytes,
    state_binding,
)
from gargoyl.telemetry import PolicyError, host_id, timestamp


def provider_message(kind, body):
    # Validation only: this helper neither signs nor enrolls a provider.
    ProviderProof(
        canonical(dict(kind=kind, key_id="validation", body=body, signature="0" * 128))
    )
    return PROVIDER_CONTEXT + kind.encode("ascii") + b"\x00" + canonical(body)


class RestartPolicy:
    """One explicit local host/backend; public trust only, no discovery/enrollment.

    process_verifier must independently compare local OS birth identity and the
    configured provider image. Injected implementations are trusted capabilities,
    not evidence supplied by a request. MacOSProcessVerifier is the native option.
    """

    def __init__(
        self, *, catalog, target_host, backend_id, provider_keys, process_verifier
    ):
        require(type(catalog) is RunbookCatalog and callable(process_verifier))
        host_id(target_host)
        host_id(backend_id)
        require(type(provider_keys) is dict and 1 <= len(provider_keys) <= 16)
        self._keys = {}
        seen = set()
        for name, public in provider_keys.items():
            key_id(name)
            require(type(public) is bytes and len(public) == 32)
            require(public not in seen)
            seen.add(public)
            self._keys[name] = Ed25519PublicKey.from_public_bytes(public)
        self.catalog, self.target_host, self.backend_id = (
            catalog,
            target_host,
            backend_id,
        )
        self._process_verifier = process_verifier

    def proof(self, proof, kind, now, *, challenge):
        require(type(proof) is ProviderProof)
        value = ProviderProof(proof.payload).as_dict()
        body = value["body"]
        require(value["kind"] == kind and value["key_id"] in self._keys)
        try:
            self._keys[value["key_id"]].verify(
                bytes.fromhex(value["signature"]), provider_message(kind, body)
            )
        except Exception:
            raise PolicyError("restart provider evidence unavailable") from None
        require(
            body["host_id"] == self.target_host
            and body["backend_id"] == self.backend_id
            and body["challenge"] == challenge
        )
        require(
            timestamp(body["observed_at"])
            <= timestamp(now)
            < timestamp(body["expires_at"])
        )
        return body

    def _process(self, identity):
        start = time.monotonic()
        require(self._process_verifier(identity) is True)
        require(time.monotonic() - start <= 1)

    def state(self, proof, now, *, challenge):
        body = self.proof(proof, "state", now, challenge=challenge)
        require(
            body["admission_fenced"]
            and body["outstanding_work"] == 0
            and body["coordinator_acknowledged"]
            and body["ack_drain_id"] == body["drain_id"]
            and body["ack_process"] == body["process"]
        )
        self._process(body["process"])
        return body

    def plan(self, runbook, preflight, *, challenge, now):
        require(type(runbook) is VerifiedRunbook)
        runbook = self.catalog.validate_runbook(runbook)
        m = runbook.as_dict()["manifest"]
        require(m["operation"] == m["runbook_id"] == OPERATION and m["version"] == 2)
        state = self.state(preflight, now, challenge=challenge)
        return RestartPlan(
            canonical(
                dict(
                    schema_version=2,
                    policy=POLICY,
                    target_host=self.target_host,
                    challenge=challenge,
                    runbook=runbook.as_dict(),
                    preflight=preflight.as_dict(),
                    planned_at=now,
                    expires_at=state["expires_at"],
                )
            )
        )

    def validate_plan(self, plan, now):
        require(type(plan) is RestartPlan)
        p = RestartPlan(plan.payload).as_dict()
        require(
            timestamp(p["planned_at"]) <= timestamp(now) < timestamp(p["expires_at"])
        )
        expected = self.plan(
            VerifiedRunbook(canonical(p["runbook"])),
            ProviderProof(canonical(p["preflight"])),
            challenge=p["challenge"],
            now=p["planned_at"],
        )
        require(expected.payload == plan.payload)
        self.state(
            ProviderProof(canonical(p["preflight"])), now, challenge=p["challenge"]
        )
        return p

    def current_matches(self, plan, proof, now):
        p = plan.as_dict()
        current = self.state(proof, now, challenge=p["challenge"])
        require(state_binding(current) == state_binding(p["preflight"]["body"]))

    def result(self, proof, plan, confirmation, operator, now):
        p, c = plan.as_dict(), confirmation.as_dict()
        previous = p["preflight"]["body"]
        body = self.proof(proof, "result", now, challenge=p["challenge"])
        require(
            body["attempt_id"] == c["click_id"]
            and body["request_digest"]
            == hashlib.sha256(request_bytes(plan, confirmation, operator)).hexdigest()
            and body["previous_process"] == previous["process"]
            and body["process"] != previous["process"]
            and body["process"]["born_us"] > previous["process"]["born_us"]
            and body["admission_fenced"]
            and body["outstanding_work"] == 0
            and body["terminal"]
            and body["no_pending_restart"]
        )
        for key in ("fence_id", "config_digest", "model_digest"):
            require(body[key] == previous[key])
        require(
            body["process"]["born_us"] / 1000000
            >= timestamp(c["confirmed_at"]).timestamp()
        )
        require(
            body["process"]["born_us"] / 1000000
            <= timestamp(body["authorization_at"]).timestamp()
            <= timestamp(body["observed_at"]).timestamp()
        )
        self._process(body["process"])
        return body

    def reconciliation(self, proof, entry, now):
        p = RestartPlan(canonical(entry["plan"]))
        c = entry["confirmation"]
        body = self.proof(
            proof, "reconciliation", now, challenge=proof.as_dict()["body"]["challenge"]
        )
        require(
            body["attempt_id"] == c["click_id"]
            and body["request_digest"] == entry["request_digest"]
            and body["terminal"]
            and body["no_pending_restart"]
            and timestamp(body["observed_at"]) >= timestamp(entry["started_at"])
        )
        state = body["state"]
        # Same fence and configuration, but process may be the verified original
        # (no effect) or a verified replacement. No interpretation of 'not found'.
        previous = p.as_dict()["preflight"]["body"]
        for key in ("fence_id", "config_digest", "model_digest"):
            require(state[key] == previous[key])
        require(
            state["admission_fenced"]
            and state["outstanding_work"] == 0
            and state["coordinator_acknowledged"]
            and state["ack_drain_id"] == state["drain_id"]
            and state["ack_process"] == state["process"]
        )
        self._process(state["process"])
        return body


class RestartAuthorization:
    def __init__(self, *, registry_provider, audience, wall_clock):
        require(callable(registry_provider) and callable(wall_clock))
        host_id(audience)
        self._registry, self._clock, self.audience = (
            registry_provider,
            wall_clock,
            audience,
        )
        self._last = None
        self._lock = threading.Lock()

    def authorize(self, plan, confirmation, proof):
        with self._lock:
            return self._authorize(plan, confirmation, proof)

    def _authorize(self, plan, confirmation, proof):
        try:
            proof = operator_proof(proof)
            registry = self._registry()
            require(type(registry) is OperatorRegistry)
            principal = registry.lookup(proof["key_id"])
            Ed25519PublicKey.from_public_bytes(principal.public_key).verify(
                proof["signature"], intent_bytes(self.audience, confirmation)
            )
            now = self._clock()
            current = timestamp(now)
            require(self._last is None or current >= self._last)
            self._last = current
            bind_confirmation(plan, confirmation, now)
            c = confirmation.as_dict()
            require(
                c["actor_id"] == principal.principal.actor_id
                and (c["target_host"], OPERATION) in principal.principal.repair_grants
            )
            return None
        except Exception:
            raise PolicyError("restart operator authorization unavailable") from None
