"""Synthetic signed provider/ledger only; never invokes a host restart."""

import copy
import hashlib
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog
from gargoyl.repair_contract import canonical, parse
from gargoyl.repair_operator import OperatorKey, OperatorPrincipal, OperatorRegistry
from gargoyl.repair_restart_contract import (
    OPERATION,
    POLICY,
    ProviderProof,
    RestartConfirmation,
    intent_bytes,
    state_binding,
)
from gargoyl.repair_restart_journal import RestartJournal
from gargoyl.repair_restart_policy import (
    RestartAuthorization,
    RestartPolicy,
    provider_message,
)
from gargoyl.repair_restart_runtime import (
    PreDrainedRestartRuntime,
    RestartBackendResult,
)

HOST = "00000000-0000-4000-8000-000000000001"
ACTOR = "00000000-0000-4000-8000-000000000002"
BACKEND = "00000000-0000-4000-8000-000000000003"
CHALLENGE = "00000000-0000-4000-8000-000000000004"
ATTEMPT = "00000000-0000-4000-8000-000000000005"
DRAIN = "00000000-0000-4000-8000-000000000006"
FENCE = "00000000-0000-4000-8000-000000000007"
OTHER = "00000000-0000-4000-8000-000000000008"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Clock:
    elapsed = 0

    def wall(self):
        return (NOW + timedelta(seconds=self.elapsed)).isoformat()

    def mono(self):
        return self.elapsed

    def advance(self, seconds):
        self.elapsed += seconds


class Provider:
    policy = POLICY
    cleanup_inclusive = True
    total_timeout_seconds = 3

    def __init__(self, clock, key):
        self.clock, self.key = clock, key
        self.identity = dict(
            pid=12345,
            owner_uid=os.getuid(),
            born_us=int((NOW.timestamp() - 100) * 1000000),
        )
        self.live = {self.identity["pid"]: dict(self.identity)}
        self.fenced, self.ack, self.outstanding = True, True, 0
        self.fence, self.drain = FENCE, DRAIN
        self.config, self.model = "a" * 64, "b" * 64
        self.calls, self.effects, self.reads, self.queries = 0, 0, 0, 0
        self.ledger = {}
        self.mode = None
        self.on_observe = None
        self.on_restart = None
        self.result_change = None

    def verify_process(self, identity):
        return self.live.get(identity["pid"]) == identity

    def common(self, challenge):
        return dict(
            schema_version=2,
            policy=POLICY,
            host_id=HOST,
            backend_id=BACKEND,
            challenge=challenge,
            observed_at=self.clock.wall(),
            expires_at=(NOW + timedelta(seconds=self.clock.elapsed + 5)).isoformat(),
        )

    def state(self, challenge):
        return dict(
            self.common(challenge),
            process=dict(self.identity),
            ack_process=dict(self.identity),
            drain_id=self.drain,
            ack_drain_id=self.drain,
            fence_id=self.fence,
            admission_fenced=self.fenced,
            outstanding_work=self.outstanding,
            coordinator_acknowledged=self.ack,
            config_digest=self.config,
            model_digest=self.model,
        )

    def sign(self, kind, body):
        signature = self.key.sign(provider_message(kind, body))
        return canonical(
            dict(kind=kind, key_id="provider", body=body, signature=signature.hex())
        )

    def observe(self, challenge, *, deadline, stop_event):
        self.reads += 1
        if self.on_observe:
            self.on_observe(self)
        return self.sign("state", self.state(challenge))

    def restart_once(self, request, *, deadline, stop_event):
        # Test-only stand-in for the required atomic provider-side operation.
        self.calls += 1
        value = parse(request)
        p = value["plan"]
        c = value["confirmation"]
        digest = hashlib.sha256(request).hexdigest()
        if digest in self.ledger:
            raise RuntimeError("duplicate dispatch")
        self.ledger[digest] = "pending"
        if self.on_restart:
            self.on_restart(self)
        if state_binding(self.state(p["challenge"])) != state_binding(
            p["preflight"]["body"]
        ):
            self.ledger[digest] = "terminal"
            raise RuntimeError("conditional state mismatch")
        if stop_event.is_set() or self.clock.wall() >= value["deadline_at"]:
            self.ledger[digest] = "terminal"
            raise TimeoutError("expired request")
        if self.mode == "pending_timeout":
            raise TimeoutError("ledger still pending")
        if self.mode == "cleanup_incomplete":
            return RestartBackendResult(None, False)
        previous = dict(self.identity)
        self.clock.advance(0.1)
        self.identity = dict(
            pid=previous["pid"] + 1,
            owner_uid=os.getuid(),
            born_us=int((NOW.timestamp() + self.clock.elapsed) * 1000000),
        )
        self.live.pop(previous["pid"])
        self.live[self.identity["pid"]] = dict(self.identity)
        self.effects += 1
        self.ledger[digest] = "terminal"
        if self.mode == "lost_reply":
            raise OSError("synthetic-private-error")
        if self.mode == "late":
            self.clock.advance(4)
        body = dict(
            self.common(p["challenge"]),
            attempt_id=c["click_id"],
            request_digest=digest,
            previous_process=previous,
            process=dict(self.identity),
            fence_id=self.fence,
            config_digest=self.config,
            model_digest=self.model,
            admission_fenced=self.fenced,
            outstanding_work=self.outstanding,
            authorization_at=self.clock.wall(),
            terminal=True,
            no_pending_restart=True,
        )
        if self.result_change:
            self.result_change(body)
        return RestartBackendResult(self.sign("result", body), True)

    def reconcile(self, request, challenge, *, deadline, stop_event):
        self.queries += 1
        value = parse(request)
        digest = hashlib.sha256(request).hexdigest()
        # No ledger mutation. 'Not found' alone never certifies terminality.
        terminal = self.ledger.get(digest) == "terminal"
        state = self.state(challenge)
        body = dict(
            self.common(challenge),
            attempt_id=value["confirmation"]["click_id"],
            request_digest=digest,
            terminal=terminal,
            no_pending_restart=terminal,
            state=state,
        )
        return self.sign("reconciliation", body)


class Fixture:
    def __init__(self, root):
        root.mkdir(mode=0o700, exist_ok=True)
        self.root = root
        self.clock = Clock()
        self.provider_key = Ed25519PrivateKey.generate()
        self.operator_key = Ed25519PrivateKey.generate()
        signer = Ed25519PrivateKey.generate()
        manifest = canonical(
            dict(
                schema_version=1,
                runbook_id=OPERATION,
                operation=OPERATION,
                version=2,
                timeout_seconds=3,
            )
        )
        self.catalog = RunbookCatalog(
            trusted_keys={"catalog": signer.public_key().public_bytes_raw()},
            allowed_versions=frozenset(
                {(OPERATION, 2, hashlib.sha256(manifest).hexdigest())}
            ),
        )
        self.book = self.catalog.verify_runbook(
            manifest, signer.sign(SIGNING_CONTEXT + manifest), key_id="catalog"
        )
        self.provider = Provider(self.clock, self.provider_key)
        self.policy = RestartPolicy(
            catalog=self.catalog,
            target_host=HOST,
            backend_id=BACKEND,
            provider_keys={
                "provider": self.provider_key.public_key().public_bytes_raw()
            },
            process_verifier=self.provider.verify_process,
        )
        self.registry = self.make_registry()
        self.authorization = RestartAuthorization(
            registry_provider=lambda: self.registry,
            audience=BACKEND,
            wall_clock=self.clock.wall,
        )
        self.journal_key = os.urandom(32)
        self.journal = RestartJournal.create(
            root / "journal", target_host=HOST, key=self.journal_key
        )
        self.runtime = self.make_runtime()
        self.plan, self.confirmation, self.proof = self.intent()

    def make_registry(self, *, granted=True, actor=ACTOR):
        return OperatorRegistry(
            {
                "operator": OperatorKey(
                    self.operator_key.public_key().public_bytes_raw(),
                    OperatorPrincipal(
                        actor,
                        frozenset({(HOST, OPERATION)}) if granted else frozenset(),
                    ),
                )
            }
        )

    def make_runtime(self, backend=True):
        return PreDrainedRestartRuntime(
            policy=self.policy,
            authorization=self.authorization,
            journal=self.journal,
            wall_clock=self.clock.wall,
            monotonic_clock=self.clock.mono,
            backend=self.provider if backend else None,
        )

    def intent(self, *, attempt=ATTEMPT, challenge=CHALLENGE):
        proof = ProviderProof(
            self.provider.sign("state", self.provider.state(challenge))
        )
        plan = self.policy.plan(
            self.book, proof, challenge=challenge, now=self.clock.wall()
        )
        c = RestartConfirmation(
            canonical(
                dict(
                    schema_version=2,
                    policy=POLICY,
                    actor_id=ACTOR,
                    click_id=attempt,
                    target_host=HOST,
                    runbook_id=OPERATION,
                    version=2,
                    runbook_digest=self.book.digest,
                    plan_digest=plan.digest,
                    confirmed_at=self.clock.wall(),
                    expires_at=(
                        NOW + timedelta(seconds=self.clock.elapsed + 4)
                    ).isoformat(),
                )
            )
        )
        operator = dict(
            key_id="operator",
            signature=self.operator_key.sign(intent_bytes(BACKEND, c)),
        )
        return plan, c, operator

    def entry_copy(self):
        return copy.deepcopy(self.journal.pending())
