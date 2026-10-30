import unittest
from dataclasses import FrozenInstanceError

import test_repair_catalog as repair_fixtures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_repair_catalog import ACTOR, END, HOST, NOW

from gargoyl.repair_contract import RepairConfirmation, canonical
from gargoyl.repair_operator import (
    OperatorAuthorization,
    OperatorKey,
    OperatorPrincipal,
    OperatorReadAuthorization,
    OperatorRegistry,
    read_intent_bytes,
    repair_intent_bytes,
)
from gargoyl.telemetry import PolicyError

AUDIENCE = "00000000-0000-4000-8000-000000000010"


class OperatorTests(unittest.TestCase):
    def setUp(self):
        fixture = repair_fixtures.RepairCatalogTests()
        fixture.setUp()
        self.plan, self.confirmation = fixture.plan, fixture.confirmation()
        self.key = Ed25519PrivateKey.generate()
        self.now = NOW
        self.registry = self.make_registry()
        self.arguments = dict(registry_provider=lambda: self.registry,
                              audience=AUDIENCE, wall_clock=lambda: self.now)

    def make_registry(self, *, actor=ACTOR, repair=True):
        principal = OperatorPrincipal(actor, frozenset({(HOST, "status_refresh")}) if repair else frozenset(),
                                      frozenset({HOST}), frozenset())
        return OperatorRegistry({"operator": OperatorKey(self.key.public_key().public_bytes_raw(), principal)})

    def proof(self, message):
        return {"key_id": "operator", "signature": self.key.sign(message)}

    def authorization(self):
        return OperatorAuthorization(self.proof(repair_intent_bytes(AUDIENCE, self.confirmation)), **self.arguments)

    def request(self):
        return dict(schema_version=1, actor_id=ACTOR, request_id=AUDIENCE, issued_at=NOW, expires_at=END)

    def test_signed_bound_repair_and_current_grants(self):
        auth = self.authorization()
        self.assertIsNone(auth.authorize(self.plan, self.confirmation))
        self.registry = self.make_registry(repair=False)
        with self.assertRaises(PolicyError):
            auth.authorize(self.plan, self.confirmation)

    def test_read_scope_separate_grants_and_context(self):
        request = self.request()
        proof = self.proof(read_intent_bytes(AUDIENCE, request))
        auth = OperatorReadAuthorization(request, proof, **self.arguments)
        scope = auth.read_scope()
        self.assertEqual(scope.actor_id, ACTOR)
        self.assertEqual(scope.evidence_hosts, frozenset({HOST}))
        self.assertEqual(scope.audit_hosts, frozenset())
        self.assertEqual(scope.expires_at, END)
        with self.assertRaises(FrozenInstanceError):
            scope.actor_id = HOST
        with self.assertRaises(PolicyError):
            OperatorAuthorization(proof, **self.arguments).authorize(self.plan, self.confirmation)
        proof = self.proof(repair_intent_bytes(AUDIENCE, self.confirmation))
        with self.assertRaises(PolicyError):
            OperatorReadAuthorization(request, proof, **self.arguments).read_scope()

    def test_wrong_actor_audience_and_confirmation_rejected(self):
        proof = self.proof(repair_intent_bytes(HOST, self.confirmation))
        with self.assertRaises(PolicyError):
            OperatorAuthorization(proof, **self.arguments).authorize(self.plan, self.confirmation)
        auth = self.authorization()
        self.registry = self.make_registry(actor=HOST)
        with self.assertRaises(PolicyError):
            auth.authorize(self.plan, self.confirmation)
        self.registry = self.make_registry()
        changed = RepairConfirmation(canonical(dict(self.confirmation.as_dict(), click_id=AUDIENCE)))
        with self.assertRaises(PolicyError):
            auth.authorize(self.plan, changed)

    def test_expiry_and_safe_provider_failure(self):
        auth = self.authorization()
        self.now = END
        with self.assertRaises(PolicyError):
            auth.authorize(self.plan, self.confirmation)
        self.now = NOW
        def fail():
            raise RuntimeError("private-operator-detail")
        arguments = dict(self.arguments, registry_provider=fail)
        auth = OperatorAuthorization(self.proof(repair_intent_bytes(AUDIENCE, self.confirmation)), **arguments)
        with self.assertRaises(PolicyError) as caught:
            auth.authorize(self.plan, self.confirmation)
        self.assertEqual(str(caught.exception), "operator authorization unavailable")

    def test_read_current_grants_revocation_and_request_detachment(self):
        request = self.request()
        proof = self.proof(read_intent_bytes(AUDIENCE, request))
        auth = OperatorReadAuthorization(request, proof, **self.arguments)
        request["actor_id"] = HOST
        proof["signature"] = b"x" * 64
        self.assertEqual(auth.read_scope().evidence_hosts, frozenset({HOST}))
        principal = OperatorPrincipal(ACTOR, evidence_hosts=frozenset(), audit_hosts=frozenset({HOST}))
        self.registry = OperatorRegistry({"operator": OperatorKey(self.key.public_key().public_bytes_raw(), principal)})
        self.assertEqual(auth.read_scope().evidence_hosts, frozenset())
        self.assertEqual(auth.read_scope().audit_hosts, frozenset({HOST}))
        self.registry = OperatorRegistry({"replacement": OperatorKey(self.key.public_key().public_bytes_raw(), principal)})
        with self.assertRaises(PolicyError):
            auth.read_scope()

    def test_registry_detached_bounds_and_forged_objects(self):
        principal = OperatorPrincipal(ACTOR)
        keys = {"operator": OperatorKey(self.key.public_key().public_bytes_raw(), principal)}
        registry = OperatorRegistry(keys)
        keys.clear()
        self.assertEqual(registry.lookup("operator").principal.actor_id, ACTOR)
        hosts = frozenset(f"00000000-0000-4000-8000-{number:012d}" for number in range(17))
        with self.assertRaises(PolicyError):
            OperatorPrincipal(ACTOR, evidence_hosts=hosts)
        OperatorPrincipal(ACTOR, evidence_hosts=frozenset(sorted(hosts)[:16]))
        for keyset in ({}, {"operator": object.__new__(OperatorKey)},
                       {"operator": OperatorKey(self.key.public_key().public_bytes_raw(), principal),
                        "alias": OperatorKey(self.key.public_key().public_bytes_raw(), principal)}):
            with self.assertRaises(PolicyError):
                OperatorRegistry(keyset)
        with self.assertRaises(PolicyError):
            OperatorKey(self.key.public_key().public_bytes_raw(), object.__new__(OperatorPrincipal))
        self.registry = object.__new__(OperatorRegistry)
        with self.assertRaises(PolicyError):
            self.authorization().authorize(self.plan, self.confirmation)

    def test_registry_key_limit_and_exact_grants_no_cartesian_product(self):
        keys = {f"key-{i}": OperatorKey(Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                                       OperatorPrincipal(ACTOR)) for i in range(65)}
        with self.assertRaises(PolicyError):
            OperatorRegistry(keys)
        keys.pop("key-64")
        OperatorRegistry(keys)
        principal = OperatorPrincipal(ACTOR, frozenset({(HOST, "diagnostics_capture"),
                                                       (ACTOR, "status_refresh")}))
        self.registry = OperatorRegistry({"operator": OperatorKey(self.key.public_key().public_bytes_raw(), principal)})
        with self.assertRaises(PolicyError):
            self.authorization().authorize(self.plan, self.confirmation)

    def test_tampered_signature_and_all_confirmation_bindings(self):
        auth = self.authorization()
        for field, value in (("actor_id", HOST), ("target_host", ACTOR),
                             ("version", 2), ("runbook_id", "diagnostics_capture"),
                             ("plan_digest", "0" * 64), ("runbook_digest", "0" * 64),
                             ("expires_at", "2026-01-01T00:00:59Z")):
            with self.subTest(field=field):
                changed = RepairConfirmation(canonical(dict(self.confirmation.as_dict(), **{field: value})))
                with self.assertRaises(PolicyError):
                    auth.authorize(self.plan, changed)
        proof = {"key_id": "operator", "signature": b"x" * 64}
        with self.assertRaises(PolicyError):
            OperatorAuthorization(proof, **self.arguments).authorize(self.plan, self.confirmation)

    def test_read_time_boundaries_rollback_and_slow_provider(self):
        request = self.request()
        proof = self.proof(read_intent_bytes(AUDIENCE, request))
        auth = OperatorReadAuthorization(request, proof, **self.arguments)
        self.now = "2026-01-01T00:00:30Z"
        auth.read_scope()
        self.now = NOW
        with self.assertRaises(PolicyError):
            auth.read_scope()
        for now in ("2025-12-31T23:59:59Z", END):
            self.now = now
            with self.assertRaises(PolicyError):
                OperatorReadAuthorization(request, proof, **self.arguments).read_scope()
        def slow_provider():
            self.now = END
            return self.registry
        self.now = NOW
        args = dict(self.arguments, registry_provider=slow_provider)
        with self.assertRaises(PolicyError):
            OperatorReadAuthorization(request, proof, **args).read_scope()
        self.now = NOW
        proof = self.proof(repair_intent_bytes(AUDIENCE, self.confirmation))
        with self.assertRaises(PolicyError):
            OperatorAuthorization(proof, **args).authorize(self.plan, self.confirmation)

    def test_read_request_strictness_and_context_audience_actor(self):
        request = self.request()
        for mutation in ({"schema_version": True}, {"actor_id": "private-operator-detail"},
                         {"raw_log": "private-operator-detail"},
                         {"expires_at": "2026-01-01T00:01:01Z"}, {"expires_at": NOW}):
            with self.assertRaises(PolicyError) as caught:
                read_intent_bytes(AUDIENCE, dict(request, **mutation))
            self.assertNotIn("private-operator-detail", str(caught.exception))
        for message in (read_intent_bytes(HOST, request),
                        read_intent_bytes(AUDIENCE, dict(request, actor_id=HOST))):
            with self.assertRaises(PolicyError):
                OperatorReadAuthorization(request, self.proof(message), **self.arguments).read_scope()
        with self.assertRaises(PolicyError):
            OperatorAuthorization({"key_id": "operator", "signature": b"x" * 65}, **self.arguments)
