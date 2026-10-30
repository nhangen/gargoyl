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
