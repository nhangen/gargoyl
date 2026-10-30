"""Operator proof plus real encrypted audit, with self-authored recording operation."""

import os
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_repair_catalog as repair_fixtures
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_repair_catalog import ACTOR, CLICK, END, HOST, NOW

from gargoyl.repair_audit import RepairAuditStore
from gargoyl.repair_contract import OperationResult
from gargoyl.repair_operator import (
    OperatorAuthorization,
    OperatorKey,
    OperatorPrincipal,
    OperatorRegistry,
    repair_intent_bytes,
)
from gargoyl.repair_runtime import RepairRuntime

AUDIENCE = "00000000-0000-4000-8000-000000000010"


class OperatorRuntimeTests(unittest.TestCase):
    def setUp(self):
        fixture = repair_fixtures.RepairCatalogTests()
        fixture.setUp()
        self.catalog, self.plan, self.confirmation = fixture.catalog, fixture.plan, fixture.confirmation()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = RepairAuditStore(self.temp.name, key=os.urandom(32))
        self.addCleanup(self.audit.close)
        self.now = NOW
        self.key = Ed25519PrivateKey.generate()
        self.set_grants(True)
        self.proof = {"key_id": "operator",
                      "signature": self.key.sign(repair_intent_bytes(AUDIENCE, self.confirmation))}
        self.auth = OperatorAuthorization(self.proof, registry_provider=lambda: self.registry,
                                          audience=AUDIENCE, wall_clock=lambda: self.now)
        self.calls = 0
        owner = self

        class RecordingOperation:
            supported_operations = frozenset({"status_refresh"})
            total_timeout_seconds = 1

            def execute(self, plan, *, stop_event):
                owner.assertEqual(owner.audit.lookup(CLICK).as_dict()["state"], "started")
                owner.calls += 1
                return OperationResult("succeeded", "completed", True)

        self.runtime = RepairRuntime(catalog=self.catalog, audit=self.audit, authorization=self.auth,
                                     evidence=lambda host: [], wall_clock=lambda: self.now,
                                     adapter=RecordingOperation())

    def set_grants(self, allowed):
        self.registry = OperatorRegistry({"operator": OperatorKey(self.key.public_key().public_bytes_raw(),
            OperatorPrincipal(ACTOR, frozenset({(HOST, "status_refresh")}) if allowed else frozenset()))})

    def execute(self):
        return self.runtime.execute(self.plan, self.confirmation, stop_event=threading.Event()).as_dict()

    def test_signed_execution_rechecks_and_never_replays(self):
        with patch.object(self.auth, "authorize", wraps=self.auth.authorize) as authorize:
            result = self.execute()
            self.assertEqual(authorize.call_count, 2)
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(self.audit.lookup(CLICK).as_dict()["receipt"], result)
        self.assertEqual(self.execute()["reason"], "already_claimed")
        self.assertEqual(self.calls, 1)

    def test_revocation_during_claim_is_durable_refusal(self):
        original = self.audit.claim
        def revoke(*args, **kwargs):
            claimed = original(*args, **kwargs)
            self.set_grants(False)
            return claimed
        with patch.object(self.audit, "claim", side_effect=revoke):
            result = self.execute()
        self.assertEqual((result["outcome"], result["reason"], result["stage"]),
                         ("blocked", "authorization_denied", "claim"))
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.audit.lookup(CLICK).as_dict()["receipt"], result)
        self.set_grants(True)
        self.assertEqual(self.execute()["reason"], "already_claimed")
        self.assertEqual(self.calls, 0)

    def test_slow_second_authorization_cannot_extend_confirmation(self):
        calls = []
        original = self.auth.authorize
        def delayed(plan, confirmation):
            calls.append(1)
            original(plan, confirmation)
            if len(calls) == 2:
                self.now = END
        with patch.object(self.auth, "authorize", side_effect=delayed):
            result = self.execute()
        self.assertEqual((result["outcome"], result["reason"]), ("blocked", "confirmation_expired"))
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.audit.lookup(CLICK).as_dict()["state"], "finished")

    def test_second_authorization_boolean_is_denial(self):
        with patch.object(self.auth, "authorize", side_effect=[None, True]):
            result = self.execute()
        self.assertEqual(result["reason"], "authorization_denied")
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.audit.lookup(CLICK).as_dict()["state"], "finished")

    def test_second_authorization_failure_is_private_and_claim_stays_consumed(self):
        with patch.object(self.auth, "authorize", side_effect=[None, RuntimeError("private-auth-detail")]):
            result = self.execute()
        self.assertEqual(result["reason"], "authorization_denied")
        self.assertNotIn("private-auth-detail", str(result))
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.audit.lookup(CLICK).as_dict()["state"], "finished")
        self.assertEqual(self.execute()["reason"], "already_claimed")
