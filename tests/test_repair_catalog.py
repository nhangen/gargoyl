import hashlib
import unittest
from dataclasses import FrozenInstanceError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gargoyl.repair_catalog import SIGNING_CONTEXT, RunbookCatalog, VerifiedRunbook
from gargoyl.repair_contract import (
    RUNBOOK_IDS,
    OperationResult,
    RepairAuditEntry,
    RepairConfirmation,
    RepairPlan,
    RepairReceipt,
    canonical,
    manifest_bytes,
    validate_confirmation,
)
from gargoyl.telemetry import PolicyError

HOST = "00000000-0000-4000-8000-000000000001"
ACTOR = "00000000-0000-4000-8000-000000000002"
CLICK = "00000000-0000-4000-8000-000000000003"
NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-01T00:00:30Z"
END = "2026-01-01T00:01:00Z"


class RepairCatalogTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.manifest = {"schema_version": 1, "runbook_id": "status_refresh", "version": 1,
                         "operation": "status_refresh", "timeout_seconds": 5}
        self.catalog, self.runbook = self.signed(self.manifest)
        self.plan = self.catalog.plan(self.runbook, HOST, [], now=NOW)

    def signed(self, manifest):
        payload = manifest_bytes(manifest)
        catalog = RunbookCatalog(
            trusted_keys={"test-key": self.key.public_key().public_bytes_raw()},
            allowed_versions=frozenset({(manifest["runbook_id"], manifest["version"],
                                        hashlib.sha256(payload).hexdigest())}))
        return catalog, catalog.verify_runbook(
            payload, self.key.sign(SIGNING_CONTEXT + payload), key_id="test-key")

    def confirmation(self, plan=None):
        plan = plan or self.plan
        return RepairConfirmation(canonical({
            "schema_version": 1, "actor_id": ACTOR, "click_id": CLICK, "target_host": HOST,
            "runbook_id": "status_refresh", "version": 1, "runbook_digest": self.runbook.digest,
            "plan_digest": plan.digest, "confirmed_at": NOW, "expires_at": END,
            "impact_acknowledged": False}))

    def receipt(self):
        return {"schema_version": 1, "actor_id": ACTOR, "click_id": CLICK,
                "target_host": HOST, "runbook_id": "status_refresh", "version": 1,
                "runbook_digest": self.runbook.digest, "plan_digest": self.plan.digest,
                "preflight": self.plan.as_dict(), "started_at": NOW, "finished_at": LATER,
                "stage": "completion", "outcome": "succeeded", "reason": "completed",
                "cleanup_complete": True}

    def test_signature_and_exact_digest_allowlist(self):
        self.assertEqual(self.catalog.validate_runbook(self.runbook), self.runbook)
        payload = manifest_bytes(self.manifest)
        for signature, key in ((b"x" * 64, "test-key"), (self.key.sign(payload), "test-key"),
                               (self.key.sign(SIGNING_CONTEXT + payload), "missing")):
            with self.assertRaises(PolicyError):
                self.catalog.verify_runbook(payload, signature, key_id=key)
        altered = dict(self.manifest, timeout_seconds=6)
        payload = manifest_bytes(altered)
        with self.assertRaises(PolicyError):
            self.catalog.verify_runbook(payload, self.key.sign(SIGNING_CONTEXT + payload), key_id="test-key")

    def test_all_five_runbooks_and_conservative_blocks(self):
        for name in RUNBOOK_IDS:
            catalog, book = self.signed(dict(self.manifest, runbook_id=name, operation=name))
            plan = catalog.plan(book, HOST, [], now=NOW)
            self.assertEqual(plan.as_dict()["blocked"], name not in {"status_refresh", "diagnostics_capture"})
            self.assertEqual(catalog.validate_plan(plan, now=LATER), plan)

    def test_detached_immutable_plan_and_forged_content(self):
        with self.assertRaises(FrozenInstanceError):
            self.plan.payload = b"{}"
        value = self.plan.as_dict()
        value["checks"][0]["state"] = "blocked"
        with self.assertRaises(PolicyError):
            self.catalog.validate_plan(RepairPlan(canonical(value)), now=NOW)
        proof = self.runbook.as_dict()
        proof["signature"] = "0" * 128
        with self.assertRaises(PolicyError):
            self.catalog.plan(VerifiedRunbook(canonical(proof)), HOST, [], now=NOW)
        for forged in (object.__new__(VerifiedRunbook), object()):
            with self.assertRaises(PolicyError):
                self.catalog.validate_runbook(forged)
        for forged in (object.__new__(RepairPlan), object()):
            with self.assertRaises(PolicyError):
                self.catalog.validate_plan(forged, now=NOW)

    def test_strict_manifest_and_payload_bounds(self):
        for mutation in ({"version": True}, {"timeout_seconds": 10**400},
                         {"operation": "shell"}, {"command": "private-detail"}):
            with self.assertRaises(PolicyError):
                manifest_bytes(dict(self.manifest, **mutation))
        for payload in (b'{"version":1,"version":1}', b"x" * 65537, b"\xff", b"[" * 1000,
                        b'{"schema_version":NaN}'):
            with self.assertRaises(PolicyError) as caught:
                self.catalog.verify_runbook(payload, b"x" * 64, key_id="test-key")
            self.assertNotIn("private-detail", str(caught.exception))

    def test_confirmation_is_bound_and_expires_without_granting_authority(self):
        confirmation = self.confirmation()
        self.assertEqual(validate_confirmation(confirmation, self.plan, now=LATER), confirmation)
        for now in ("2025-12-31T23:59:59Z", END):
            with self.assertRaises(PolicyError):
                validate_confirmation(confirmation, self.plan, now=now)
        for mutation in ({"target_host": ACTOR}, {"plan_digest": "0" * 64}, {"version": 2}):
            value = dict(confirmation.as_dict(), **mutation)
            with self.assertRaises(PolicyError):
                validate_confirmation(RepairConfirmation(canonical(value)), self.plan, now=NOW)
        with self.assertRaises(PolicyError):
            RepairConfirmation(canonical(dict(confirmation.as_dict(), impact_acknowledged=True)))

    def test_receipt_and_claim_shape_and_binding(self):
        receipt = RepairReceipt(canonical(self.receipt()))
        entry = {"schema_version": 1, "state": "started", "plan": self.plan.as_dict(),
                 "confirmation": self.confirmation().as_dict(), "started_at": NOW, "receipt": None}
        RepairAuditEntry(canonical(entry))
        RepairAuditEntry(canonical(dict(entry, state="finished", receipt=receipt.as_dict())))
        for mutation in ({"cleanup_complete": False}, {"reason": "operation_failed"},
                         {"plan_digest": "0" * 64}, {"raw_output": "private-detail"}):
            with self.assertRaises(PolicyError):
                RepairReceipt(canonical(dict(self.receipt(), **mutation)))
        with self.assertRaises(PolicyError):
            RepairAuditEntry(canonical(dict(entry, state="finished", receipt=None)))

    def test_operation_results_preserve_uncertainty(self):
        OperationResult("succeeded", "completed", True).validate()
        OperationResult("outcome_unknown", "cleanup_incomplete", False).validate()
        for result in (OperationResult("succeeded", "completed", False),
                       OperationResult("failed", "operation_failed", False),
                       object.__new__(OperationResult)):
            with self.assertRaises(PolicyError):
                result.validate()
