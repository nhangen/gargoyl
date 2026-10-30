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
                        b'{"schema_version":NaN}',
                        canonical(dict(self.manifest, command="private-detail")),
                        canonical(dict(self.manifest, operation="private-detail"))):
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

    def snapshot(self, *, when=NOW, value="running", source="daemon"):
        return {"schema_version": 1, "host_id": HOST, "collected_at": when,
                "fields": {"daemon_state": {"value": value, "source": source,
                "timestamp": when, "freshness_seconds": 10,
                "state": "observed", "sensitivity": "safe"}}}

    def test_evidence_provenance_conflicts_and_missing_stale_future_are_conservative(self):
        good = self.snapshot()
        detached = self.catalog.plan(self.runbook, HOST, [good], now=NOW)
        self.assertEqual(detached.as_dict()["checks"][1]["state"], "passed")
        cases = (([], NOW), ([good], LATER),
                 ([self.snapshot(when=LATER)], NOW),
                 ([good, self.snapshot(value="stopped")], NOW))
        for records, now in cases:
            plan = self.catalog.plan(self.runbook, HOST, records, now=now)
            self.assertEqual(plan.as_dict()["checks"][1]["state"], "unknown")
        conflicts = self.catalog.plan(self.runbook, HOST, [good, self.snapshot(value="stopped"), good], now=NOW)
        self.assertEqual(len(conflicts.as_dict()["evidence"]), 2)
        good["fields"]["daemon_state"]["value"] = "stopped"
        self.assertEqual(detached.as_dict()["evidence"][0]["fields"]["daemon_state"]["value"], "running")

    def test_cross_host_raw_fields_and_excess_evidence_fail_closed(self):
        for value in (dict(self.snapshot(), host_id=ACTOR),
                      dict(self.snapshot(), raw_logs="private-detail")):
            with self.assertRaises(PolicyError):
                self.catalog.plan(self.runbook, HOST, [value], now=NOW)
        with self.assertRaises(PolicyError):
            self.catalog.plan(self.runbook, HOST, [self.snapshot()] * 17, now=NOW)
        self.catalog.plan(self.runbook, HOST, [self.snapshot()] * 16, now=NOW)

    def test_plan_expiry_boundary_overflow_and_tampered_expiry(self):
        for now in (END, "2025-12-31T23:59:59Z"):
            with self.assertRaises(PolicyError):
                self.catalog.validate_plan(self.plan, now=now)
        self.catalog.validate_plan(self.plan, now="2026-01-01T00:00:59.999999Z")
        with self.assertRaises(PolicyError):
            self.catalog.plan(self.runbook, HOST, [], now="9999-12-31T23:59:59Z")
        shortened = dict(self.plan.as_dict(), expires_at=LATER)
        with self.assertRaises(PolicyError):
            self.catalog.validate_plan(RepairPlan(canonical(shortened)), now=NOW)

    def test_trust_registry_copy_and_replacement_rejects_old_proof(self):
        keys = {"test-key": self.key.public_key().public_bytes_raw()}
        pins = frozenset({("status_refresh", 1, self.runbook.digest)})
        catalog = RunbookCatalog(trusted_keys=keys, allowed_versions=pins)
        keys.clear()
        catalog.validate_runbook(self.runbook)
        other = Ed25519PrivateKey.generate()
        revoked = RunbookCatalog(trusted_keys={"test-key": other.public_key().public_bytes_raw()},
                                 allowed_versions=pins)
        with self.assertRaises(PolicyError):
            revoked.validate_plan(self.plan, now=NOW)
        for keys, pins in (({}, pins), ({"test-key": b"x"}, pins),
                           ({"test-key": self.key.public_key().public_bytes_raw()}, frozenset())):
            with self.assertRaises(PolicyError):
                RunbookCatalog(trusted_keys=keys, allowed_versions=pins)

    def test_exact_input_size_boundary_and_strict_utf8(self):
        payload = manifest_bytes(self.manifest)
        signature = self.key.sign(SIGNING_CONTEXT + payload)
        self.catalog.verify_runbook(payload + b" " * (65536 - len(payload)), signature, key_id="test-key")
        for raw in (payload + b" " * (65537 - len(payload)),
                    payload.decode().encode("utf-16")):
            with self.assertRaises(PolicyError):
                self.catalog.verify_runbook(raw, signature, key_id="test-key")

    def test_forged_confirmation_receipt_audit_and_operation_fields_rejected(self):
        for cls in (RepairConfirmation, RepairReceipt, RepairAuditEntry):
            with self.assertRaises(PolicyError):
                object.__new__(cls).as_dict()
        for result in (OperationResult("succeeded", "private-detail", True),
                       OperationResult("failed", "operation_failed", 1)):
            with self.assertRaises(PolicyError):
                result.validate()
        value = self.receipt()
        value["preflight"]["evidence"] = [dict(self.snapshot(), raw_logs="private-detail")]
        with self.assertRaises(PolicyError):
            RepairReceipt(canonical(value))

    def test_outcome_reason_cleanup_matrix_is_shared_at_both_boundaries(self):
        valid = [
            ("succeeded", "completed", True),
            ("failed", "operation_failed", True),
            ("cancelled", "cancelled", True),
            ("outcome_unknown", "cancelled", False),
            ("outcome_unknown", "audit_unavailable", True),
            ("outcome_unknown", "cleanup_incomplete", False),
        ]
        uncertain = ("clock_invalid", "deadline_exceeded", "interrupted",
                     "invalid_result", "recovery_required")
        valid.extend(("outcome_unknown", reason, clean) for reason in uncertain for clean in (True, False))
        invalid = [
            ("failed", "clock_invalid", True),
            ("failed", "cleanup_incomplete", True),
            ("cancelled", "completed", True),
            ("outcome_unknown", "cleanup_incomplete", True),
            ("succeeded", "operation_failed", True),
            ("failed", "operation_failed", False),
            ("outcome_unknown", "completed", True),
        ]
        invalid.extend((outcome, reason, True) for reason in uncertain
                       for outcome in ("succeeded", "failed", "cancelled"))
        for expected, cases in ((True, valid), (False, invalid)):
            for outcome, reason, cleanup in cases:
                with self.subTest(outcome=outcome, reason=reason, cleanup=cleanup, valid=expected):
                    result = OperationResult(outcome, reason, cleanup)
                    receipt = canonical(dict(self.receipt(), outcome=outcome, reason=reason,
                                             cleanup_complete=cleanup))
                    if expected:
                        self.assertEqual(result.validate(), result)
                        RepairReceipt(receipt)
                    else:
                        with self.assertRaises(PolicyError):
                            result.validate()
                        with self.assertRaises(PolicyError):
                            RepairReceipt(receipt)

    def test_receipt_stage_matrix_and_audit_nested_validation(self):
        valid = (("blocked", "authorization_denied", "preflight", True),
                 ("blocked", "already_claimed", "claim", True),
                 ("blocked", "audit_unavailable", "claim", True),
                 ("outcome_unknown", "audit_unavailable", "completion", True),
                 ("outcome_unknown", "recovery_required", "claim", False),
                 ("failed", "operation_failed", "execution", True),
                 ("outcome_unknown", "clock_invalid", "preflight", True))
        invalid = (("succeeded", "completed", "execution", True),
                   ("failed", "operation_failed", "preflight", True),
                   ("blocked", "authorization_denied", "completion", True),
                   ("blocked", "audit_unavailable", "execution", True),
                   ("outcome_unknown", "cleanup_incomplete", "claim", False),
                   ("outcome_unknown", "deadline_exceeded", "preflight", True),
                   ("outcome_unknown", "recovery_required", "execution", False))
        for accepted, cases in ((True, valid), (False, invalid)):
            for outcome, reason, stage, cleanup in cases:
                with self.subTest(outcome=outcome, reason=reason, stage=stage):
                    receipt = dict(self.receipt(), outcome=outcome, reason=reason,
                                   stage=stage, cleanup_complete=cleanup)
                    audit = {"schema_version": 1, "state": "finished", "plan": self.plan.as_dict(),
                             "confirmation": self.confirmation().as_dict(), "started_at": NOW,
                             "receipt": receipt}
                    if accepted:
                        RepairReceipt(canonical(receipt))
                        RepairAuditEntry(canonical(audit))
                    else:
                        with self.assertRaises(PolicyError):
                            RepairReceipt(canonical(receipt))
                        with self.assertRaises(PolicyError):
                            RepairAuditEntry(canonical(audit))
