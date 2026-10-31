"""Controlled provider/ledger simulation; never restarts an installed provider."""

import copy
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from restart_fixtures import ACTOR, ATTEMPT, CHALLENGE, HOST, OTHER, Fixture

from gargoyl.repair_contract import canonical
from gargoyl.repair_process_identity import MacOSProcessVerifier
from gargoyl.repair_restart_contract import (
    ProviderProof,
    RestartConfirmation,
    RestartPlan,
    bind_confirmation,
    request_bytes,
)
from gargoyl.repair_restart_journal import (
    RestartJournal,
    RestartJournalError,
    RestartPending,
)
from gargoyl.telemetry import PolicyError


class RestartTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.f = Fixture(self.root)
        self.addCleanup(self.f.journal.close)
        self.stop = threading.Event()

    def execute(self, *, runtime=None, intent=None):
        p, c, proof = intent or (self.f.plan, self.f.confirmation, self.f.proof)
        return (
            (runtime or self.f.runtime)
            .execute(p, c, proof, stop_event=self.stop)
            .as_dict()
        )

    def test_success_is_one_replacement_same_configuration_and_still_fenced(self):
        result = self.execute()
        self.assertEqual(
            (result["outcome"], result["reason"]), ("succeeded", "completed")
        )
        self.assertEqual((self.f.provider.calls, self.f.provider.effects), (1, 1))
        self.assertTrue(self.f.provider.fenced)
        self.assertEqual(
            (self.f.provider.config, self.f.provider.model), ("a" * 64, "b" * 64)
        )
        self.assertEqual(self.f.journal.lookup(ATTEMPT)["receipt"], result)
        self.assertIsNotNone(self.f.journal.pending())

    def test_default_backend_refuses_before_claim(self):
        result = self.execute(runtime=self.f.make_runtime(backend=False))
        self.assertEqual(result["reason"], "operation_unavailable")
        self.assertIsNone(self.f.journal.lookup(ATTEMPT))
        self.assertEqual(self.f.provider.calls, 0)

    def test_v1_catalog_still_blocks_disruptive_operation(self):
        self.assertTrue(
            self.f.catalog.plan(
                self.f.book, HOST, [], now=self.f.clock.wall()
            ).as_dict()["blocked"]
        )
        with self.assertRaises(PolicyError):
            RestartPlan(
                canonical(
                    self.f.catalog.plan(
                        self.f.book, HOST, [], now=self.f.clock.wall()
                    ).as_dict()
                )
            )

    def test_each_missing_or_unsafe_precondition_refuses_plan(self):
        original = self.f.provider.state(CHALLENGE)
        changes = [
            dict(admission_fenced=False),
            dict(outstanding_work=1),
            dict(coordinator_acknowledged=False),
            dict(ack_drain_id=OTHER),
            dict(ack_process=dict(original["process"], born_us=1)),
            dict(host_id=OTHER),
            dict(backend_id=OTHER),
            dict(challenge=OTHER),
            dict(process=dict(original["process"], born_us=1)),
            dict(observed_at="2025-12-31T23:59:50Z", expires_at="2025-12-31T23:59:55Z"),
        ]
        for change in changes:
            with self.subTest(change=change):
                body = dict(original, **change)
                proof = ProviderProof(self.f.provider.sign("state", body))
                with self.assertRaises(PolicyError):
                    self.f.policy.plan(
                        self.f.book, proof, challenge=CHALLENGE, now=self.f.clock.wall()
                    )
        self.assertEqual(self.f.provider.effects, 0)

    def test_missing_fields_duplicate_keys_nonfinite_and_wrong_signature_fail_closed(
        self,
    ):
        body = self.f.provider.state(CHALLENGE)
        body.pop("fence_id")
        with self.assertRaises(PolicyError):
            ProviderProof(
                canonical(
                    dict(
                        kind="state", key_id="provider", body=body, signature="0" * 128
                    )
                )
            )
        for payload in (
            b'{"kind":"state","kind":"result"}',
            b'{"bad":NaN}',
            b"x" * 65537,
        ):
            with self.assertRaises(PolicyError):
                ProviderProof(payload)
        value = self.f.plan.as_dict()["preflight"]
        value["signature"] = "0" * 128
        with self.assertRaises(PolicyError):
            self.f.policy.plan(
                self.f.book,
                ProviderProof(canonical(value)),
                challenge=CHALLENGE,
                now=self.f.clock.wall(),
            )

    def test_scope_actor_and_signature_authorization_denials_never_dispatch(self):
        for change in ("grant", "actor", "signature"):
            with self.subTest(change=change):
                self.f.registry = self.f.make_registry(
                    granted=change != "grant",
                    actor=OTHER if change == "actor" else ACTOR,
                )
                proof = dict(self.f.proof)
                if change == "signature":
                    proof["signature"] = bytes(64)
                result = self.execute(intent=(self.f.plan, self.f.confirmation, proof))
                self.assertEqual(result["reason"], "authorization_denied")
        self.assertEqual(self.f.provider.calls, 0)
        self.assertIsNone(self.f.journal.pending())

    def test_confirmation_binding_and_cross_domain_signatures_refuse(self):
        changed = RestartConfirmation(
            canonical(dict(self.f.confirmation.as_dict(), plan_digest="f" * 64))
        )
        with self.assertRaises(PolicyError):
            bind_confirmation(self.f.plan, changed, self.f.clock.wall())
        proof = dict(
            self.f.proof,
            signature=self.f.operator_key.sign(
                b"gargoyl:operator:repair:v1\x00" + self.f.confirmation.payload
            ),
        )
        self.assertEqual(
            self.execute(intent=(self.f.plan, self.f.confirmation, proof))["reason"],
            "authorization_denied",
        )

    def test_expired_or_changed_state_refuses_before_claim(self):
        self.f.clock.advance(6)
        self.assertEqual(self.execute()["outcome"], "blocked")
        self.assertIsNone(self.f.journal.pending())
        self.f.clock.elapsed = 0
        self.f.provider.config = "c" * 64
        self.assertEqual(self.execute()["outcome"], "blocked")
        self.assertEqual(self.f.provider.calls, 0)

    def test_identity_or_fence_change_between_claim_and_dispatch_refuses(self):
        for change in ("fence", "identity"):
            f = Fixture(self.root / change)
            self.addCleanup(f.journal.close)
            original = f.journal.claim

            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                if change == "fence":
                    f.provider.fence = OTHER
                else:
                    f.provider.live.clear()
                return result

            with patch.object(f.journal, "claim", side_effect=changed):
                result = f.runtime.execute(
                    f.plan, f.confirmation, f.proof, stop_event=self.stop
                ).as_dict()
            self.assertEqual(result["outcome"], "blocked")
            self.assertEqual(f.provider.calls, 0)
            self.assertIsNotNone(f.journal.pending())

    def test_revocation_or_expiry_during_claim_prevents_dispatch(self):
        original = self.f.journal.claim

        def revoke(*args, **kwargs):
            result = original(*args, **kwargs)
            self.f.registry = self.f.make_registry(granted=False)
            return result

        with patch.object(self.f.journal, "claim", side_effect=revoke):
            self.assertEqual(self.execute()["outcome"], "blocked")
        self.assertEqual(self.f.provider.calls, 0)

    def test_expiry_during_journal_wait_consumes_gate_without_dispatch(self):
        original = self.f.journal.claim

        def delayed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.f.clock.advance(6)
            return result

        with patch.object(self.f.journal, "claim", side_effect=delayed):
            result = self.execute()
        self.assertIn(result["outcome"], {"blocked", "outcome_unknown"})
        self.assertEqual(self.f.provider.calls, 0)
        self.assertIsNotNone(self.f.journal.pending())

    def test_pre_cancel_never_claims_and_post_accept_cancel_is_unknown(self):
        self.stop.set()
        self.assertEqual(self.execute()["outcome"], "cancelled")
        self.assertIsNone(self.f.journal.pending())
        self.stop.clear()
        original = self.f.provider.restart_once

        def cancel(*args, **kwargs):
            result = original(*args, **kwargs)
            self.stop.set()
            return result

        with patch.object(self.f.provider, "restart_once", side_effect=cancel):
            result = self.execute()
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(self.f.provider.effects, 1)
        self.assertIsNotNone(self.f.journal.pending())

    def test_backend_atomic_state_change_at_mutation_is_not_overridden(self):
        self.f.provider.on_restart = lambda backend: setattr(backend, "fenced", False)
        self.assertEqual(self.execute()["outcome"], "outcome_unknown")
        self.assertEqual(self.f.provider.effects, 0)
        self.assertIsNotNone(self.f.journal.pending())

    def test_unknown_reply_blocks_fresh_clicks_after_restart_and_reopen(self):
        self.f.provider.mode = "lost_reply"
        self.assertEqual(self.execute()["outcome"], "outcome_unknown")
        self.assertEqual(self.f.provider.effects, 1)
        reopened = RestartJournal(
            self.root / "journal", target_host=HOST, key=self.f.journal_key
        )
        self.addCleanup(reopened.close)
        other = self.f.make_runtime()
        other.journal = reopened
        fresh = self.f.intent(attempt=OTHER, challenge=OTHER)
        self.assertEqual(
            self.execute(runtime=other, intent=fresh)["reason"], "recovery_required"
        )
        self.assertEqual(self.f.provider.calls, 1)

    def test_late_and_incomplete_cleanup_never_succeed_or_release_gate(self):
        for mode in ("late", "pending_timeout", "cleanup_incomplete"):
            f = Fixture(self.root / mode)
            self.addCleanup(f.journal.close)
            f.provider.mode = mode
            result = f.runtime.execute(
                f.plan, f.confirmation, f.proof, stop_event=self.stop
            ).as_dict()
            self.assertEqual(result["outcome"], "outcome_unknown")
            self.assertIsNotNone(f.journal.pending())
            self.assertEqual(f.provider.calls, 1)

    def test_result_requires_new_identity_fence_same_config_and_terminal_ledger(self):
        cases = [
            dict(admission_fenced=False),
            dict(outstanding_work=1),
            dict(fence_id=OTHER),
            dict(config_digest="f" * 64),
            dict(model_digest="f" * 64),
            dict(request_digest="f" * 64),
            dict(attempt_id=OTHER),
            dict(terminal=False),
            dict(no_pending_restart=False),
        ]
        for i, change in enumerate(cases):
            f = Fixture(self.root / str(i))
            self.addCleanup(f.journal.close)
            f.provider.result_change = lambda body: body.update(change)
            result = f.runtime.execute(
                f.plan, f.confirmation, f.proof, stop_event=self.stop
            ).as_dict()
            self.assertEqual(result["outcome"], "outcome_unknown")
            self.assertIsNotNone(f.journal.pending())

    def test_forged_or_unverified_replacement_cannot_claim_success(self):
        def wrong(body):
            body["process"] = dict(body["previous_process"])

        self.f.provider.result_change = wrong
        self.assertEqual(self.execute()["outcome"], "outcome_unknown")
        self.assertIsNotNone(self.f.journal.pending())

    def test_reconciliation_is_read_only_and_never_retries_old_attempt(self):
        self.f.provider.mode = "lost_reply"
        self.execute()
        effects = self.f.provider.effects
        calls = self.f.provider.calls
        proof = self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
        self.assertEqual(proof.as_dict()["kind"], "reconciliation")
        self.assertIsNone(self.f.journal.pending())
        self.assertEqual(
            (self.f.provider.calls, self.f.provider.effects), (calls, effects)
        )
        self.assertIsNotNone(self.f.journal.lookup(ATTEMPT)["resolution"])
        # A new attempt requires a separately signed fresh plan; no automatic action.
        self.f.provider.mode = None
        fresh = self.f.intent(attempt=OTHER, challenge=OTHER)
        self.assertEqual(self.execute(intent=fresh)["outcome"], "succeeded")
        self.assertEqual(self.f.provider.calls, 2)

    def test_pending_not_found_or_stale_reconciliation_cannot_clear_gate(self):
        self.f.provider.mode = "pending_timeout"
        self.execute()
        for status in ("pending", None):
            self.f.provider.ledger = {k: status for k in self.f.provider.ledger}
            with self.assertRaises(PolicyError):
                self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
            self.assertIsNotNone(self.f.journal.pending())
        self.assertEqual(self.f.provider.calls, 1)

    def test_old_resolution_cannot_clear_new_gate(self):
        self.execute()
        proof = self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
        fresh = self.f.intent(attempt=OTHER, challenge=OTHER)
        self.execute(intent=fresh)
        with self.assertRaises(RestartJournalError):
            self.f.journal.reconcile(
                proof, policy=self.f.policy, wall_clock=self.f.clock.wall
            )
        self.assertEqual(self.f.journal.pending()["confirmation"]["click_id"], OTHER)

    def test_same_runtime_concurrent_call_refuses_without_queueing(self):
        entered, release = threading.Event(), threading.Event()
        original = self.f.provider.observe

        def held(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(2))
            return original(*args, **kwargs)

        with (
            patch.object(self.f.provider, "observe", side_effect=held),
            ThreadPoolExecutor(1) as pool,
        ):
            future = pool.submit(self.execute)
            self.assertTrue(entered.wait(2))
            try:
                with self.assertRaises(PolicyError):
                    self.execute()
            finally:
                release.set()
            self.assertEqual(future.result(timeout=3)["outcome"], "succeeded")
        self.assertEqual(self.f.provider.calls, 1)

    def test_concurrent_claims_different_clicks_reserve_host_atomically(self):
        other = RestartJournal(
            self.root / "journal", target_host=HOST, key=self.f.journal_key
        )
        self.addCleanup(other.close)
        intent = self.f.intent(attempt=OTHER)

        def claim(journal, p, c, proof):
            try:
                return journal.claim(p, c, proof, now=self.f.clock.wall())
            except RestartPending:
                return "pending"

        with ThreadPoolExecutor(2) as pool:
            futures = [
                pool.submit(
                    claim,
                    self.f.journal,
                    self.f.plan,
                    self.f.confirmation,
                    self.f.proof,
                ),
                pool.submit(claim, other, *intent),
            ]
            results = [future.result() for future in futures]
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count("pending"), 1)

    def test_commit_ambiguity_before_dispatch_keeps_gate_and_never_invokes(self):
        original = self.f.journal._commit

        def committed_then_lost():
            original()
            raise OSError("synthetic-private")

        with patch.object(self.f.journal, "_commit", side_effect=committed_then_lost):
            result = self.execute()
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(self.f.provider.calls, 0)
        self.assertIsNotNone(self.f.journal.pending())

    def test_finalization_failure_keeps_consumed_intent_and_host_gate(self):
        with patch.object(
            self.f.journal, "finish", side_effect=OSError("synthetic-private")
        ):
            result = self.execute()
        self.assertEqual(
            (result["outcome"], result["reason"]),
            ("outcome_unknown", "audit_unavailable"),
        )
        self.assertEqual(self.f.journal.lookup(ATTEMPT)["state"], "started")
        self.assertIsNotNone(self.f.journal.pending())
        self.assertNotIn("synthetic-private", repr(result))

    def test_journal_corruption_deletion_permissions_and_wrong_key_refuse(self):
        self.execute()
        with self.assertRaises(RestartJournalError):
            RestartJournal(self.root / "journal", target_host=HOST, key=os.urandom(32))
        self.f.journal._db.execute("DELETE FROM records")
        with self.assertRaises(RestartJournalError):
            self.f.journal.pending()

    def test_runtime_reopen_never_reprovisions_missing_consumed_state(self):
        self.f.provider.mode = "pending_timeout"
        self.execute()
        path = self.f.journal._path
        self.f.journal.close()
        path.unlink()
        with self.assertRaises(RestartJournalError):
            RestartJournal(
                self.root / "journal", target_host=HOST, key=self.f.journal_key
            )
        self.assertFalse(path.exists())

    def test_explicit_creation_refuses_existing_journal_and_open_refuses_missing_directory(
        self,
    ):
        with self.assertRaises(RestartJournalError):
            RestartJournal.create(
                self.root / "journal", target_host=HOST, key=self.f.journal_key
            )
        with self.assertRaises(RestartJournalError):
            RestartJournal(
                self.root / "missing", target_host=HOST, key=self.f.journal_key
            )
        self.assertFalse((self.root / "missing").exists())

    def test_predispatch_refusal_requires_terminal_proof_even_if_request_unseen(self):
        original = self.f.journal.claim

        def revoke(*args, **kwargs):
            result = original(*args, **kwargs)
            self.f.registry = self.f.make_registry(granted=False)
            return result

        with patch.object(self.f.journal, "claim", side_effect=revoke):
            self.assertEqual(self.execute()["outcome"], "blocked")
        self.assertEqual(self.f.provider.calls, 0)
        with self.assertRaises(RestartJournalError):
            self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
        self.assertIsNotNone(self.f.journal.pending())

    def test_capacity_no_eviction_and_no_plaintext_fallback(self):
        self.f.journal._limit = 1
        self.execute()
        self.assertNotIn(self.f.plan.payload, self.f.journal._path.read_bytes())
        self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
        fresh = self.f.intent(attempt=OTHER, challenge=OTHER)
        self.assertEqual(self.execute(intent=fresh)["outcome"], "outcome_unknown")
        self.assertIsNotNone(self.f.journal.lookup(ATTEMPT))
        self.assertEqual(self.f.provider.calls, 1)

    def test_interrupt_after_acceptance_never_retries_or_claims_cleanup(self):
        original = self.f.provider.restart_once

        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt

        with patch.object(self.f.provider, "restart_once", side_effect=interrupted):
            result = self.execute()
        self.assertEqual(
            (result["outcome"], result["reason"], result["cleanup_complete"]),
            ("outcome_unknown", "interrupted", False),
        )
        self.assertEqual(self.f.provider.effects, 1)
        self.assertIsNotNone(self.f.journal.pending())

    def test_expired_result_and_process_birth_before_intent_are_refused(self):
        for case in ("expired", "old_birth", "native_denied"):
            f = Fixture(self.root / case)
            self.addCleanup(f.journal.close)

            def change(body):
                if case == "expired":
                    body.update(
                        observed_at="2025-12-31T23:59:50Z",
                        expires_at="2025-12-31T23:59:55Z",
                    )
                elif case == "old_birth":
                    body["process"]["born_us"] -= 50000000
                    f.provider.live[body["process"]["pid"]] = dict(body["process"])
                else:
                    f.provider.live.clear()

            f.provider.result_change = change
            result = f.runtime.execute(
                f.plan, f.confirmation, f.proof, stop_event=self.stop
            ).as_dict()
            self.assertEqual(result["outcome"], "outcome_unknown")
            self.assertIsNotNone(f.journal.pending())

    def test_clock_rollback_after_backend_action_is_unknown(self):
        original = self.f.provider.restart_once

        def rollback(*args, **kwargs):
            result = original(*args, **kwargs)
            self.f.clock.elapsed = -1
            return result

        with patch.object(self.f.provider, "restart_once", side_effect=rollback):
            result = self.execute()
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(result["reason"], "clock_invalid")
        self.assertIsNotNone(self.f.journal.pending())

    def test_future_stale_or_wrong_backend_reconciliation_preserves_gate(self):
        self.execute()
        entry = self.f.journal.pending()
        request = request_bytes(self.f.plan, self.f.confirmation, self.f.proof)
        value = json.loads(
            self.f.provider.reconcile(
                request, OTHER, deadline=time.monotonic() + 1, stop_event=self.stop
            )
        )
        for change in (
            dict(attempt_id=OTHER),
            dict(request_digest="f" * 64),
            dict(backend_id=OTHER),
            dict(observed_at="2025-12-31T23:59:50Z", expires_at="2025-12-31T23:59:55Z"),
        ):
            body = copy.deepcopy(value["body"])
            body.update(change)
            for name in (
                "host_id",
                "backend_id",
                "challenge",
                "observed_at",
                "expires_at",
            ):
                body["state"][name] = body[name]
            proof = ProviderProof(self.f.provider.sign("reconciliation", body))
            with self.assertRaises(RestartJournalError):
                self.f.journal.reconcile(
                    proof, policy=self.f.policy, wall_clock=self.f.clock.wall
                )
            self.assertEqual(self.f.journal.pending(), entry)

    def test_private_directory_file_identity_and_size_limits_fail_closed(self):
        for case in ("directory", "hardlink", "missing", "oversized"):
            f = Fixture(self.root / case)
            self.addCleanup(f.journal.close)
            f.journal.claim(f.plan, f.confirmation, f.proof, now=f.clock.wall())
            if case == "directory":
                f.journal._path.parent.chmod(0o755)
            elif case == "hardlink":
                os.link(f.journal._path, f.root / "linked")
            elif case == "missing":
                f.journal._path.unlink()
            else:
                f.journal._db.execute("UPDATE records SET payload=?", (bytes(65565),))
            with self.assertRaises(RestartJournalError):
                f.journal.pending()
            if case == "directory":
                f.journal._path.parent.chmod(0o700)

    def test_consumed_click_is_not_reset_by_reconciliation(self):
        self.execute()
        self.f.runtime.reconcile(challenge=OTHER, stop_event=self.stop)
        self.assertFalse(
            self.f.journal.claim(
                self.f.plan,
                self.f.confirmation,
                self.f.proof,
                now=self.f.confirmation.as_dict()["confirmed_at"],
            )
        )
        self.assertEqual(self.f.provider.calls, 1)

    def test_controlled_transport_child_obeys_real_cleanup_inclusive_deadline(self):
        # This is an owned transport test process, never the provider. It models
        # a bounded backend implementation; the library cannot bound a lying callback.
        self.f.provider.total_timeout_seconds = 0.6
        process = []

        def bounded(request, *, deadline, stop_event):
            self.f.provider.calls += 1
            child = subprocess.Popen(
                [sys.executable, "-c", "import time;time.sleep(10)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.append(child)

            def cleanup():
                if child.poll() is None:
                    child.kill()  # Owned transport fixture only, never provider code.
                child.communicate(timeout=3)

            self.addCleanup(cleanup)
            try:
                child.communicate(timeout=max(0.01, deadline - time.monotonic() - 0.2))
            except subprocess.TimeoutExpired:
                child.terminate()
                child.communicate(timeout=max(0.01, deadline - time.monotonic()))
            return RestartBackendResult(None, child.poll() is not None)

        from gargoyl.repair_restart_runtime import RestartBackendResult

        begin = time.monotonic()
        with patch.object(self.f.provider, "restart_once", side_effect=bounded):
            result = self.execute()
        self.assertLess(time.monotonic() - begin, 1.5)
        self.assertIsNotNone(process[0].poll())
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(self.f.provider.calls, 1)
        self.assertIsNotNone(self.f.journal.pending())

    def test_receipts_and_provider_contexts_are_not_interchangeable(self):
        proof = self.f.plan.as_dict()["preflight"]
        proof["kind"] = "result"
        with self.assertRaises(PolicyError):
            ProviderProof(canonical(proof))
        bad = json.loads(self.f.plan.payload)
        bad["policy"] = "force"
        with self.assertRaises(PolicyError):
            RestartPlan(canonical(bad))


@unittest.skipUnless(sys.platform == "darwin", "Darwin libproc verification")
class NativeIdentityTests(unittest.TestCase):
    def test_native_identity_for_only_this_test_process(self):
        # No denied ps target or unrelated process is inspected.
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        buffer = ctypes.create_string_buffer(4096)
        self.assertGreater(lib.proc_pidpath(os.getpid(), buffer, len(buffer)), 0)
        executable = buffer.value.decode("utf-8")
        verifier = MacOSProcessVerifier(
            expected_owner_uid=os.getuid(), expected_executable=executable
        )
        identity = verifier._identity(os.getpid())
        self.assertTrue(verifier(identity))
        self.assertFalse(verifier(dict(identity, born_us=identity["born_us"] + 1)))
        self.assertFalse(verifier(dict(identity, owner_uid=os.getuid() + 1)))
        self.assertFalse(verifier(dict(identity, pid=2**31 - 1)))
