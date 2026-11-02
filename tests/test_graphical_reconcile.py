"""Synthetic journal/owner fixtures; never invokes a provider or real Mac auth."""

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from test_manual_restart import NOW, REPLACEMENT, TARGET

from gargoyl.gui_runtime import graphical_reconcile
from gargoyl.manual_restart import ManualJournal, reconciliation_snapshot

LATER = "2026-10-31T12:20:00Z"


class GraphicalReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name).resolve() / "journal")
        self.events = []
        self.record = dict(
            schema=1,
            operation_id="a" * 32,
            state="unknown",
            started_at=NOW,
            finished_at=NOW,
            target=copy.deepcopy(TARGET),
            reason="completion_unverified",
            child=dict(pid=999, born_us=123),
        )

    def run_flow(self, journal, **options):
        def approve():
            preview = self.events[0]
            return {
                key: preview[key] for key in ("request_id", "preview_digest")
            } | dict(approved=True)

        arguments = dict(
            journal=journal,
            inspect_target=Mock(return_value=TARGET),
            receive=approve,
            owner=lambda: True,
            send=self.events.append,
            alive=Mock(return_value=False),
            clock=lambda: LATER,
            wall_clock=lambda: 100,
            monotonic=lambda: 10,
        )
        arguments.update(options)
        return graphical_reconcile(**arguments)

    def test_candidate_is_pure_and_confirmed_flow_writes_once_without_provider_action(
        self,
    ):
        original = copy.deepcopy(self.record)
        candidate = reconciliation_snapshot(
            self.record,
            inspect_target=lambda: TARGET,
            alive=lambda child: False,
            clock=lambda: LATER,
        )
        self.assertEqual(self.record, original)
        self.assertEqual(candidate["state"], "reconciled")
        with ManualJournal(self.path) as journal:
            journal.write(self.record)
            original_write = journal.write
            journal.write = Mock(wraps=original_write)
            result = self.run_flow(journal)
            journal.write.assert_called_once()
            self.assertEqual(result, journal.read())
            self.assertEqual(result["observation"], "original_process_observed")
            self.assertEqual(
                [e["kind"] for e in self.events], ["preview", "reconcile-result"]
            )
            with self.assertRaisesRegex(ValueError, "no_unresolved_operation"):
                self.run_flow(journal)

    def test_running_or_recent_unidentified_command_refuses_before_confirmation(self):
        for variation in ("running", "unidentified"):
            with self.subTest(variation=variation), ManualJournal(self.path) as journal:
                record = copy.deepcopy(self.record)
                if variation == "unidentified":
                    record.pop("child")
                journal.write(record)
                with self.assertRaisesRegex(ValueError, "restart_.*running"):
                    self.run_flow(
                        journal,
                        alive=lambda child: variation == "running",
                        clock=lambda: NOW,
                    )
                self.assertEqual(journal.read(), record)
                self.assertEqual(self.events, [])

    def test_cancel_forged_extra_expired_and_wrong_owner_never_write(self):
        for variation in ("cancel", "request", "digest", "extra", "expired", "owner"):
            with self.subTest(variation=variation), ManualJournal(self.path) as journal:
                self.events.clear()
                journal.write(self.record)

                def reply():
                    request = self.events[0]
                    value = dict(
                        request_id=request["request_id"],
                        preview_digest=request["preview_digest"],
                        approved=True,
                    )
                    if variation == "cancel":
                        value["approved"] = False
                    if variation == "request":
                        value["request_id"] = "b" * 32
                    if variation == "digest":
                        value["preview_digest"] = "b" * 64
                    if variation == "extra":
                        value["command"] = "restart"
                    return value

                with self.assertRaisesRegex(ValueError, "confirmation_unavailable"):
                    self.run_flow(
                        journal,
                        receive=reply,
                        wall_clock=Mock(side_effect=[100, 191])
                        if variation == "expired"
                        else lambda: 100,
                        owner=Mock(side_effect=[True, False])
                        if variation == "owner"
                        else lambda: True,
                    )
                self.assertEqual(journal.read(), self.record)

    def test_changed_journal_observation_or_child_cannot_be_confirmed(self):
        for variation in ("journal", "observation", "child", "owner"):
            with self.subTest(variation=variation), ManualJournal(self.path) as journal:
                self.events.clear()
                journal.write(self.record)

                def reply():
                    if variation == "journal":
                        changed = dict(self.record, operation_id="b" * 32)
                        journal.write(changed)
                    request = self.events[0]
                    return dict(
                        request_id=request["request_id"],
                        preview_digest=request["preview_digest"],
                        approved=True,
                    )

                with self.assertRaises(ValueError):
                    self.run_flow(
                        journal,
                        receive=reply,
                        inspect_target=Mock(side_effect=[TARGET, REPLACEMENT])
                        if variation == "observation"
                        else lambda: TARGET,
                        alive=Mock(side_effect=[False, True])
                        if variation == "child"
                        else lambda child: False,
                        owner=Mock(side_effect=[True, True, False])
                        if variation == "owner"
                        else lambda: True,
                    )
                self.assertEqual(journal.read()["state"], "unknown")

    def test_pipe_failure_before_consent_changes_nothing_after_commit_never_repeats(
        self,
    ):
        with ManualJournal(self.path) as journal:
            journal.write(self.record)
            with self.assertRaises(BrokenPipeError):
                self.run_flow(journal, send=Mock(side_effect=BrokenPipeError))
            self.assertEqual(journal.read(), self.record)

            def send(event):
                if event["kind"] == "reconcile-result":
                    raise BrokenPipeError
                self.events.append(event)

            result = self.run_flow(journal, send=send)
            self.assertEqual(result["state"], "reconciled")
            with self.assertRaisesRegex(ValueError, "no_unresolved_operation"):
                self.run_flow(journal)

    def test_unknown_write_outcome_is_not_automatically_retried_or_rolled_back(self):
        with ManualJournal(self.path) as journal:
            journal.write(self.record)
            original_write = journal.write

            def uncertain(record):
                original_write(record)
                raise OSError("synthetic fsync uncertainty")

            journal.write = Mock(side_effect=uncertain)
            with self.assertRaises(OSError):
                self.run_flow(journal)
            journal.write.assert_called_once()
            self.assertEqual(journal.read()["state"], "reconciled")
            self.assertEqual(len(self.events), 1)

    def test_shared_lock_and_target_owner_fail_closed(self):
        with ManualJournal(self.path) as journal:
            with self.assertRaises(BlockingIOError):
                ManualJournal(self.path)
            record = copy.deepcopy(self.record)
            record["target"]["process"]["owner_uid"] = os.getuid() + 1
            journal.write(record)
            with self.assertRaisesRegex(ValueError, "inactive_owner"):
                self.run_flow(journal)
            self.assertEqual(journal.read(), record)
            self.assertEqual(self.events, [])

    def test_unobservable_is_unknown_and_absent_journal_creates_no_operation(self):
        with ManualJournal(self.path) as journal:
            with self.assertRaisesRegex(ValueError, "no_unresolved_operation"):
                self.run_flow(journal)
            self.assertIsNone(journal.read())
            journal.write(self.record)
            result = self.run_flow(
                journal, inspect_target=Mock(side_effect=ValueError("fixture"))
            )
            self.assertEqual(result["observation"], "provider_unobservable")
            self.assertNotIn("current", result)
