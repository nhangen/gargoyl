import hashlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from test_telemetry import snapshot

from gargoyl.ingestion import (
    EvidenceReadError,
    EvidenceStore,
    EvidenceWriteError,
    IngestionService,
    Principal,
)
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError, encode_snapshot

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-01T00:00:10Z"
OTHER_HOST = "00000000-0000-4000-8000-000000000002"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "evidence"
        self.identity = CollectionIdentity(snapshot()["host_id"])
        self.ciphers = {self.identity.host_id: SpoolCipher(self.identity, b"x" * 32)}
        self.policy = RetentionPolicy(max_age_seconds=60, max_records=2)

    def store(self, now=NOW, ciphers=None):
        store = EvidenceStore(self.directory, ciphers or self.ciphers, self.policy, now)
        self.addCleanup(store.close)
        return store

    def mutate(self, sql, parameters=()):
        with sqlite3.connect(self.directory / "evidence.sqlite3") as db:
            db.execute(sql, parameters)

    def test_restart_dedup_and_ciphertext_only_payload(self):
        store = self.store()
        self.assertTrue(store.accept(snapshot(), now=NOW))
        self.assertTrue(store.accept(snapshot(), now=NOW))
        self.assertEqual(store.snapshots(now=NOW), [snapshot()])
        store.close()
        for path in self.directory.iterdir():
            raw = path.read_bytes()
            for marker in (b'"daemon_state"', b'"schema_version"', b'"running"'):
                self.assertNotIn(marker, raw)
        restored = self.store()
        self.assertEqual(restored.snapshots(now=NOW), [snapshot()])
        detached = restored.snapshots(now=NOW)
        detached[0]["fields"].clear()
        self.assertEqual(restored.snapshots(now=NOW), [snapshot()])

    def test_conflicts_survive_and_future_is_not_deleted(self):
        store = self.store()
        first = snapshot()
        first["collected_at"] = LATER
        second = snapshot()
        second["collected_at"] = LATER
        second["fields"]["daemon_state"]["value"] = "stopped"
        store.accept(first, now=LATER)
        store.accept(second, now=LATER)
        self.assertEqual(store.snapshots(now=NOW), [first, second])
        store.close()
        self.assertEqual(self.store().snapshots(now=NOW), [first, second])

    def test_per_host_count_and_age_retention(self):
        other_identity = CollectionIdentity(OTHER_HOST)
        self.ciphers[OTHER_HOST] = SpoolCipher(other_identity, b"y" * 32)
        store = self.store()
        other = snapshot()
        other["host_id"] = OTHER_HOST
        store.accept(other, now=NOW)
        for value in (NOW, LATER, "2026-01-01T00:00:20Z"):
            data = snapshot()
            data["collected_at"] = value
            store.accept(data, now=value)
        rows = store.snapshots(now="2026-01-01T00:00:20Z")
        self.assertEqual(len(rows), 3)
        self.assertIn(other, rows)
        self.assertEqual(store.snapshots(now="2026-01-01T00:02:00Z"), [])

    def test_expired_or_capacity_excluded_input_cannot_acknowledge(self):
        store = self.store()
        with self.assertRaises(PolicyError):
            store.accept(snapshot(), now="2026-01-01T00:02:00Z")
        for value in (LATER, "2026-01-01T00:00:20Z"):
            data = snapshot()
            data["collected_at"] = value
            store.accept(data, now=NOW)
        before = store.snapshots(now=NOW)
        with self.assertRaises(EvidenceWriteError):
            store.accept(snapshot(), now=NOW)
        self.assertEqual(store.snapshots(now=NOW), before)

    def test_corruption_and_wrong_keys_fail_closed_even_when_expired(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)
        store.close()
        with self.assertRaises(EvidenceReadError):
            self.store(
                ciphers={self.identity.host_id: SpoolCipher(self.identity, b"y" * 32)}
            )
        store = self.store()
        self.mutate("UPDATE evidence SET payload = ?", (b"GSP1" + b"x" * 40,))
        with self.assertRaises(EvidenceReadError) as caught:
            store.snapshots(now="2026-01-01T00:02:00Z")
        self.assertEqual(str(caught.exception), "evidence unavailable")
        with self.assertRaises(EvidenceWriteError):
            store.accept(snapshot(), now=NOW)

    def test_metadata_tampering_and_storage_failure_are_not_empty_views(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)
        self.mutate("UPDATE evidence SET digest = ?", ("synthetic-marker",))
        with self.assertRaises(EvidenceReadError) as caught:
            store.snapshots(now=NOW)
        self.assertNotIn("synthetic-marker", str(caught.exception))
        store.close()
        with self.assertRaises(EvidenceReadError):
            store.snapshots(now=NOW)

    def test_failed_transaction_preserves_previous_snapshot(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)
        self.mutate(
            "CREATE TRIGGER fail_write BEFORE INSERT ON evidence BEGIN SELECT RAISE(ABORT, 'synthetic-marker'); END"
        )
        data = snapshot()
        data["collected_at"] = LATER
        with self.assertRaises(EvidenceWriteError) as caught:
            store.accept(data, now=LATER)
        self.assertNotIn("synthetic-marker", str(caught.exception))
        self.assertEqual(store.snapshots(now=LATER), [snapshot()])

    def test_privacy_validation_before_persistence(self):
        store = self.store()
        data = snapshot()
        data["raw_logs"] = "synthetic-marker"
        with self.assertRaises(PolicyError):
            store.accept(data, now=NOW)
        self.assertEqual(store.snapshots(now=NOW), [])
        self.assertNotIn(
            b"synthetic-marker", (self.directory / "evidence.sqlite3").read_bytes()
        )

    def test_concurrent_duplicate_writes_and_reads_are_consistent(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)

        def mixed_operation(index):
            if index % 2:
                return store.accept(snapshot(), now=NOW)
            return store.snapshots(now=NOW)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(mixed_operation, range(40)))
        for index, result in enumerate(results):
            self.assertEqual(result, True if index % 2 else [snapshot()])

    def test_oversized_corruption_returns_no_partial_view(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)
        data = snapshot()
        data["collected_at"] = LATER
        store.accept(data, now=LATER)
        self.mutate("UPDATE evidence SET payload = ? WHERE id = 2", (b"x" * 65569,))
        with self.assertRaises(EvidenceReadError):
            store.snapshots(now=LATER)

    def test_failed_retention_transaction_does_not_delete_history(self):
        store = self.store()
        store.accept(snapshot(), now=NOW)
        self.mutate(
            "CREATE TRIGGER fail_delete BEFORE DELETE ON evidence BEGIN SELECT RAISE(ABORT, 'synthetic-marker'); END"
        )
        with self.assertRaises(EvidenceReadError):
            store.snapshots(now="2026-01-01T00:02:00Z")
        self.assertEqual(store.snapshots(now=NOW), [snapshot()])

    def test_private_directory_and_inventory_bounds(self):
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        with self.assertRaises(EvidenceReadError):
            self.store()
        with self.assertRaises(ValueError):
            EvidenceStore(self.directory, {}, self.policy, NOW)
        self.directory.chmod(0o700)
        (self.directory / "evidence.sqlite3").symlink_to(self.directory / "elsewhere")
        with self.assertRaises(EvidenceReadError):
            self.store()


class AuthorizationTests(unittest.TestCase):
    def test_peer_host_and_source_grants_precede_storage(self):
        class Store:
            called = False

            def accept(self, snapshot, *, now):
                self.called = True
                return True

        store = Store()
        cert = b"synthetic-unit-test-peer"
        principal = Principal(
            frozenset({snapshot()["host_id"]}), frozenset({("daemon_state", "daemon")})
        )
        service = IngestionService(store, {hashlib.sha256(cert).hexdigest(): principal})
        self.assertTrue(service.accept(encode_snapshot(snapshot()), cert, now=NOW))
        for kind in ("peer", "host", "source", "metric"):
            data = snapshot()
            peer = cert
            if kind == "peer":
                peer = b"unregistered-synthetic-peer"
            elif kind == "host":
                data["host_id"] = OTHER_HOST
            elif kind == "source":
                data["fields"]["daemon_state"]["source"] = "coordinator"
            else:
                data["fields"]["model_state"] = data["fields"].pop("daemon_state")
                data["fields"]["model_state"]["value"] = "resident"
            store.called = False
            with self.assertRaises(PermissionError):
                service.accept(encode_snapshot(data), peer, now=NOW)
            self.assertFalse(store.called)
