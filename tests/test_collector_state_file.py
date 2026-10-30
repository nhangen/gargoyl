"""Only temporary synthetic JSON files; never reads an installed producer's state."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gargoyl.collector import collect
from gargoyl.collector_state_file import read_daemon_state
from gargoyl.ingestion import EvidenceStore
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher
from gargoyl.telemetry import PolicyError

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-01-01T00:02:00Z"
EPOCH = 1767225600
HOST = "00000000-0000-4000-8000-000000000001"


def fixture():
    return dict(schema=1, pid=12345, version="synthetic-1", written_at=EPOCH,
                started_at=EPOCH-100, inference_active=False, warm_models=["synthetic-private-model"],
                stats=dict(requests_served=3, tokens_generated=17, usage_gaps=0),
                attestation_public_key="synthetic-private-key", coordinator_url="synthetic-private-url",
                process_identity=dict(pid=12345, start_time=EPOCH-100),
                extra=dict(raw="synthetic-private-extra"))


class StateFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "state.json"
        self.write(fixture())

    def write(self, data):
        self.path.write_text(json.dumps(data))
        self.path.chmod(0o600)

    def read(self, **kwargs):
        return read_daemon_state(str(self.path), expected_owner_uid=os.getuid(),
                                 now=kwargs.pop("now", NOW), **kwargs)

    def test_normalized_allowlist_and_no_identity_health_leak(self):
        result = self.read()
        self.assertEqual(result.observed_at, NOW)
        self.assertEqual(result.result.errors, ())
        self.assertEqual(set(result.result.readings), {"requests_total", "tokens_total", "model_state"})
        snapshot = collect(HOST, NOW, result.result.readings)
        self.assertEqual(snapshot["fields"]["requests_total"]["value"], 3)
        self.assertEqual(snapshot["fields"]["tokens_total"]["value"], 17)
        self.assertIsNone(snapshot["fields"]["daemon_state"]["value"])
        self.assertIsNone(snapshot["fields"]["attestation_state"]["value"])
        self.assertNotIn("synthetic-private", repr(result))
        self.assertNotIn("12345", repr(result))

    def test_empty_selected_values_preserve_valid_envelope_time(self):
        data = fixture()
        data.update(warm_models=[], stats={})
        self.write(data)
        result = self.read()
        self.assertEqual(result.observed_at, NOW)
        self.assertEqual(result.result.readings, {})
        self.assertEqual(result.result.errors, ())
        data["current_model"] = "synthetic-private-current"
        self.write(data)
        self.assertEqual(self.read().result.readings["model_state"]["value"], "resident")

    def test_repeated_reads_preserve_timestamp_and_staleness(self):
        first, later = self.read(), self.read(now=LATER)
        self.assertEqual(first.observed_at, later.observed_at)
        for field in later.result.readings.values():
            self.assertEqual((field["timestamp"], field["state"]), (NOW, "stale"))
        self.assertEqual(self.read(now=LATER, ttl=180).result.readings["model_state"]["state"], "observed")

    def test_invalid_envelopes_and_future_times_fail_closed(self):
        for field, value in (("schema", True), ("schema", 2), ("pid", False), ("pid", 0),
                             ("written_at", EPOCH+1), ("written_at", float("inf")),
                             ("written_at", True), ("started_at", EPOCH+1),
                             ("started_at", -1), ("inference_active", 1),
                             ("warm_models", "private"), ("stats", None), ("version", 1)):
            with self.subTest(field=field, value=value):
                data = fixture()
                data[field] = value
                self.write(data)
                result = self.read()
                self.assertIsNone(result.observed_at)
                self.assertEqual(result.result.errors, ("invalid_state",))

    def test_counter_bounds_null_and_missing_never_coerce_or_clamp(self):
        for value in (True, -1, 2**53, 1.0, "17", 10**100):
            data = fixture()
            data["stats"]["tokens_generated"] = value
            self.write(data)
            self.assertEqual(self.read().result.errors, ("invalid_state",))
        data["stats"] = dict(requests_served=2**53-1, tokens_generated=None)
        self.write(data)
        result = self.read().result
        self.assertEqual(result.readings["requests_total"]["value"], 2**53-1)
        self.assertNotIn("tokens_total", result.readings)

    def test_duplicate_nonfinite_nested_invalid_utf8_and_oversize(self):
        encoded = json.dumps(fixture()).encode()
        for raw in (encoded[:-1]+b',"schema":1}', b'\xff', b'{', b' ' * 65537,
                    encoded[:-1]+b',"extra_number":1e999}',
                    encoded[:-1]+b',"deep":'+b'['*20+b'0'+b']'*20+b'}',
                    encoded[:-1]+b',"bad":"\\ud800"}'):
            self.path.write_bytes(raw)
            self.assertEqual(self.read().result.errors, ("invalid_state",))
        self.path.write_bytes(encoded + b' ' * (65536-len(encoded)))
        self.assertEqual(self.read().result.errors, ())
        self.assertEqual(self.read(max_bytes=100).result.errors, ("invalid_state",))

    def test_missing_unreadable_and_unsafe_permissions(self):
        self.path.unlink()
        self.assertEqual(self.read().result.errors, ("unavailable",))
        self.write(fixture())
        self.path.chmod(0)
        self.assertEqual(self.read().result.errors, ("permission_denied",))
        self.path.chmod(0o622)
        self.assertEqual(self.read().result.errors, ("permission_denied",))
        self.path.chmod(0o644)  # Safe because containing directory is private.
        self.assertEqual(self.read().result.errors, ())
        self.root.chmod(0o755)
        self.assertEqual(self.read().result.errors, ("permission_denied",))
        self.root.chmod(0o700)

    def test_wrong_owner_symlink_fifo_and_hardlink_rejected(self):
        result = read_daemon_state(str(self.path), expected_owner_uid=os.getuid()+1, now=NOW)
        self.assertEqual(result.result.errors, ("permission_denied",))
        target = self.root / "target"
        self.path.rename(target)
        self.path.symlink_to(target)
        self.assertEqual(self.read().result.errors, ("unavailable",))
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.assertEqual(self.read().result.errors, ("invalid_state",))
        self.path.unlink()
        os.link(target, self.path)
        self.assertEqual(self.read().result.errors, ("invalid_state",))

    def test_mutation_during_read_rejected(self):
        original = os.read
        changed = []

        def mutate(fd, count):
            payload = original(fd, count)
            if not changed:
                changed.append(True)
                self.path.write_text("{}")
            return payload

        with patch("gargoyl.collector_state_file.os.read", side_effect=mutate):
            self.assertEqual(self.read().result.errors, ("invalid_state",))

    def test_atomic_replacement_returns_one_complete_generation_or_failure(self):
        original = os.read
        replacement = self.root / "replacement"
        data = fixture()
        data["stats"]["requests_served"] = 99
        replacement.write_text(json.dumps(data))
        replacement.chmod(0o600)
        replaced = []

        def replace(fd, count):
            if not replaced:
                replaced.append(True)
                os.replace(replacement, self.path)
            return original(fd, count)

        with patch("gargoyl.collector_state_file.os.read", side_effect=replace):
            result = self.read()
        if not result.result.errors:
            self.assertEqual(result.result.readings["requests_total"]["value"], 3)
        else:
            self.assertIsNone(result.observed_at)
        self.assertEqual(self.read().result.readings["requests_total"]["value"], 99)

    def test_caller_configuration_rejected_before_open(self):
        for options in (dict(path="relative"), dict(ttl=True), dict(ttl=0), dict(max_bytes=65537),
                        dict(expected_owner_uid=True), dict(path=str(self.root)+"/../state")):
            args = dict(path=str(self.path), expected_owner_uid=os.getuid(), now=NOW)
            args.update(options)
            with patch("gargoyl.collector_state_file.os.open") as opened:
                with self.assertRaises(PolicyError):
                    read_daemon_state(**args)
                opened.assert_not_called()

    def test_encrypted_persistence_restart_never_redates_source(self):
        result = self.read(now=LATER)
        snapshot = collect(HOST, LATER, result.result.readings)
        ciphers = {HOST: SpoolCipher(CollectionIdentity(HOST), os.urandom(32))}
        directory = self.root / "evidence"
        store = EvidenceStore(directory, ciphers, RetentionPolicy(), LATER)
        self.assertTrue(store.accept(snapshot, now=LATER))
        store.close()
        store = EvidenceStore(directory, ciphers, RetentionPolicy(), LATER)
        self.addCleanup(store.close)
        self.assertEqual(store.snapshots(now=LATER), [snapshot])
        self.assertEqual(snapshot["fields"]["requests_total"]["timestamp"], NOW)
        for path in directory.iterdir():
            self.assertNotIn(b"synthetic-private", path.read_bytes())
