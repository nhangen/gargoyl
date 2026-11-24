import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from gargoyl.fleet_account import FleetError
from gargoyl.fleet_state import (
    FleetCache,
    evidence_state,
    normalize_inventory,
    validate_inventory,
)

NOW = "2026-11-01T00:00:00Z"


def response():
    return {
        "providers": [
            {
                "id": "provider-real-format-test-only",
                "name": "Fixture Mac",
                "status": "running",
                "last_heartbeat": NOW,
                "version": "0.10.6",
                "se_public_key": "fixture-public-key",
                "hardware": {"machine_model": "Mac Studio"},
                "token": "must-never-persist",
                "warm_models": ["private-model"],
                "earnings": "private-financial-value",
            }
        ],
        "total_count": 1,
    }


class FleetStateTests(unittest.TestCase):
    def test_only_allowlisted_metadata_persisted_and_actual_id_preserved(self):
        value = normalize_inventory(response(), NOW)
        self.assertEqual(value["providers"][0]["id"], "provider-real-format-test-only")
        self.assertEqual(value["providers"][0]["name_kind"], "source_name")
        encoded = json.dumps(value)
        for private in [
            "must-never-persist",
            "fixture-public-key",
            "private-model",
            "private-financial-value",
        ]:
            self.assertNotIn(private, encoded)
        self.assertEqual(validate_inventory(value), value)

    def test_names_are_not_invented_and_hardware_is_labelled_separately(self):
        raw = response()
        del raw["providers"][0]["name"]
        value = normalize_inventory(raw, NOW)
        self.assertEqual(value["providers"][0]["name_kind"], "hardware_label")
        del raw["providers"][0]["hardware"]
        value = normalize_inventory(raw, NOW)
        self.assertEqual(value["providers"][0]["name"], raw["providers"][0]["id"])
        self.assertEqual(value["providers"][0]["name_kind"], "provider_id")

    def test_duplicate_identity_rejected_and_missing_records_are_partial(self):
        raw = response()
        raw["providers"].append(copy.deepcopy(raw["providers"][0]))
        with self.assertRaises(FleetError):
            normalize_inventory(raw, NOW)
        raw = response()
        raw["providers"].append({"name": "no identity"})
        value = normalize_inventory(raw, NOW)
        self.assertTrue(value["partial"])
        self.assertEqual(value["rejected_records"], 1)
        raw = response()
        raw["next_cursor"] = "not-followed-as-a-url"
        self.assertTrue(normalize_inventory(raw, NOW)["partial"])

    def test_fetch_and_heartbeat_freshness_are_separate_not_health_verdicts(self):
        value = normalize_inventory(response(), NOW)
        row = value["providers"][0]
        self.assertEqual(evidence_state(value, row, NOW), ("current", "recent"))
        self.assertEqual(
            evidence_state(value, row, "2026-11-01T00:05:00Z"), ("stale", "older")
        )
        self.assertEqual(
            evidence_state(value, row, "2026-10-31T23:59:00Z"), ("unknown", "unknown")
        )
        value["connection"] = "auth_required"
        self.assertEqual(evidence_state(value, row, NOW), ("stale", "recent"))
        row["heartbeat_at"] = None
        self.assertEqual(evidence_state(value, row, NOW), ("stale", "unknown"))
        value["connection"] = "connected"
        row["heartbeat_at"] = NOW
        self.assertEqual(
            evidence_state(value, row, NOW, lifecycle={"status": "running"}),
            ("current", "recent"),
        )
        for stopped_status in ("exited", "stopped", "terminal_failure"):
            self.assertEqual(
                evidence_state(value, row, NOW, lifecycle={"status": stopped_status}),
                ("stale", "recent"),
            )

    def test_fractional_api_timestamps_and_offsets_normalize_without_relaxing_v1(self):
        from gargoyl.fleet_state import heartbeat
        from gargoyl.telemetry import timestamp

        for digits in range(1, 10):
            raw = {"last_heartbeat": "2026-11-01T01:00:00." + "1" * digits + "+01:00"}
            at, reason, source, precision = heartbeat(raw)
            self.assertEqual(
                (reason, source, precision), ("reported", "last_heartbeat", digits)
            )
            self.assertTrue(at.startswith("2026-11-01T00:00:00."))
            timestamp(at)
        with self.assertRaises(ValueError):
            timestamp("2026-11-01T00:00:00.123456789Z")

    def test_missing_invalid_and_numeric_units_are_distinguished_not_invented(self):
        from gargoyl.fleet_state import heartbeat

        cases = [
            ({}, "not_reported"),
            ({"last_seen": 1234567890}, "unsupported_type"),
            ({"last_heartbeat": True}, "unsupported_type"),
            ({"last_seen": "2026-02-30T00:00:00Z"}, "invalid_timestamp"),
            ({"last_seen": "private arbitrary payload"}, "invalid_timestamp"),
        ]
        for raw, reason in cases:
            result = heartbeat(raw)
            self.assertIsNone(result[0])
            self.assertEqual(result[1], reason)
        raw = response()
        raw["providers"][0]["last_heartbeat"] = "2026-11-01T01:00:00.123456789Z"
        value = normalize_inventory(raw, NOW)
        row = value["providers"][0]
        self.assertEqual(row["heartbeat_precision"], 9)
        self.assertEqual(evidence_state(value, row, NOW)[1], "unknown")
        self.assertEqual(validate_inventory(value), value)

    def test_legacy_cached_inventory_remains_readable_until_refreshed(self):
        value = normalize_inventory(response(), NOW)
        value["schema"] = 1
        for row in value["providers"]:
            for key in ["heartbeat_reason", "heartbeat_source", "heartbeat_precision"]:
                row.pop(key)
        self.assertEqual(validate_inventory(value), value)

    def test_cache_ownership_symlink_and_retention_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            cache = FleetCache(root / "cache", os.getuid())
            self.assertIsNone(cache.read(NOW))
            cache.write(normalize_inventory(response(), NOW))
            self.assertEqual((root / "cache").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "cache/fleet.json").stat().st_mode & 0o777, 0o600)
            self.assertIsNotNone(cache.read(NOW))
            self.assertIsNone(cache.read("2026-11-03T00:00:00Z"))
            self.assertFalse((root / "cache/fleet.json").exists())
            (root / "cache/fleet.json").symlink_to(root / "outside")
            with self.assertRaises((FleetError, OSError)):
                cache.write(normalize_inventory(response(), NOW))
            self.assertFalse((root / "outside").exists())
            (root / "linked").symlink_to(root / "cache", target_is_directory=True)
            with self.assertRaises((FleetError, OSError)):
                FleetCache(root / "linked", os.getuid()).write(
                    normalize_inventory(response(), NOW)
                )

    def test_unknown_schema_and_excessive_inventory_refused(self):
        with self.assertRaises(FleetError):
            normalize_inventory({"providers": [{}] * 257}, NOW)
        value = normalize_inventory(response(), NOW)
        value["token"] = "not-allowed"
        with self.assertRaises(FleetError):
            validate_inventory(value)
        value = normalize_inventory(response(), NOW)
        value["providers"][0]["private_payload"] = "not-allowed"
        with self.assertRaises(FleetError):
            validate_inventory(value)
