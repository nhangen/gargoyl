import copy
import unittest
from gargoyl.telemetry import PolicyError, validate_snapshot, encode_snapshot, decode_snapshot, effective_state


def snapshot():
    return {"schema_version": 1, "host_id": "00000000-0000-4000-8000-000000000001", "collected_at": "2026-01-01T00:00:00Z", "fields": {"daemon_state": {"value": "running", "source": "daemon", "timestamp": "2026-01-01T00:00:00Z", "freshness_seconds": 60, "state": "observed", "sensitivity": "safe"}}}

class ContractTests(unittest.TestCase):
    def test_roundtrip_and_detached(self):
        original = snapshot()
        self.assertEqual(decode_snapshot(encode_snapshot(original)), original)
        copied = validate_snapshot(original)
        copied["fields"].clear()
        self.assertTrue(original["fields"])

    def test_prohibited_fields_rejected_without_echo(self):
        for key in ("prompt", "completion", "credentials", "api_key", "raw_logs", "customer_id", "ip_address"):
            for level in ("root", "fields", "observation"):
                data = snapshot()
                target = data if level == "root" else data["fields"] if level == "fields" else data["fields"]["daemon_state"]
                target[key] = "synthetic-secret-marker"
                with self.assertRaises(PolicyError) as caught:
                    encode_snapshot(data)
                self.assertNotIn("synthetic-secret-marker", str(caught.exception))

    def test_arbitrary_values_and_missing_metadata(self):
        for key, value in (("value", "synthetic-secret-marker"), ("source", "free text"), ("sensitivity", "sensitive"), ("freshness_seconds", True), ("timestamp", "2026-01-01")):
            data = snapshot(); data["fields"]["daemon_state"][key] = value
            with self.assertRaises(PolicyError): validate_snapshot(data)
        for key in snapshot()["fields"]["daemon_state"]:
            data = snapshot(); del data["fields"]["daemon_state"][key]
            with self.assertRaises(PolicyError): validate_snapshot(data)

    def test_freshness(self):
        field = snapshot()["fields"]["daemon_state"]
        self.assertEqual(effective_state(field, "2026-01-01T00:01:01Z"), "stale")
        self.assertEqual(effective_state(field, "2025-12-31T23:59:59Z"), "unknown")

    def test_duplicate_keys_and_size(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b' ' * 65537):
            with self.assertRaises(PolicyError): decode_snapshot(raw)
