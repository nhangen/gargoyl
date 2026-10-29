import copy
import unittest

from gargoyl.collector import SOURCES, RetrySchedule, boundary_payload, collect, heartbeat_incident
from gargoyl.telemetry import PolicyError, decode_snapshot

IDENTITY = "00000000-0000-4000-8000-000000000001"
NOW = "2026-01-01T00:00:00Z"


def observation(value="running", source="daemon", time=NOW):
    return dict(value=value, source=source, timestamp=time,
                freshness_seconds=60, state="observed", sensitivity="safe")


class CollectorTests(unittest.TestCase):
    def test_normalized_sources_and_missing_evidence(self):
        values = ["running", "passed", "running", "resident", "normal", "normal",
                  1024, "valid", 10, "reachable"]
        readings = {name: observation(value, source) for (name, source), value in zip(SOURCES.items(), values)}
        snapshot = collect(IDENTITY, NOW, readings)
        self.assertEqual(len(snapshot["fields"]), 13)
        self.assertEqual(snapshot["fields"]["memory_headroom_bytes"]["value"], 1024)
        self.assertEqual(snapshot["fields"]["clock_skew_seconds"]["state"], "unknown")
        readings["daemon_state"]["value"] = "stopped"
        self.assertEqual(snapshot["fields"]["daemon_state"]["value"], "running")
        missing = collect(IDENTITY, NOW, {})
        for name in SOURCES:
            self.assertIsNone(missing["fields"][name]["value"])
            self.assertEqual(missing["fields"][name]["state"], "unknown")

    def test_prohibited_input_rejected_without_echo(self):
        for key in ("prompt", "completion", "credentials", "api_key", "raw_logs", "customer_id", "ip_address"):
            for readings in ({key: "synthetic-marker"}, {"daemon_state": dict(observation(), **{key: "synthetic-marker"})}):
                with self.assertRaises(PolicyError) as error:
                    collect(IDENTITY, NOW, readings)
                self.assertNotIn("synthetic-marker", str(error.exception))
        for value in ("synthetic-marker", {"prompt": "synthetic-marker"}):
            with self.assertRaises(PolicyError):
                collect(IDENTITY, NOW, {"daemon_state": observation(value)})

    def test_wrong_source_and_future_observation_rejected(self):
        for field in (observation(source="host"), observation(time="2026-01-01T00:00:01Z")):
            with self.assertRaises(PolicyError):
                collect(IDENTITY, NOW, {"daemon_state": field})

    def test_age_and_signed_clock_skew(self):
        snapshot = collect(IDENTITY, "2026-01-01T00:01:01Z", {"daemon_state": observation()}, reference_time="2026-01-01T00:01:03Z")
        self.assertEqual(snapshot["fields"]["daemon_state"]["state"], "stale")
        self.assertEqual(snapshot["fields"]["daemon_state"]["timestamp"], NOW)
        self.assertEqual(snapshot["fields"]["clock_skew_seconds"]["value"], -2)

    def test_bounded_error_summary(self):
        snapshot = collect(IDENTITY, NOW, {}, errors=["timeout", "unavailable"])
        self.assertEqual(snapshot["fields"]["error_code"]["value"], "unavailable")
        for errors in (["timeout"] * 33, ["synthetic-marker"], [dict(raw="synthetic-marker")], iter(["timeout"])):
            with self.assertRaises(PolicyError): collect(IDENTITY, NOW, {}, errors=errors)

    def test_revalidate_each_boundary_and_identity(self):
        snapshot = collect(IDENTITY, NOW, {})
        self.assertEqual(decode_snapshot(boundary_payload(snapshot, IDENTITY)), snapshot)
        with self.assertRaises(PolicyError):
            boundary_payload(snapshot, "00000000-0000-4000-8000-000000000002")
        for level in ("root", "fields", "observation"):
            data = copy.deepcopy(snapshot)
            target = data if level == "root" else data["fields"] if level == "fields" else data["fields"]["daemon_state"]
            target["raw_logs"] = "synthetic-marker"
            with self.assertRaises(PolicyError): boundary_payload(data, IDENTITY)

    def test_heartbeat_incidents(self):
        snapshot = collect(IDENTITY, NOW, {})
        self.assertFalse(heartbeat_incident(snapshot, "2026-01-01T00:01:00Z"))
        self.assertTrue(heartbeat_incident(snapshot, "2026-01-01T00:01:01Z"))
        self.assertTrue(heartbeat_incident(snapshot, "2025-12-31T23:59:59Z"))
        self.assertTrue(heartbeat_incident(None, NOW))
        snapshot["fields"]["heartbeat_age_seconds"]["value"] = 61
        self.assertTrue(heartbeat_incident(snapshot, NOW))
        del snapshot["fields"]["heartbeat_age_seconds"]
        self.assertTrue(heartbeat_incident(snapshot, NOW))

    def test_invalid_ttl(self):
        for ttl in (0, True, 86401):
            with self.assertRaises(PolicyError): collect(IDENTITY, NOW, {}, ttl=ttl)


class RetryTests(unittest.TestCase):
    def test_capped_backoff_and_success_reset(self):
        retry = RetrySchedule(1, 4)
        now = 0
        for delay in (1, 2, 4, 4, 4):
            self.assertTrue(retry.ready(now))
            due = retry.failed(now)
            self.assertEqual(due, now + delay)
            self.assertFalse(retry.ready(due - .5))
            now = due
        retry.succeeded(now)
        self.assertEqual(retry.failed(now), now + 1)

    def test_retry_does_not_gate_collection(self):
        retry = RetrySchedule()
        retry.failed(0)
        self.assertFalse(retry.ready(.5))
        self.assertFalse(heartbeat_incident(collect(IDENTITY, NOW, {}), NOW))

    def test_invalid_bounds_and_clock(self):
        for bounds in ((0, 1), (2, 1), (True, 1), (1, float("inf"))):
            with self.assertRaises(ValueError): RetrySchedule(*bounds)
        for now in (-1, True, float("nan"), float("inf")):
            with self.assertRaises(ValueError): RetrySchedule().failed(now)
        retry = RetrySchedule()
        retry.ready(10)
        with self.assertRaises(ValueError): retry.ready(9)
