import copy
import unittest
from unittest.mock import Mock

from test_collector_adapters import DOCTOR_TEXT

from gargoyl.collector_acquisition import AcquisitionResult
from gargoyl.collector_adapters import AdapterResult, parse_observations
from gargoyl.collector_runtime import CollectorRuntime
from gargoyl.security import CollectionIdentity
from gargoyl.telemetry import PolicyError

STATUS = "darkbloom_status_text_v1"
DOCTOR = "darkbloom_doctor_text_v1"
START = "2026-01-01T00:00:00Z"


def acquired(kind=STATUS, *, observed_at=START, completed_at="2026-01-01T00:00:03Z"):
    text = "Status: ● Running — serving synthetic-secret" if kind == STATUS else DOCTOR_TEXT
    return AcquisitionResult(kind, observed_at, completed_at,
                             parse_observations(kind, text.encode(), observed_at=observed_at), True)


class AcquiredRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.history = Mock()
        self.now = "2026-01-01T00:00:05Z"
        self.runtime = CollectorRuntime(
            CollectionIdentity("00000000-0000-4000-8000-000000000001"),
            self.history, Mock(), wall_clock=lambda: self.now, monotonic_clock=lambda: 0)

    def test_start_timestamp_preserved_and_no_cadence_gate(self):
        self.runtime._next_collection = 999
        snapshot = self.runtime.collect_acquired({STATUS: acquired()})
        self.assertEqual(snapshot["fields"]["daemon_state"]["timestamp"], START)
        self.assertEqual(snapshot["collected_at"], self.now)
        self.assertNotIn("synthetic-secret", repr(self.history.append.call_args))
        self.now = "2026-01-01T00:01:01Z"
        snapshot = self.runtime.collect_acquired({STATUS: acquired()})
        self.assertEqual(snapshot["fields"]["daemon_state"]["state"], "stale")
        self.assertEqual(snapshot["fields"]["daemon_state"]["timestamp"], START)
        self.assertEqual(self.history.append.call_count, 2)

    def test_failed_independent_source_and_missing_sources(self):
        failed = AcquisitionResult(DOCTOR, START, self.now, AdapterResult({}, ("timeout",)), True)
        snapshot = self.runtime.collect_acquired({STATUS: acquired(), DOCTOR: failed})
        self.assertEqual(snapshot["fields"]["daemon_state"]["value"], "running")
        self.assertEqual(snapshot["fields"]["doctor_state"]["state"], "unknown")
        self.assertEqual(snapshot["fields"]["error_code"]["value"], "timeout")
        missing = self.runtime.collect_acquired({})
        self.assertEqual(missing["fields"]["daemon_state"]["state"], "unknown")

    def test_future_start_omitted_without_redating_other_source(self):
        future = acquired(observed_at="2026-01-01T00:00:10Z", completed_at="2026-01-01T00:00:04Z")
        other = acquired(DOCTOR)
        snapshot = self.runtime.collect_acquired({STATUS: future, DOCTOR: other})
        self.assertEqual(snapshot["fields"]["daemon_state"]["state"], "unknown")
        self.assertEqual(snapshot["fields"]["doctor_state"]["timestamp"], START)
        self.assertEqual(snapshot["fields"]["doctor_state"]["value"], "passed")
        self.assertEqual(snapshot["fields"]["error_code"]["value"], "invalid_state")
        self.assertEqual(future.result.readings["daemon_state"]["timestamp"], "2026-01-01T00:00:10Z")

    def test_incomplete_cleanup_never_persists_even_good_other_source(self):
        bad = AcquisitionResult(STATUS, START, self.now, AdapterResult({}, ("timeout",)), False)
        with self.assertRaisesRegex(PolicyError, "cleanup incomplete"):
            self.runtime.collect_acquired({DOCTOR: acquired(DOCTOR), STATUS: bad})
        self.history.append.assert_not_called()

    def test_ownership_metadata_and_privacy_rejected_before_persistence(self):
        base = acquired()
        mutations = []
        for field, value in (("source", "coordinator"), ("timestamp", self.now),
                             ("freshness_seconds", 1), ("freshness_seconds", True),
                             ("value", "synthetic-secret"), ("raw_logs", "synthetic-secret")):
            changed = copy.deepcopy(base.result.readings)
            changed["daemon_state"][field] = value
            mutations.append(AcquisitionResult(STATUS, START, self.now, AdapterResult(changed, ()), True))
        mutations.extend([
            AcquisitionResult(STATUS, START, self.now, AdapterResult(base.result.readings, ("timeout",)), True),
            AcquisitionResult(STATUS, START, self.now, AdapterResult({}, ("synthetic-secret",)), True),
            AcquisitionResult(STATUS, START, self.now, AdapterResult({}, ()), True),
            AcquisitionResult(STATUS, START, self.now, acquired(DOCTOR).result, True),
            AcquisitionResult(STATUS, START, "synthetic-secret", base.result, True),
            AcquisitionResult(STATUS, START, self.now, base.result, 1),
            acquired(DOCTOR),
        ])
        for result in mutations:
            with self.subTest(result_type=type(result)):
                with self.assertRaises(PolicyError) as error:
                    self.runtime.collect_acquired({STATUS: result})
                self.assertNotIn("synthetic-secret", str(error.exception))
        self.history.append.assert_not_called()

    def test_future_evidence_still_validated_and_output_detached(self):
        future = acquired(observed_at="2026-01-01T00:00:10Z")
        future.result.readings["daemon_state"]["raw_logs"] = "synthetic-secret"
        with self.assertRaises(PolicyError):
            self.runtime.collect_acquired({STATUS: future})
        self.history.append.assert_not_called()
        original = acquired()
        result = self.runtime.collect_acquired({STATUS: original})
        result["fields"]["daemon_state"]["value"] = "stopped"
        self.assertEqual(original.result.readings["daemon_state"]["value"], "running")
