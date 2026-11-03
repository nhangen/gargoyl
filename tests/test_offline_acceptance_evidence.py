"""Runs the offline acceptance evidence runner and pins genuinely new runner behavior."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from gargoyl.telemetry import decode_snapshot

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "offline_acceptance_evidence.py"
_SPEC = importlib.util.spec_from_file_location("offline_acceptance_evidence", RUNNER)
RUNNER_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RUNNER_MODULE)
SCENARIO_NAMES = ("missing_offline_host", "stale_snapshot", "clock_skew_reference", "coordinator_disagreement")


def run_runner(out, script=None, env_extra=None):
    environment = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONWARNINGS": "ignore"}
    if env_extra:
        environment.update(env_extra)
    return subprocess.run([sys.executable, str(script or RUNNER), "--out", str(out)],
                          cwd=ROOT, capture_output=True, text=True, timeout=60, env=environment)


class OfflineAcceptanceEvidenceRunnerTests(unittest.TestCase):
    def load(self, tmp):
        path = Path(tmp) / "offline_acceptance_evidence.json"
        self.assertTrue(path.is_file(), path)
        return json.loads(path.read_text(encoding="utf-8"))

    def check(self, scenario, label):
        return next(record for record in scenario["checks"] if record["label"] == label)

    def test_match_run_writes_marked_artifacts_with_fixed_reference_time(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-") as tmp:
            result = run_runner(tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn(RUNNER_MODULE.MARKER, result.stdout)
            for name in SCENARIO_NAMES:
                page = (Path(tmp) / (name + ".html")).read_text(encoding="utf-8")
                self.assertIn(RUNNER_MODULE.MARKER, page)
                self.assertIn(f"<title>{RUNNER_MODULE.MARKER} — Gargoyl fleet evidence</title>", page)
                self.assertIn(f"{RUNNER_MODULE.MARKER} (PASS)", page)
                self.assertIn("<strong>", page)
            evidence = self.load(tmp)
            self.assertEqual(evidence["marker"], RUNNER_MODULE.MARKER)
            self.assertIn("OFFLINE FIXTURE SOFTWARE EVIDENCE", evidence["note"])
            self.assertIn("not live acceptance", evidence["note"].lower())
            self.assertEqual(evidence["reference_time"], RUNNER_MODULE.REFERENCE_TIME)
            self.assertTrue(evidence["all_matched"])
            self.assertEqual(sorted(evidence["scenarios"]), sorted(SCENARIO_NAMES))
            for scenario in evidence["scenarios"].values():
                self.assertTrue(scenario["all_matched"])
                for encoded in scenario["snapshots"]:
                    decode_snapshot(encoded.encode("utf-8"))

    def test_missing_offline_host_pins_unknown_labels_and_incident(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-") as tmp:
            run_runner(tmp)
            scenario = self.load(tmp)["scenarios"]["missing_offline_host"]
            self.assertEqual(scenario["snapshots"], [])
            self.assertEqual(scenario["evaluated_at"], RUNNER_MODULE.REFERENCE_TIME)
            self.assertEqual(self.check(scenario, "incidents")["expected"], ["missing_collector_heartbeat"])
            self.assertEqual(self.check(scenario, "expected_host_has_no_metric_reports")["expected"], True)
            page = (Path(tmp) / "missing_offline_host.html").read_text(encoding="utf-8")
            self.assertIn("unknown · No report", page)
            self.assertIn(RUNNER_MODULE.MISSING_HOST, page)
            self.assertNotIn("<button", page)

    def test_stale_scenario_pins_effective_state_and_preserved_report(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-") as tmp:
            run_runner(tmp)
            scenario = self.load(tmp)["scenarios"]["stale_snapshot"]
            self.assertEqual(self.check(scenario, "observed_reading_becomes_stale_after_ttl")["expected"], "stale")
            self.assertEqual(self.check(scenario, "observed_reported_state_preserved")["actual"], "observed")
            self.assertEqual(self.check(scenario, "observed_value_preserved_when_stale")["actual"], "running")
            self.assertEqual(self.check(scenario, "collector_heartbeat_incident_after_ttl")["actual"],
                             ["collector_heartbeat_not_current"])
            page = (Path(tmp) / "stale_snapshot.html").read_text(encoding="utf-8")
            self.assertIn("<th>daemon_state</th><td>stale (reported: observed)</td><td>running</td>", page)
            self.assertIn("daemon_state: stale daemon report", page)

    def test_clock_skew_scenario_pins_supplied_reference_and_future_unknown(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-") as tmp:
            run_runner(tmp)
            scenario = self.load(tmp)["scenarios"]["clock_skew_reference"]
            skew = self.check(scenario, "skew_measured_against_supplied_reference")
            self.assertEqual(skew["expected"], 300)
            self.assertEqual(skew["actual"], skew["expected"])
            self.assertEqual(self.check(scenario, "future_collected_override_makes_fresh_report_unknown")["actual"], "unknown")
            self.assertEqual(self.check(scenario, "reported_state_preserved_under_future_override")["actual"], "observed")
            self.assertEqual(self.check(scenario, "future_collected_reports_all_unknown")["actual"], True)
            self.assertEqual(scenario["evaluated_at"], RUNNER_MODULE.REFERENCE_TIME)
            snapshot = decode_snapshot(scenario["snapshots"][0].encode("utf-8"))
            self.assertEqual(snapshot["fields"]["clock_skew_seconds"]["value"], 300)
            self.assertEqual(snapshot["collected_at"], RUNNER_MODULE.LATER_EVALUATION)
            page = (Path(tmp) / "clock_skew_reference.html").read_text(encoding="utf-8")
            self.assertIn("<th>daemon_state</th><td>unknown (reported: observed)</td><td>running</td>", page)
            self.assertIn("<th>clock_skew_seconds</th><td>unknown (reported: observed)</td><td>300</td>", page)

    def test_disagreement_scenario_pins_conflict_preservation_and_rendering(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-") as tmp:
            run_runner(tmp)
            scenario = self.load(tmp)["scenarios"]["coordinator_disagreement"]
            self.assertEqual(self.check(scenario, "conflicting_originals_preserved")["actual"],
                             ["eligible", "ineligible"])
            self.assertEqual(self.check(scenario, "same_source_conflict_stays_unknown")["actual"], "unknown")
            self.assertEqual(self.check(scenario, "coordinator_report_unresolved")["actual"], "unknown")
            self.assertEqual(self.check(scenario, "local_coordinator_report_mismatch")["actual"], "mismatch")
            self.assertEqual(self.check(scenario, "mismatch_incident_recorded")["actual"],
                             ["daemon_state_mismatch"])
            page = (Path(tmp) / "coordinator_disagreement.html").read_text(encoding="utf-8")
            self.assertIn("routing_eligible: unknown — conflicting observations", page)
            self.assertIn("daemon_state: adverse reported value stopped", page)

    def test_deviation_from_hand_computed_labels_exits_nonzero(self):
        source = RUNNER.read_text(encoding="utf-8")
        # Preserve checkout import precedence in the scratch mutant copy.
        mutated = source.replace(
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
            f"sys.path.insert(0, {repr(str(ROOT))})"
        ).replace('"stale"', '"observed"')
        self.assertNotEqual(mutated, source)
        self.assertNotIn('"stale"', mutated)
        with tempfile.TemporaryDirectory(prefix="gargoyl-offline-evidence-mutant-") as tmp:
            copy = Path(tmp) / "stale_snapshot" / "mutant_runner.py"
            copy.parent.mkdir()
            copy.write_text(mutated, encoding="utf-8")
            out = Path(tmp) / "out"
            result = run_runner(out, script=copy)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("mismatch [stale_snapshot] observed_reading_becomes_stale_after_ttl", result.stderr)
            self.assertIn("expected 'observed', got 'stale'", result.stderr)
            evidence = json.loads((out / "offline_acceptance_evidence.json").read_text(encoding="utf-8"))
            self.assertFalse(evidence["all_matched"])

    def test_output_requirement_is_enforced(self):
        result = subprocess.run([sys.executable, str(RUNNER)], cwd=ROOT,
                                capture_output=True, text=True, timeout=60,
                                env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_renderer_heading_change_fails_closed_without_publishing_unmarked_html(self):
        source = RUNNER.read_text(encoding="utf-8")
        # Mutate the heading target in the runner to simulate production heading drift.
        mutated = source.replace(
            "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
            f"sys.path.insert(0, {repr(str(ROOT))})"
        ).replace(
            'heading_target = "<h1>Fleet evidence</h1>"',
            'heading_target = "<h1>Drifted heading</h1>"'
        )
        self.assertNotEqual(mutated, source)
        with tempfile.TemporaryDirectory(prefix="gargoyl-heading-drift-") as tmp:
            copy = Path(tmp) / "mutant_runner.py"
            copy.write_text(mutated, encoding="utf-8")
            out = Path(tmp) / "out"
            result = run_runner(out, script=copy)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("Offline fixture artifacts unavailable:", result.stderr)
            self.assertIn("Expected exactly one '<h1>Drifted heading</h1>'", result.stderr)
            self.assertFalse((out / "offline_acceptance_evidence.json").exists())

    def test_runner_imports_this_checkout_even_with_decoy_on_pythonpath_and_external_cwd(self):
        with tempfile.TemporaryDirectory(prefix="gargoyl-decoy-") as decoy_tmp:
            decoy_gargoyl = Path(decoy_tmp) / "gargoyl"
            decoy_gargoyl.mkdir()
            (decoy_gargoyl / "__init__.py").write_text('raise RuntimeError("decoy gargoyl imported")\n', encoding="utf-8")
            out = Path(decoy_tmp) / "out"
            env = {**os.environ, "PYTHONPATH": decoy_tmp, "PYTHONWARNINGS": "ignore"}
            result = subprocess.run([sys.executable, str(RUNNER), "--out", str(out)],
                                    cwd=decoy_tmp, capture_output=True, text=True, timeout=60, env=env)
            self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}\nstderr: {result.stderr}")
            self.assertNotIn("decoy gargoyl imported", result.stderr)
            self.assertTrue((out / "offline_acceptance_evidence.json").is_file())


if __name__ == "__main__":
    unittest.main()
