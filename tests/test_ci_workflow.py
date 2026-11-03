"""Tests for Issue #82 CI workflow gates, platform invariants, and action graph integrity.

Environment: mock data / static analysis (does not claim live Linux CI or hosted runner execution).
"""

import hashlib
import os
import subprocess
import tomllib
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_YML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXPECTED_CI_GIT_SHA = "545f03c2df66a9f9feb72aaa7cf425dca8f40bb2"
EXPECTED_CI_SHA256 = "1e7c8eda685a3765f2eb1fc47e5ab34a17416913459cc47d72a5e99dd3a78d0b"


def load_workflow(path=CI_YML_PATH):
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in raw and "on" not in raw:
        raw["on"] = raw[True]
    return raw


def evaluate_prerequisite_gate(linux_result, macos_result, audit_result):
    """Execute the exact production prerequisite gate shell logic.

    Returns the process exit code (0 for success, non-zero for refusal).
    """
    script = (
        'test "$LINUX_RESULT" = success && '
        'test "$MACOS_RESULT" = success && '
        'test "$AUDIT_RESULT" = success'
    )
    env = dict(
        os.environ,
        LINUX_RESULT=linux_result,
        MACOS_RESULT=macos_result,
        AUDIT_RESULT=audit_result,
    )
    proc = subprocess.run(
        ["/bin/sh", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode


def validate_workflow_invariants(doc):
    """Verify that a workflow document satisfies all Gargoyl production gates."""
    assert doc.get("permissions") == {"contents": "read"}, (
        "Permissions must be read-only"
    )

    triggers = doc.get("on")
    assert isinstance(triggers, dict), "Triggers must be a mapping"
    assert "pull_request" in triggers, "pull_request trigger required"
    assert triggers.get("push", {}).get("branches") == ["main"], (
        "push restricted to main"
    )

    jobs = doc.get("jobs", {})
    for required_job in (
        "lint-and-test",
        "macos-native",
        "dependency-audit",
        "release-artifact",
    ):
        assert required_job in jobs, f"Missing required job: {required_job}"

    # lint-and-test invariants
    lint_job = jobs["lint-and-test"]
    assert lint_job["runs-on"] == "ubuntu-latest", (
        "Current Linux routing must be ubuntu-latest"
    )
    matrix = lint_job.get("strategy", {}).get("matrix", {})
    assert matrix.get("python-version") == ["3.11", "3.12", "3.13", "3.14"], (
        "Matrix must include all 4 Python versions"
    )

    # macos-native invariants
    macos_job = jobs["macos-native"]
    assert macos_job["runs-on"] == "macos-15", (
        "macos-native must run on real macos-15 runner"
    )
    assert macos_job.get("timeout-minutes") == 15
    macos_steps = macos_job.get("steps", [])
    assert any("TMPDIR" in step.get("run", "") for step in macos_steps), (
        "macos-native must configure canonical TMPDIR"
    )

    # dependency-audit invariants
    audit_job = jobs["dependency-audit"]
    assert audit_job["runs-on"] == "ubuntu-latest"
    audit_steps = audit_job.get("steps", [])
    assert any("pip-audit==2.10.1" in step.get("run", "") for step in audit_steps)
    assert any("--strict" in step.get("run", "") for step in audit_steps)

    # release-artifact invariants
    release_job = jobs["release-artifact"]
    assert set(release_job.get("needs", [])) == {
        "lint-and-test",
        "macos-native",
        "dependency-audit",
    }, "release-artifact must depend on all three prior gates"
    assert release_job.get("if") == "${{ always() }}", (
        "release-artifact must have if: ${{ always() }}"
    )
    assert release_job["runs-on"] == "ubuntu-latest"
    release_steps = release_job.get("steps", [])
    prereq_step = release_steps[0]
    assert 'test "$LINUX_RESULT" = success' in prereq_step.get("run", "")
    assert 'test "$MACOS_RESULT" = success' in prereq_step.get("run", "")
    assert 'test "$AUDIT_RESULT" = success' in prereq_step.get("run", "")


class CIWorkflowTests(unittest.TestCase):
    def test_workflow_file_integrity_and_exact_hashes(self):
        content = CI_YML_PATH.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        self.assertEqual(
            sha256,
            EXPECTED_CI_SHA256,
            "ci.yml SHA-256 digest changed unexpectedly",
        )

        git_hash = subprocess.check_output(
            ["git", "hash-object", str(CI_YML_PATH)], text=True
        ).strip()
        self.assertEqual(
            git_hash,
            EXPECTED_CI_GIT_SHA,
            "ci.yml Git object SHA changed unexpectedly",
        )

    def test_workflow_structure_and_production_invariants(self):
        doc = load_workflow()
        validate_workflow_invariants(doc)

    def test_pinned_action_shas(self):
        doc = load_workflow()
        pinned_actions = {
            "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
            "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
            "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
        }
        found_actions = {}
        for job_name, job in doc.get("jobs", {}).items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses and "@" in uses:
                    action_name, action_sha = uses.split("@", 1)
                    found_actions[action_name] = action_sha
                    if action_name in pinned_actions:
                        self.assertEqual(
                            action_sha,
                            pinned_actions[action_name],
                            f"Action {action_name} in job {job_name} has unexpected SHA {action_sha}",
                        )
        for required_action in pinned_actions:
            self.assertIn(required_action, found_actions)

    def test_no_secrets_referenced(self):
        content = CI_YML_PATH.read_text(encoding="utf-8")
        self.assertNotIn(
            "secrets.", content, "ci.yml must not reference any repository secrets"
        )

    def test_release_prerequisite_gate_fail_closed(self):
        """Verify that release-artifact strictly refuses execution unless all three prerequisites succeed."""
        # Only all-success should exit 0
        self.assertEqual(evaluate_prerequisite_gate("success", "success", "success"), 0)

        # Linux failure, cancelled, or skipped must refuse
        self.assertEqual(evaluate_prerequisite_gate("failure", "success", "success"), 1)
        self.assertEqual(
            evaluate_prerequisite_gate("cancelled", "success", "success"), 1
        )
        self.assertEqual(evaluate_prerequisite_gate("skipped", "success", "success"), 1)

        # macOS failure, cancelled, or skipped must refuse
        self.assertEqual(evaluate_prerequisite_gate("success", "failure", "success"), 1)
        self.assertEqual(
            evaluate_prerequisite_gate("success", "cancelled", "success"), 1
        )
        self.assertEqual(evaluate_prerequisite_gate("success", "skipped", "success"), 1)

        # Audit failure, cancelled, or skipped must refuse
        self.assertEqual(evaluate_prerequisite_gate("success", "success", "failure"), 1)
        self.assertEqual(
            evaluate_prerequisite_gate("success", "success", "cancelled"), 1
        )
        self.assertEqual(evaluate_prerequisite_gate("success", "success", "skipped"), 1)

        # Empty or unexpected results must refuse
        self.assertEqual(evaluate_prerequisite_gate("", "", ""), 1)
        self.assertEqual(evaluate_prerequisite_gate("unknown", "unknown", "unknown"), 1)

    def test_causal_mutations_fail_invariants(self):
        """Verify that mutating required production gates in scratch copies causes regression failures."""
        base_doc = load_workflow()

        # Mutant 1: Remove macos-native from needs
        mutant1 = yaml.safe_load(yaml.dump(base_doc))
        mutant1["jobs"]["release-artifact"]["needs"] = [
            "lint-and-test",
            "dependency-audit",
        ]
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant1)

        # Mutant 2: Change if: ${{ always() }} to if: success()
        mutant2 = yaml.safe_load(yaml.dump(base_doc))
        mutant2["jobs"]["release-artifact"]["if"] = "success()"
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant2)

        # Mutant 3: Remove test "$MACOS_RESULT" = success from script
        mutant3 = yaml.safe_load(yaml.dump(base_doc))
        mutant3["jobs"]["release-artifact"]["steps"][0]["run"] = (
            'test "$LINUX_RESULT" = success\ntest "$AUDIT_RESULT" = success\n'
        )
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant3)

        # Mutant 4: Remove Python 3.14 from matrix
        mutant4 = yaml.safe_load(yaml.dump(base_doc))
        mutant4["jobs"]["lint-and-test"]["strategy"]["matrix"]["python-version"] = [
            "3.11",
            "3.12",
            "3.13",
        ]
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant4)

        # Mutant 5: Move macos-native to ubuntu-latest (fake/skip Linux)
        mutant5 = yaml.safe_load(yaml.dump(base_doc))
        mutant5["jobs"]["macos-native"]["runs-on"] = "ubuntu-latest"
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant5)

        # Mutant 6: Weaken permissions to contents: write
        mutant6 = yaml.safe_load(yaml.dump(base_doc))
        mutant6["permissions"] = {"contents": "write"}
        with self.assertRaises(AssertionError):
            validate_workflow_invariants(mutant6)

    def test_action_and_script_graph_digests(self):
        digests = {
            "pyproject.toml": "7f5ada8949aaa2cdcffbdb61ab8409380d3d4f054c39a262d138d0002429a786",
            "README.md": "c1ba02440f8c5cfa07c5457f57b03110f5148e33a6e8aeec8c9aa6c6d197469b",
            "tools/run_tests.py": "522456210ef5c77d9109388e12088ab4695ed203af8f2f491327b8c9a3f9977f",
            "tools/verify_release_artifact.py": (
                "eec6c171586a8acb7b52914e04b1209e01a929a2dbd6afd5bdeee65ffbe264a7"
            ),
            "tools/build_macos_app.py": (
                "9627562a2ac1ac3ccf909fd75b07ae8844034d7065fc1e0a6d85434893d375f5"
            ),
            "tools/offline_acceptance_evidence.py": (
                "1447cd6f98336efa34d23e6bfc411d2ae6498c011c7abd0f76aa6b5e8f2c8734"
            ),
        }
        for rel_path, expected_sha in digests.items():
            full_path = REPO_ROOT / rel_path
            self.assertTrue(full_path.is_file(), f"File {rel_path} must exist")
            actual_sha = hashlib.sha256(full_path.read_bytes()).hexdigest()
            self.assertEqual(
                actual_sha,
                expected_sha,
                f"File {rel_path} digest mismatch: {actual_sha} != {expected_sha}",
            )

    def test_declared_dependencies_graph_resolution(self):
        """Verify the exact dependency resolution logic used by the dependency-audit job."""
        with open(REPO_ROOT / "pyproject.toml", "rb") as f:
            p = tomllib.load(f)
        d = p["project"]
        req = (
            p["build-system"]["requires"]
            + d["dependencies"]
            + sum(d["optional-dependencies"].values(), [])
        )
        resolved = list(dict.fromkeys(req))
        expected = [
            "setuptools==84.1.0",
            "wheel==0.46.2",
            "cryptography>=46,<51",
            "ruff==0.14.3",
        ]
        self.assertEqual(resolved, expected)

    def test_routing_delta_proposal_validator(self):
        """Validate the potential Linux runner routing delta while verifying current routing is held."""
        # 1. Verify current production routing is held on ubuntu-latest
        doc = load_workflow()
        self.assertEqual(doc["jobs"]["lint-and-test"]["runs-on"], "ubuntu-latest")
        self.assertEqual(doc["jobs"]["macos-native"]["runs-on"], "macos-15")
        self.assertEqual(doc["jobs"]["dependency-audit"]["runs-on"], "ubuntu-latest")
        self.assertEqual(doc["jobs"]["release-artifact"]["runs-on"], "ubuntu-latest")

        # 2. Define proposed routing delta (for when approved enrollment and capacity exist)
        proposed_linux_label = ["self-hosted", "linux", "gargoyl"]
        proposed_routing = {
            "lint-and-test": proposed_linux_label,
            "macos-native": "macos-15",  # Strictly preserved on real macOS runner
            "dependency-audit": proposed_linux_label,
            "release-artifact": proposed_linux_label,
        }

        # Rule: macos-native must never be routed to self-hosted Linux
        self.assertEqual(proposed_routing["macos-native"], "macos-15")
        self.assertNotIn("linux", repr(proposed_routing["macos-native"]))

        # Rule: Proposed Linux routing must be repository-specific
        for job_name in ("lint-and-test", "dependency-audit", "release-artifact"):
            labels = proposed_routing[job_name]
            self.assertIn("gargoyl", labels)
            self.assertIn("linux", labels)


if __name__ == "__main__":
    unittest.main()
