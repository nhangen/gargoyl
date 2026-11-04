"""Tests for Issue #82 CI workflow gates, platform invariants, and action graph integrity.

Environment: mock data / static analysis (does not claim live Linux CI or hosted runner execution).
"""

import contextlib
import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_YML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXPECTED_CI_GIT_SHA = "545f03c2df66a9f9feb72aaa7cf425dca8f40bb2"
EXPECTED_CI_SHA256 = "1e7c8eda685a3765f2eb1fc47e5ab34a17416913459cc47d72a5e99dd3a78d0b"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools import ci_preflight as preflight_mod  # noqa: E402
from tools.ci_preflight import (  # noqa: E402
    PROPOSED_LOCAL_ROUTING,
    extract_declared_dependencies,
)

# Documented CLI contract, written independently of the module constants.
EXIT_READY = 0
EXIT_CONTRACT_FAILED = 1
EXIT_USAGE_ERROR = 2
EXIT_HELD_BLOCKED = 3

EXPECTED_HELD_GATE_NAMES = [
    "local_fleet_capacity",
    "repository_enrollment",
    "branch_protection_visibility",
    "linux_matrix_runtime",
    "strict_vulnerability_audit",
    "release_packaging_and_verification",
    "container_unprivileged_profile",
    "hosted_pipeline_equivalence",
    "fork_pr_and_state_isolation",
    "python314_pyyaml_sdist_build_risk",
    "macos_native_full_suite_local_proof",
    "macos_native_retained_hosted",
]

GATE_SHELL = "/bin/bash"
GATE_SHELL_PATH = "/usr/bin:/bin"


def hermetic_env(home, **extra):
    """Build a subprocess environment that excludes the caller's startup files and env.

    PATH is pinned to system directories, and HOME, TMPDIR and git config point at the
    fixture, so subprocesses do not pick up the operator's PATH shims, shell startup
    files, exported shell functions, BASH_ENV/ENV, or global/system git config. This is
    environment isolation only; it does not sandbox absolute-path reads.
    """
    env = {
        "PATH": GATE_SHELL_PATH,
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    env.update(extra)
    return env


def load_workflow(path=CI_YML_PATH):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(doc, dict) and True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    return doc


def evaluate_prerequisite_gate(linux_result, macos_result, audit_result, doc=None):
    """Execute the prerequisite gate script extracted from ci.yml.

    Approximates GitHub's unspecified-shell form, `bash -e {0}` on a script file.
    The step must not declare its own shell, which the structural validator enforces.
    The run is hermetic: --noprofile --norc, stdin from /dev/null, and an explicit env
    with only PATH, a fixture HOME and the three results. It never inherits the caller's
    environment, BASH_ENV/ENV or exported functions.
    Returns the process exit code (0 for success, non-zero for refusal).
    """
    if doc is None:
        doc = load_workflow()

    release_job = doc.get("jobs", {}).get("release-artifact", {})
    steps = release_job.get("steps", [])
    assert steps, "release-artifact has no steps"
    gate_step = steps[0]
    assert (
        gate_step.get("name") == "Require successful platform and audit prerequisites"
    ), f"Step 0 name mismatch: {gate_step.get('name')}"

    script = gate_step.get("run", "")
    assert script, "Prerequisite gate step has empty run script"

    env_mapping = gate_step.get("env", {})
    expected_env_keys = {"LINUX_RESULT", "MACOS_RESULT", "AUDIT_RESULT"}
    assert set(env_mapping.keys()) == expected_env_keys, (
        f"Prerequisite gate env keys mismatch: {set(env_mapping.keys())} != {expected_env_keys}"
    )

    with tempfile.TemporaryDirectory() as fixture_home:
        script_path = Path(fixture_home) / "prerequisite_gate.sh"
        script_path.write_text(script, encoding="utf-8")
        env = {
            "PATH": GATE_SHELL_PATH,
            "HOME": fixture_home,
            "LINUX_RESULT": linux_result,
            "MACOS_RESULT": macos_result,
            "AUDIT_RESULT": audit_result,
        }
        proc = subprocess.run(
            [GATE_SHELL, "--noprofile", "--norc", "-e", str(script_path)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
    return proc.returncode


def validate_workflow_invariants(doc):
    """Verify that a workflow document satisfies all Gargoyl production gates."""
    assert isinstance(doc, dict), "Workflow document must be a mapping"
    assert doc.get("permissions") == {"contents": "read"}, (
        "Root permissions must be strictly read-only contents: read"
    )

    # 1. Triggers (normalize PyYAML unquoted 'on' boolean parse if needed)
    if True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    triggers = doc.get("on")
    assert isinstance(triggers, dict), "Triggers must be a mapping"
    assert "pull_request" in triggers, "pull_request trigger required"
    assert "pull_request_target" not in triggers, (
        "pull_request_target trigger is strictly forbidden"
    )
    assert triggers.get("push", {}).get("branches") == ["main"], (
        "push trigger must be restricted to main"
    )
    unauthorized_triggers = set(triggers.keys()) - {"push", "pull_request"}
    assert not unauthorized_triggers, (
        f"Unauthorized triggers present: {unauthorized_triggers}"
    )

    # 2. Required jobs
    jobs = doc.get("jobs", {})
    expected_jobs = {
        "lint-and-test",
        "macos-native",
        "dependency-audit",
        "release-artifact",
    }
    assert set(jobs.keys()) == expected_jobs, (
        f"Jobs mismatch: {set(jobs.keys())} != {expected_jobs}"
    )

    for job_name, job in jobs.items():
        assert not job.get("continue-on-error"), (
            f"Job {job_name} must not have continue-on-error"
        )
        job_perms = job.get("permissions")
        if job_perms is not None:
            assert job_perms == {"contents": "read"}, (
                f"Job {job_name} permissions exceed read-only: {job_perms}"
            )

    # 3. lint-and-test invariants
    lint_job = jobs["lint-and-test"]
    assert lint_job.get("runs-on") == "ubuntu-latest", (
        "Current Linux routing must be ubuntu-latest"
    )
    matrix = lint_job.get("strategy", {}).get("matrix", {})
    assert matrix.get("python-version") == ["3.11", "3.12", "3.13", "3.14"], (
        "Matrix must include all 4 Python versions: 3.11, 3.12, 3.13, 3.14"
    )
    lint_steps = lint_job.get("steps", [])
    assert any(
        "ruff check ." in step.get("run", "")
        and not step.get("continue-on-error")
        and not step.get("if")
        for step in lint_steps
    ), "lint-and-test must execute ruff check without continue-on-error or if"
    assert any(
        "python tools/run_tests.py discover -s tests -v" in step.get("run", "")
        and not step.get("continue-on-error")
        and not step.get("if")
        for step in lint_steps
    ), "lint-and-test must execute test suite without continue-on-error or if"

    # 4. macos-native invariants
    macos_job = jobs["macos-native"]
    assert macos_job.get("runs-on") == "macos-15", (
        "macos-native must run on real macos-15 runner"
    )
    assert macos_job.get("timeout-minutes") == 15, "macos-native timeout must be 15"
    macos_steps = macos_job.get("steps", [])
    assert any(
        'export TMPDIR="$(python -c' in step.get("run", "")
        and "os.path.realpath(tempfile.gettempdir())" in step.get("run", "")
        and "python tools/run_tests.py discover -s tests -v" in step.get("run", "")
        and not step.get("continue-on-error")
        and not step.get("if")
        for step in macos_steps
    ), (
        "macos-native must export canonical TMPDIR and run the suite in the same "
        "step, without continue-on-error or if"
    )

    # 5. dependency-audit invariants
    audit_job = jobs["dependency-audit"]
    assert audit_job.get("runs-on") == "ubuntu-latest", (
        "dependency-audit must run on ubuntu-latest"
    )
    audit_steps = audit_job.get("steps", [])
    assert any(
        "pip-audit==2.10.1" in step.get("run", "") and not step.get("continue-on-error")
        for step in audit_steps
    ), "dependency-audit must install pip-audit==2.10.1"
    assert any(
        "--strict" in step.get("run", "")
        and "-r audit-requirements.txt" in step.get("run", "")
        and not step.get("continue-on-error")
        and not step.get("if")
        for step in audit_steps
    ), "dependency-audit must execute --strict audit without continue-on-error"

    # 6. release-artifact invariants
    release_job = jobs["release-artifact"]
    assert set(release_job.get("needs", [])) == {
        "lint-and-test",
        "macos-native",
        "dependency-audit",
    }, "release-artifact must depend on all three prior gates"
    assert release_job.get("if") == "${{ always() }}", (
        "release-artifact must have if: ${{ always() }}"
    )
    assert release_job.get("runs-on") == "ubuntu-latest", (
        "release-artifact must run on ubuntu-latest"
    )
    release_steps = release_job.get("steps", [])
    assert len(release_steps) >= 7, "release-artifact must contain at least 7 steps"

    # Step 0: Gate
    gate_step = release_steps[0]
    assert (
        gate_step.get("name") == "Require successful platform and audit prerequisites"
    ), "Step 0 must be prerequisite verification gate"
    assert not gate_step.get("continue-on-error"), (
        "Gate step must not have continue-on-error"
    )
    assert not gate_step.get("shell"), "Gate step must not override shell"
    assert not gate_step.get("if"), "Gate step must not have if condition"

    gate_env = gate_step.get("env", {})
    assert gate_env.get("LINUX_RESULT") == "${{ needs.lint-and-test.result }}", (
        "LINUX_RESULT binding mismatch"
    )
    assert gate_env.get("MACOS_RESULT") == "${{ needs.macos-native.result }}", (
        "MACOS_RESULT binding mismatch"
    )
    assert gate_env.get("AUDIT_RESULT") == "${{ needs.dependency-audit.result }}", (
        "AUDIT_RESULT binding mismatch"
    )

    gate_run = gate_step.get("run", "").strip().splitlines()
    expected_run = [
        'test "$LINUX_RESULT" = success',
        'test "$MACOS_RESULT" = success',
        'test "$AUDIT_RESULT" = success',
    ]
    assert gate_run == expected_run, (
        f"Gate step script mismatch: {gate_run} != {expected_run}"
    )

    # Step 5: Verify wheel
    verify_step = release_steps[5]
    assert (
        "python tools/verify_release_artifact.py dist/gargoyl-0.1.0-py3-none-any.whl"
        in verify_step.get("run", "")
    ), "Step 5 must verify release artifact wheel"
    assert not verify_step.get("continue-on-error"), (
        "Verify artifact step must not have continue-on-error"
    )
    assert not verify_step.get("if"), "Verify artifact step must not have if condition"

    # Step 6: Upload artifact
    upload_step = release_steps[6]
    assert upload_step.get("uses", "").startswith("actions/upload-artifact@"), (
        "Step 6 must use actions/upload-artifact"
    )
    assert not upload_step.get("continue-on-error"), (
        "Upload step must not have continue-on-error"
    )
    assert not upload_step.get("if"), (
        "Upload step must not have if condition (must use default if: success())"
    )
    upload_with = upload_step.get("with", {})
    assert upload_with.get("path") == "dist/*.whl", "Upload must publish dist/*.whl"
    assert upload_with.get("if-no-files-found") == "error", (
        "Upload must fail when no wheel exists (if-no-files-found: error)"
    )

    # Action pins
    hex40_pattern = re.compile(r"^[0-9a-f]{40}$")
    for j_name, j_data in jobs.items():
        for s in j_data.get("steps", []):
            u = s.get("uses")
            if u and "@" in u:
                action_name, action_sha = u.split("@", 1)
                assert hex40_pattern.match(action_sha), (
                    f"Action {action_name} in {j_name} not pinned to 40-char hex SHA: {action_sha}"
                )


class CIWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._fixture_dir = tempfile.TemporaryDirectory()
        cls.fixture_home = Path(cls._fixture_dir.name)

    @classmethod
    def tearDownClass(cls):
        cls._fixture_dir.cleanup()

    def _run_preflight(self, *args, **extra_env):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "ci_preflight.py"), *args],
            env=hermetic_env(self.fixture_home, **extra_env),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )

    def _run_main_in_process(self, argv):
        with (
            mock.patch.dict(os.environ, hermetic_env(self.fixture_home), clear=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            return preflight_mod.main(argv)

    def test_workflow_file_integrity_and_exact_hashes(self):
        content = CI_YML_PATH.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        self.assertEqual(
            sha256,
            EXPECTED_CI_SHA256,
            "ci.yml SHA-256 digest changed unexpectedly",
        )

        git_hash = subprocess.check_output(
            ["git", "hash-object", str(CI_YML_PATH)],
            env=hermetic_env(self.fixture_home),
            stdin=subprocess.DEVNULL,
            text=True,
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
        """Verify that release-artifact refuses execution unless all prerequisites succeed."""
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

    def test_prerequisite_gate_ignores_caller_shell_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            poisoned_home = tmp_path / "home"
            poisoned_home.mkdir()
            marker = tmp_path / "STARTUP_SOURCED"
            override = f'test() {{ touch "{marker}"; return 0; }}\n'
            for rc_name in (".bashrc", ".bash_profile", ".profile"):
                (poisoned_home / rc_name).write_text(override, encoding="utf-8")
            env_file = tmp_path / "bash_env.sh"
            env_file.write_text(override, encoding="utf-8")
            exported_function = f'() {{ touch "{marker}"; return 0\n}}'
            poisoned = {
                "HOME": str(poisoned_home),
                "BASH_ENV": str(env_file),
                "ENV": str(env_file),
                "BASH_FUNC_test%%": exported_function,
                "BASH_FUNC_test()": exported_function,
            }
            with mock.patch.dict(os.environ, poisoned):
                self.assertEqual(
                    evaluate_prerequisite_gate("success", "success", "success"), 0
                )
                self.assertEqual(
                    evaluate_prerequisite_gate("failure", "success", "success"), 1
                )
                self.assertEqual(
                    evaluate_prerequisite_gate("success", "skipped", "success"), 1
                )
                self.assertEqual(
                    evaluate_prerequisite_gate("success", "success", "cancelled"), 1
                )
            self.assertFalse(marker.exists())

    def test_causal_mutations_fail_invariants(self):
        """Verify that mutating required production gates in scratch copies causes regression failures."""
        base_doc = load_workflow()

        # Positive baseline verification: unmodified base_doc MUST pass all invariants
        validate_workflow_invariants(base_doc)

        def assert_mutant_fails(mutant, desc):
            with self.assertRaises(AssertionError, msg=f"Mutant escaped: {desc}"):
                validate_workflow_invariants(mutant)

        # M1: Rebind MACOS_RESULT to needs.lint-and-test.result
        m1 = yaml.safe_load(yaml.dump(base_doc))
        m1["jobs"]["release-artifact"]["steps"][0]["env"]["MACOS_RESULT"] = (
            "${{ needs.lint-and-test.result }}"
        )
        assert_mutant_fails(m1, "Rebound MACOS_RESULT to lint-and-test")

        # M2: Bind MACOS_RESULT to literal success
        m2 = yaml.safe_load(yaml.dump(base_doc))
        m2["jobs"]["release-artifact"]["steps"][0]["env"]["MACOS_RESULT"] = "success"
        assert_mutant_fails(m2, "Bound MACOS_RESULT to literal success")

        # M3: Remove MACOS_RESULT from step 0 env
        m3 = yaml.safe_load(yaml.dump(base_doc))
        del m3["jobs"]["release-artifact"]["steps"][0]["env"]["MACOS_RESULT"]
        assert_mutant_fails(m3, "Removed MACOS_RESULT from env")

        # M4: Add continue-on-error: true on gate step 0
        m4 = yaml.safe_load(yaml.dump(base_doc))
        m4["jobs"]["release-artifact"]["steps"][0]["continue-on-error"] = True
        assert_mutant_fails(m4, "Added continue-on-error on gate step 0")

        # M5: Add continue-on-error: true on macos-native job
        m5 = yaml.safe_load(yaml.dump(base_doc))
        m5["jobs"]["macos-native"]["continue-on-error"] = True
        assert_mutant_fails(m5, "Added continue-on-error on macos-native job")

        # M6: Add shell: bash {0} on gate step 0 (disabling -e fail-fast)
        m6 = yaml.safe_load(yaml.dump(base_doc))
        m6["jobs"]["release-artifact"]["steps"][0]["shell"] = "bash {0}"
        assert_mutant_fails(m6, "Added shell override on gate step 0")

        # M7: Remove verify_release_artifact step
        m7 = yaml.safe_load(yaml.dump(base_doc))
        m7["jobs"]["release-artifact"]["steps"] = [
            s
            for s in m7["jobs"]["release-artifact"]["steps"]
            if "verify_release_artifact" not in s.get("run", "")
        ]
        assert_mutant_fails(m7, "Removed verify_release_artifact step")

        # M8: Remove upload-artifact step
        m8 = yaml.safe_load(yaml.dump(base_doc))
        m8["jobs"]["release-artifact"]["steps"] = [
            s
            for s in m8["jobs"]["release-artifact"]["steps"]
            if "actions/upload-artifact" not in s.get("uses", "")
        ]
        assert_mutant_fails(m8, "Removed upload-artifact step")

        # M9: Add if: always() on upload-artifact step
        m9 = yaml.safe_load(yaml.dump(base_doc))
        for s in m9["jobs"]["release-artifact"]["steps"]:
            if "actions/upload-artifact" in s.get("uses", ""):
                s["if"] = "${{ always() }}"
        assert_mutant_fails(m9, "Added if: always() on upload-artifact step")

        # M10: Replace macOS test command with echo
        m10 = yaml.safe_load(yaml.dump(base_doc))
        for s in m10["jobs"]["macos-native"]["steps"]:
            if "tools/run_tests.py" in s.get("run", ""):
                s["run"] = "echo 'faked tests'"
        assert_mutant_fails(m10, "Replaced macOS tests with echo")

        # M11: Add pull_request_target trigger
        m11 = yaml.safe_load(yaml.dump(base_doc))
        m11["on"]["pull_request_target"] = {}
        assert_mutant_fails(m11, "Added pull_request_target trigger")

        # M12: Move macos-native to ubuntu-latest
        m12 = yaml.safe_load(yaml.dump(base_doc))
        m12["jobs"]["macos-native"]["runs-on"] = "ubuntu-latest"
        assert_mutant_fails(m12, "Moved macos-native to ubuntu-latest")

        # M13: Remove Python 3.14 from matrix
        m13 = yaml.safe_load(yaml.dump(base_doc))
        m13["jobs"]["lint-and-test"]["strategy"]["matrix"]["python-version"] = [
            "3.11",
            "3.12",
            "3.13",
        ]
        assert_mutant_fails(m13, "Removed Python 3.14 from matrix")

        # M14: Weaken permissions to contents: write
        m14 = yaml.safe_load(yaml.dump(base_doc))
        m14["permissions"] = {"contents": "write"}
        assert_mutant_fails(m14, "Weakened permissions to contents: write")

        # M15: Change release job if: ${{ always() }} to if: success()
        m15 = yaml.safe_load(yaml.dump(base_doc))
        m15["jobs"]["release-artifact"]["if"] = "success()"
        assert_mutant_fails(m15, "Changed release job if to success()")

        m16 = yaml.safe_load(yaml.dump(base_doc))
        for s in m16["jobs"]["release-artifact"]["steps"]:
            if "actions/upload-artifact" in s.get("uses", ""):
                del s["with"]["if-no-files-found"]
        assert_mutant_fails(m16, "Removed if-no-files-found: error from upload")

        m17 = yaml.safe_load(yaml.dump(base_doc))
        macos_steps = m17["jobs"]["macos-native"]["steps"]
        suite_index = next(
            i
            for i, s in enumerate(macos_steps)
            if "tools/run_tests.py" in s.get("run", "")
        )
        export_line, suite_line = macos_steps[suite_index]["run"].strip().splitlines()
        macos_steps[suite_index]["run"] = suite_line
        macos_steps.insert(suite_index, {"run": export_line})
        assert_mutant_fails(m17, "Split canonical TMPDIR export into a separate step")

    def test_action_and_script_graph_digests(self):
        digests = {
            "pyproject.toml": "10f1a10cc95e3b8e2ec5b0931b91f580fe3061f7a00eeac2f4d4215555db3b69",
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

    def test_declared_dependencies_manifest_extraction(self):
        """Verify static extraction of declared dependencies from pyproject.toml manifest."""
        expected = [
            "setuptools==84.1.0",
            "wheel==0.46.2",
            "cryptography>=46,<51",
            "ruff==0.14.3",
            "PyYAML==6.0.2",
        ]
        # 1. Call production helper directly
        extracted = extract_declared_dependencies()
        self.assertEqual(extracted, expected)

        # 2. Compare with ci.yml dependency-audit step's manifest generation logic
        doc = load_workflow()
        audit_step = next(
            s
            for s in doc["jobs"]["dependency-audit"]["steps"]
            if "audit-requirements.txt" in s.get("run", "")
        )
        run_text = audit_step["run"]
        match = re.search(r"python -c '([^']+)'", run_text)
        self.assertTrue(match, "Could not find python -c snippet in audit step")
        proc = subprocess.run(
            [sys.executable, "-c", match.group(1)],
            cwd=str(REPO_ROOT),
            env=hermetic_env(self.fixture_home),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
        )
        audit_reqs = proc.stdout.strip().splitlines()
        self.assertEqual(audit_reqs, expected)

    def test_routing_delta_proposal_validator(self):
        """Validate the local-ci unique custom label profile against tool's actual PROPOSED_LOCAL_ROUTING contract."""
        # 1. Verify current production routing is held on ubuntu-latest
        doc = load_workflow()
        self.assertEqual(doc["jobs"]["lint-and-test"]["runs-on"], "ubuntu-latest")
        self.assertEqual(doc["jobs"]["macos-native"]["runs-on"], "macos-15")
        self.assertEqual(doc["jobs"]["dependency-audit"]["runs-on"], "ubuntu-latest")
        self.assertEqual(doc["jobs"]["release-artifact"]["runs-on"], "ubuntu-latest")

        # 2. Verify preflight tool's actual PROPOSED_LOCAL_ROUTING contract
        self.assertEqual(PROPOSED_LOCAL_ROUTING["profile"], "nhangen/local-ci")
        self.assertEqual(PROPOSED_LOCAL_ROUTING["flags"], "--no-default-labels")
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["target_label_state"], "UNRESOLVED_HELD"
        )
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["macos_jobs_excluded"], ["macos-native"]
        )
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["linux_jobs"],
            ["lint-and-test", "dependency-audit", "release-artifact"],
        )
        target = PROPOSED_LOCAL_ROUTING["target_label"]
        self.assertIsInstance(target, str)
        self.assertNotIn("local-ci-gargoyl", target)
        self.assertNotIn("local-ci-326cbb95", target)

        # 3. Verify via tool CLI execution in JSON mode
        proc = self._run_preflight("--json")
        self.assertEqual(proc.returncode, EXIT_HELD_BLOCKED)
        data = json.loads(proc.stdout)
        self.assertEqual(
            data["proposed_routing"]["target_label_state"], "UNRESOLVED_HELD"
        )
        self.assertFalse(data["deployment_ready"])
        self.assertEqual(data["held_gates_count"], 11)
        self.assertEqual(data["preserved_gates_count"], 1)

    def test_preflight_cli_modes_and_exit_semantics(self):
        """Causally test that preflight CLI modes enforce correct exit semantics and avoid false readiness."""
        # 1. --check-source verifies static contracts and exits 0 on valid source
        proc_source = self._run_preflight("--check-source")
        self.assertEqual(
            proc_source.returncode,
            EXIT_READY,
            proc_source.stdout + proc_source.stderr,
        )
        self.assertIn("Source Contracts:     PASS", proc_source.stdout)

        # 2. --check-readiness evaluates held infrastructure gates and exits 3 (EXIT_HELD_BLOCKED)
        proc_ready = self._run_preflight("--check-readiness")
        self.assertEqual(
            proc_ready.returncode,
            EXIT_HELD_BLOCKED,
            "Readiness must exit 3 while gates held",
        )
        self.assertIn("Deployment Readiness: BLOCKED", proc_ready.stdout)

        # 3. Default --check and the no-argument form exit 3 while infrastructure gates are held
        for args in (("--check",), ()):
            proc_check = self._run_preflight(*args)
            self.assertEqual(
                proc_check.returncode,
                EXIT_HELD_BLOCKED,
                f"{args or 'no-argument'} must return 3 while gates held",
            )

        # 4. --manifest-only outputs the 5 extracted requirements and exits 0
        proc_manifest = self._run_preflight("--manifest-only")
        self.assertEqual(proc_manifest.returncode, EXIT_READY)
        lines = proc_manifest.stdout.strip().splitlines()
        self.assertEqual(len(lines), 5)
        self.assertIn("PyYAML==6.0.2", lines)

        # 5. --manifest-only --json outputs JSON and exits 0
        proc_manifest_json = self._run_preflight("--manifest-only", "--json")
        self.assertEqual(proc_manifest_json.returncode, EXIT_READY)
        data = json.loads(proc_manifest_json.stdout)
        self.assertEqual(len(data.get("declared_dependencies", [])), 5)

        # 6. Typos / unrecognized arguments exit with 2 (EXIT_USAGE_ERROR)
        proc_bogus = self._run_preflight("--bogus")
        self.assertEqual(
            proc_bogus.returncode,
            EXIT_USAGE_ERROR,
            "Unrecognized option must exit 2 (usage error), not 3 (held)",
        )

        # 7. Conflicting check modes must be rejected with 2 (EXIT_USAGE_ERROR)
        proc_conflict = self._run_preflight("--check", "--check-source")
        self.assertEqual(
            proc_conflict.returncode,
            EXIT_USAGE_ERROR,
            "Conflicting CLI check modes must be rejected with exit 2",
        )
        self.assertIn("not allowed with argument", proc_conflict.stderr)

        # 8. Contract failure in an isolated fixture exits 1 (EXIT_CONTRACT_FAILED) in every
        # check mode, including default --check and no arguments, and never reports READY.
        with tempfile.TemporaryDirectory() as tmpdir:
            broken_workflow = Path(tmpdir) / "broken_ci.yml"
            doc = load_workflow()
            del doc["jobs"]["release-artifact"]
            broken_workflow.write_text(yaml.dump(doc), encoding="utf-8")
            override = {"GARGOYL_CI_WORKFLOW_PATH": str(broken_workflow)}

            for args in (("--check-source",), ("--check-readiness",), ("--check",), ()):
                proc_fail = self._run_preflight(*args, **override)
                self.assertEqual(
                    proc_fail.returncode,
                    EXIT_CONTRACT_FAILED,
                    f"Broken workflow must exit 1 on {args or 'no-argument'}",
                )

            proc_fail_readiness = self._run_preflight("--check-readiness", **override)
            self.assertIn(
                "BLOCKED (source contracts failed", proc_fail_readiness.stdout
            )

            proc_fail_json = self._run_preflight(
                "--check-readiness", "--json", **override
            )
            self.assertEqual(proc_fail_json.returncode, EXIT_CONTRACT_FAILED)
            fail_report = json.loads(proc_fail_json.stdout)
            self.assertFalse(fail_report["source_contracts_passed"])
            self.assertFalse(fail_report["deployment_ready"])

        # 9. The gate inventory matches a hand-written list: no rename, drop, or duplicate.
        gate_names = [g["gate"] for g in preflight_mod.HELD_GATES]
        self.assertEqual(gate_names, EXPECTED_HELD_GATE_NAMES)
        self.assertEqual(len(set(gate_names)), len(EXPECTED_HELD_GATE_NAMES))

        full_proc = self._run_preflight("--json")
        self.assertEqual(full_proc.returncode, EXIT_HELD_BLOCKED)
        full_report = json.loads(full_proc.stdout)
        self.assertEqual(
            sorted(full_report["readiness"].keys()), sorted(EXPECTED_HELD_GATE_NAMES)
        )
        self.assertFalse(full_report["readiness"]["hosted_pipeline_equivalence"])
        self.assertFalse(full_report["readiness"]["python314_pyyaml_sdist_build_risk"])
        self.assertFalse(
            full_report["readiness"]["macos_native_full_suite_local_proof"]
        )
        self.assertTrue(full_report["readiness"]["macos_native_retained_hosted"])

        # 10. Causal F6 proof: simulate all recorded infrastructure gates as VERIFIED.
        # Broken source contracts MUST still force is_ready=False and exit 1.
        simulated_verified_gates = [
            {"gate": g["gate"], "status": "VERIFIED", "reason": "simulated"}
            for g in preflight_mod.HELD_GATES
        ]
        with mock.patch.object(preflight_mod, "HELD_GATES", simulated_verified_gates):
            ready_when_source_ok, _ = preflight_mod.evaluate_deployment_readiness(
                source_ok=True
            )
            self.assertTrue(ready_when_source_ok)

            ready_when_source_fail, _ = preflight_mod.evaluate_deployment_readiness(
                source_ok=False
            )
            self.assertFalse(
                ready_when_source_fail,
                "evaluate_deployment_readiness must be False on source failure even when all infrastructure gates are VERIFIED",
            )

            with tempfile.TemporaryDirectory() as tmpdir:
                broken_workflow = Path(tmpdir) / "broken_ci.yml"
                doc = load_workflow()
                del doc["jobs"]["release-artifact"]
                broken_workflow.write_text(yaml.dump(doc), encoding="utf-8")

                with mock.patch.object(preflight_mod, "CI_YML_PATH", broken_workflow):
                    for argv in (["--check-readiness"], ["--check"], []):
                        self.assertEqual(
                            self._run_main_in_process(argv),
                            EXIT_CONTRACT_FAILED,
                            f"main({argv}) must exit 1 on contract failure even when all gates are simulated VERIFIED",
                        )

    def test_preflight_digest_mismatch_fails_source_gate(self):
        self.assertEqual(self._run_main_in_process(["--check-source"]), EXIT_READY)

        ci_key = ".github/workflows/ci.yml"
        for field, bad_value in (("sha256", "0" * 64), ("git", "0" * 40)):
            tampered = copy.deepcopy(preflight_mod.EXPECTED_DIGESTS)
            tampered[ci_key][field] = bad_value
            with mock.patch.object(preflight_mod, "EXPECTED_DIGESTS", tampered):
                for argv in (
                    ["--check-source"],
                    ["--check-readiness"],
                    ["--check"],
                    [],
                ):
                    self.assertEqual(
                        self._run_main_in_process(argv),
                        EXIT_CONTRACT_FAILED,
                        f"{field} mismatch must exit 1 on main({argv})",
                    )

    def test_preflight_each_contract_key_fails_closed(self):
        def drop_audit_need(doc):
            doc["jobs"]["release-artifact"]["needs"] = ["lint-and-test", "macos-native"]

        mutations = {
            "permissions_read_only": lambda doc: doc.update(
                permissions={"contents": "write"}
            ),
            "current_routing_intact": lambda doc: doc["jobs"]["lint-and-test"].update(
                {"runs-on": "self-hosted"}
            ),
            "release_needs_all_three": drop_audit_need,
            "release_if_always": lambda doc: doc["jobs"]["release-artifact"].update(
                {"if": "${{ success() }}"}
            ),
        }
        for contract_key, mutate in mutations.items():
            with self.subTest(contract_key=contract_key):
                with tempfile.TemporaryDirectory() as tmpdir:
                    mutated_workflow = Path(tmpdir) / "mutated_ci.yml"
                    doc = load_workflow()
                    mutate(doc)
                    mutated_workflow.write_text(yaml.dump(doc), encoding="utf-8")
                    with mock.patch.object(
                        preflight_mod, "CI_YML_PATH", mutated_workflow
                    ):
                        passed, checks = preflight_mod.verify_workflow_contracts()
                        self.assertFalse(passed)
                        self.assertFalse(checks[contract_key])
                        failing = sorted(k for k, ok in checks.items() if not ok)
                        self.assertEqual(failing, [contract_key])
                        self.assertEqual(
                            self._run_main_in_process(["--check-source"]),
                            EXIT_CONTRACT_FAILED,
                        )


if __name__ == "__main__":
    unittest.main()
