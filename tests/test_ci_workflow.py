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
EXPECTED_CI_GIT_SHA = "f6eebc0e70045d4333cdd8bc611d7abce63011f3"
EXPECTED_CI_SHA256 = "d43e5301610a1d318b5094c16bfa86d54d2915ec86ed89b35c9c7a9b08d700c4"

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
    "macos_runner_enrollment",
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


LINUX_RUNS_ON = "local-ci-b6b0a4fed6586b3a"
MACOS_RUNS_ON = "${{ vars.GARGOYL_MACOS_RUNNER_LABEL }}"
GENERIC_RUNNER_LABELS = {"self-hosted", "linux", "macos", "x64", "arm64"}
ALLOWED_ACTION = re.compile(
    r"^actions/(checkout|setup-python|upload-artifact)@[0-9a-f]{40}$"
)
CHECKOUT = {
    "uses": "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "with": {"persist-credentials": False},
}
VENV_STEP = {
    "name": "Create job-local virtualenv",
    "run": 'python -m venv --clear "$RUNNER_TEMP/venv"\n'
    'echo "$RUNNER_TEMP/venv/bin" >> "$GITHUB_PATH"\n',
}


def setup_python(version):
    return {
        "uses": "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "with": {"python-version": version},
    }


SAME_REPOSITORY_ONLY = (
    "${{ github.event_name == 'push' || "
    "github.event.pull_request.head.repo.full_name == github.repository }}"
)
EXPECTED_RELEASE_IF = (
    "${{ always() && (github.event_name == 'push' || "
    "github.event.pull_request.head.repo.full_name == github.repository) }}"
)
EXPECTED_TRIGGERS = {"pull_request": None, "push": {"branches": ["main"]}}
EXPECTED_CONCURRENCY = {
    "group": "ci-${{ github.event_name == 'pull_request' && "
    "format('pr-{0}', github.event.pull_request.number) || "
    "format('push-{0}', github.sha) }}",
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}
EXPECTED_JOBS = {
    "lint-and-test": {
        "if": SAME_REPOSITORY_ONLY,
        "runs-on": LINUX_RUNS_ON,
        "timeout-minutes": 30,
        "strategy": {"matrix": {"python-version": ["3.11", "3.12", "3.13", "3.14"]}},
        "steps": [
            CHECKOUT,
            setup_python("${{ matrix.python-version }}"),
            VENV_STEP,
            {"run": "python -m pip install -e '.[dev]'"},
            {"run": "python -m ruff check ."},
            {"run": "python tools/run_tests.py discover -s tests -v"},
        ],
    },
    "macos-native": {
        "if": SAME_REPOSITORY_ONLY,
        "runs-on": MACOS_RUNS_ON,
        "timeout-minutes": 15,
        "steps": [
            {
                "name": "Require macOS runner with Xcode toolchain",
                "run": 'test "$RUNNER_OS" = macOS\n'
                "command -v xcrun\n"
                "command -v swiftc\n",
            },
            CHECKOUT,
            setup_python("3.14"),
            VENV_STEP,
            {"run": "python -m pip install -e '.[dev]'"},
            {
                "name": "Run full macOS suite including compiled Swift self-test",
                "run": "export TMPDIR=\"$(python -c 'import os,tempfile; "
                "print(os.path.realpath(tempfile.gettempdir()))')\"\n"
                "python tools/run_tests.py discover -s tests -v\n",
            },
        ],
    },
    "dependency-audit": {
        "if": SAME_REPOSITORY_ONLY,
        "runs-on": LINUX_RUNS_ON,
        "timeout-minutes": 10,
        "steps": [
            CHECKOUT,
            setup_python("3.14"),
            VENV_STEP,
            {"run": "python -m pip install pip-audit==2.10.1"},
            {
                "name": "Resolve and audit declared dependencies",
                "run": "python -c 'import tomllib; "
                'p=tomllib.load(open("pyproject.toml","rb")); d=p["project"]; '
                'req=p["build-system"]["requires"]+d["dependencies"]'
                '+sum(d["optional-dependencies"].values(), []); '
                'print("\\n".join(dict.fromkeys(req)))\' > audit-requirements.txt\n'
                "python -m pip_audit --strict --progress-spinner off "
                "-r audit-requirements.txt\n",
            },
        ],
    },
    "release-artifact": {
        "needs": ["lint-and-test", "macos-native", "dependency-audit"],
        "if": EXPECTED_RELEASE_IF,
        "runs-on": LINUX_RUNS_ON,
        "timeout-minutes": 15,
        "steps": [
            {
                "name": "Require successful platform and audit prerequisites",
                "env": {
                    "LINUX_RESULT": "${{ needs.lint-and-test.result }}",
                    "MACOS_RESULT": "${{ needs.macos-native.result }}",
                    "AUDIT_RESULT": "${{ needs.dependency-audit.result }}",
                },
                "run": 'test "$LINUX_RESULT" = success\n'
                'test "$MACOS_RESULT" = success\n'
                'test "$AUDIT_RESULT" = success\n',
            },
            CHECKOUT,
            setup_python("3.12"),
            VENV_STEP,
            {"run": "python -m pip install -e '.[release]'"},
            {
                "run": "rm -rf dist\n"
                "python -m pip wheel --no-deps --no-build-isolation "
                "--wheel-dir dist .\n"
            },
            {
                "run": "python tools/verify_release_artifact.py "
                "dist/gargoyl-0.1.0-py3-none-any.whl"
            },
            {
                "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                "with": {
                    "name": "gargoyl-wheel-${{ github.sha }}",
                    "path": "dist/*.whl",
                    "if-no-files-found": "error",
                },
            },
        ],
    },
}


def validate_workflow_invariants(doc):
    """Require the workflow to match the reviewed self-hosted routing exactly.

    Exact matching closes the escapes a substring or index check leaves open:
    workflow- or job-level defaults (a run.shell override drops -e), container
    or services, matrix include/exclude, extra job-level if, appended `|| true`,
    reordered build/verify/upload steps, unpinned or non-allowlisted actions,
    and persisted checkout credentials.
    """
    if not isinstance(doc, dict):
        raise AssertionError("Workflow document must be a mapping")
    if True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    if set(doc) != {"name", "on", "permissions", "concurrency", "jobs"}:
        raise AssertionError(
            f"Unexpected top-level workflow keys: {sorted(map(str, doc))}"
        )
    if doc["permissions"] != {"contents": "read"}:
        raise AssertionError("Root permissions must be exactly contents: read")
    if doc["on"] != EXPECTED_TRIGGERS:
        raise AssertionError(
            f"Triggers must be exactly {EXPECTED_TRIGGERS}: {doc['on']}"
        )
    if doc["concurrency"] != EXPECTED_CONCURRENCY:
        raise AssertionError(
            "Concurrency must cancel only superseded PR runs, never main validation"
        )
    jobs = doc["jobs"]
    if not isinstance(jobs, dict) or set(jobs) != set(EXPECTED_JOBS):
        raise AssertionError(
            f"Jobs mismatch: {jobs if not isinstance(jobs, dict) else sorted(jobs)}"
        )
    for job_name, expected in EXPECTED_JOBS.items():
        job = jobs[job_name]
        if not isinstance(job, dict):
            raise AssertionError(f"Job {job_name} must be a mapping")
        runs_on = job.get("runs-on")
        labels = set(runs_on) if isinstance(runs_on, list) else {runs_on}
        if labels & GENERIC_RUNNER_LABELS:
            raise AssertionError(
                f"Job {job_name} uses a generic runner selector: {runs_on}"
            )
        if set(job) != set(expected):
            raise AssertionError(
                f"Job {job_name} keys {sorted(job)} != {sorted(expected)}"
            )
        for key in expected:
            if key == "steps":
                continue
            if job[key] != expected[key]:
                raise AssertionError(
                    f"Job {job_name} {key}: {job[key]!r} != {expected[key]!r}"
                )
        steps = job["steps"]
        if not isinstance(steps, list) or len(steps) != len(expected["steps"]):
            raise AssertionError(
                f"Job {job_name} must have exactly {len(expected['steps'])} steps"
            )
        for index, (step, expected_step) in enumerate(zip(steps, expected["steps"])):
            uses = step.get("uses") if isinstance(step, dict) else None
            if uses is not None and not ALLOWED_ACTION.match(uses):
                raise AssertionError(
                    f"Job {job_name} step {index} uses non-allowlisted action {uses!r}"
                )
            if step != expected_step:
                raise AssertionError(
                    f"Job {job_name} step {index} mismatch: {step!r} != {expected_step!r}"
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

        def mutant(mutate):
            doc = yaml.safe_load(yaml.dump(base_doc))
            mutate(doc)
            return doc

        def drop_fork_guard(doc):
            del doc["jobs"]["lint-and-test"]["if"]

        def persist_credentials(doc):
            doc["jobs"]["dependency-audit"]["steps"][0]["with"][
                "persist-credentials"
            ] = True

        def drop_venv(doc):
            doc["jobs"]["release-artifact"]["steps"].pop(3)

        def or_true(doc):
            doc["jobs"]["dependency-audit"]["steps"][4]["run"] += "|| true\n"

        def unpinned_action(doc):
            doc["jobs"]["lint-and-test"]["steps"][0]["uses"] = "actions/checkout@v4"

        def foreign_action(doc):
            doc["jobs"]["macos-native"]["steps"].insert(
                0, {"uses": "evil/action@" + "a" * 40}
            )

        def swap_verify_and_upload(doc):
            steps = doc["jobs"]["release-artifact"]["steps"]
            steps[6], steps[7] = steps[7], steps[6]

        new_mutants = {
            "generic self-hosted label": lambda d: d["jobs"]["lint-and-test"].update(
                {"runs-on": ["self-hosted", "linux"]}
            ),
            "hard-coded runner label": lambda d: d["jobs"]["macos-native"].update(
                {"runs-on": "local-ci-unreviewed"}
            ),
            "workflow defaults.run.shell": lambda d: d.update(
                defaults={"run": {"shell": "bash {0}"}}
            ),
            "job defaults.run.shell": lambda d: d["jobs"]["release-artifact"].update(
                defaults={"run": {"shell": "bash {0}"}}
            ),
            "job container": lambda d: d["jobs"]["dependency-audit"].update(
                container="python:3.14"
            ),
            "matrix include": lambda d: d["jobs"]["lint-and-test"]["strategy"][
                "matrix"
            ].update(include=[{"python-version": "3.10"}]),
            "cancel main validation": lambda d: d["concurrency"].update(
                {"cancel-in-progress": True}
            ),
            "dropped concurrency": lambda d: d.pop("concurrency"),
            "fork PR guard removed": drop_fork_guard,
            "checkout persists credentials": persist_credentials,
            "job-local venv removed": drop_venv,
            "audit || true": or_true,
            "unpinned action": unpinned_action,
            "non-allowlisted action": foreign_action,
            "upload before verify": swap_verify_and_upload,
            "release timeout removed": lambda d: d["jobs"]["release-artifact"].pop(
                "timeout-minutes"
            ),
            "macOS runner check removed": lambda d: d["jobs"]["macos-native"][
                "steps"
            ].pop(0),
            "macOS runner check weakened": lambda d: d["jobs"]["macos-native"]["steps"][
                0
            ].update({"run": "command -v xcrun || true\n"}),
        }
        for desc, mutate in new_mutants.items():
            with self.subTest(mutant=desc):
                assert_mutant_fails(mutant(mutate), desc)

    def test_action_and_script_graph_digests(self):
        digests = {
            "pyproject.toml": "10f1a10cc95e3b8e2ec5b0931b91f580fe3061f7a00eeac2f4d4215555db3b69",
            "README.md": "db1efae68d13c78a7fa51de7ae257b6fb68c32b72d3721f51ff80b7ca0d12af2",
            "tools/run_tests.py": "522456210ef5c77d9109388e12088ab4695ed203af8f2f491327b8c9a3f9977f",
            "tools/verify_release_artifact.py": (
                "eec6c171586a8acb7b52914e04b1209e01a929a2dbd6afd5bdeee65ffbe264a7"
            ),
            "tools/build_macos_app.py": (
                "dbde43749c11f3229b9acae666bcf0d410d1bfc220a67793040bfc4fce153a54"
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
        doc = load_workflow()
        linux = "local-ci-b6b0a4fed6586b3a"
        identity = b"github:nhangen/gargoyl:ml1-wsl"
        self.assertEqual(linux, "local-ci-" + hashlib.sha256(identity).hexdigest()[:16])
        self.assertEqual(doc["jobs"]["lint-and-test"]["runs-on"], linux)
        self.assertEqual(
            doc["jobs"]["macos-native"]["runs-on"],
            "${{ vars.GARGOYL_MACOS_RUNNER_LABEL }}",
        )
        self.assertEqual(doc["jobs"]["dependency-audit"]["runs-on"], linux)
        self.assertEqual(doc["jobs"]["release-artifact"]["runs-on"], linux)
        self.assertEqual(doc["jobs"]["release-artifact"]["if"], EXPECTED_RELEASE_IF)

        # 2. Verify preflight tool's actual PROPOSED_LOCAL_ROUTING contract
        self.assertEqual(PROPOSED_LOCAL_ROUTING["profile"], "nhangen/local-ci")
        self.assertEqual(PROPOSED_LOCAL_ROUTING["flags"], "--no-default-labels")
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["target_label_state"], "DERIVED_NOT_ENROLLED"
        )
        self.assertEqual(PROPOSED_LOCAL_ROUTING["target_label"], linux)
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["target_label_identity"], identity.decode()
        )
        self.assertEqual(PROPOSED_LOCAL_ROUTING["macos_jobs"], ["macos-native"])
        self.assertEqual(
            PROPOSED_LOCAL_ROUTING["macos_label_variable"], "GARGOYL_MACOS_RUNNER_LABEL"
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
            data["proposed_routing"]["target_label_state"], "DERIVED_NOT_ENROLLED"
        )
        self.assertFalse(data["deployment_ready"])
        self.assertEqual(data["held_gates_count"], 12)
        self.assertNotIn("preserved_gates_count", data)

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
        self.assertFalse(full_report["readiness"]["macos_runner_enrollment"])

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

        def persist_release_checkout(doc):
            doc["jobs"]["release-artifact"]["steps"][1]["with"][
                "persist-credentials"
            ] = True

        def add_preview_builder_step(doc):
            steps = doc["jobs"]["release-artifact"]["steps"]
            steps.append(
                {
                    "run": "python tools/build_macos_app.py --output /tmp/app --python /tmp/py\n"
                }
            )

        mutations = {
            "permissions_read_only": lambda doc: doc.update(
                permissions={"contents": "write"}
            ),
            "self_hosted_routing": lambda doc: doc["jobs"]["lint-and-test"].update(
                {"runs-on": "self-hosted"}
            ),
            "release_needs_all_three": drop_audit_need,
            "release_if_always": lambda doc: doc["jobs"]["release-artifact"].update(
                {"if": "${{ success() }}"}
            ),
            "checkout_credentials_not_persisted": persist_release_checkout,
            "main_validation_not_cancelled": lambda doc: doc["concurrency"].update(
                {"cancel-in-progress": True}
            ),
            "release_builder_uses_native_actions": add_preview_builder_step,
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

    def test_release_builder_check_scopes_to_release_job_and_each_invocation(self):
        def verdict(job, run):
            doc = load_workflow()
            doc["jobs"][job]["steps"].append({"run": run})
            return preflight_mod._release_builder_uses_native_actions(doc)

        builder = "python tools/build_macos_app.py --output /tmp/app --python /tmp/py"
        self.assertTrue(verdict("macos-native", builder + "\n"))
        self.assertTrue(verdict("lint-and-test", builder + "\n"))
        self.assertTrue(
            verdict("release-artifact", builder + " --enable-native-actions\n")
        )
        self.assertTrue(
            verdict(
                "release-artifact",
                "python tools/build_macos_app.py --output /tmp/app \\\n"
                "  --python /tmp/py --enable-native-actions\n",
            )
        )
        self.assertTrue(
            verdict(
                "release-artifact", builder + ' "--enable-native-actions" | tee log\n'
            )
        )
        rejected = {
            "flag_only_in_comment": builder + "  # --enable-native-actions\n",
            "flag_only_in_echo": "echo --enable-native-actions\n" + builder + "\n",
            "second_call_unflagged": builder
            + " --enable-native-actions\n"
            + builder
            + "\n",
            "module_invocation": "python -m tools.build_macos_app --output /tmp/app --python /tmp/py\n",
            "flag_prefix_only": builder + " --enable-native-actions-later\n",
            "quoted_hash_before_call": 'echo "#"; ' + builder + "\n",
            "dollar_hash_before_call": "[ $# -eq 0 ] && " + builder + "\n",
            "flag_on_later_command": builder + "; echo --enable-native-actions\n",
            "unbalanced_quote": builder + ' --enable-native-actions "\n',
        }
        for name, run in rejected.items():
            with self.subTest(case=name):
                self.assertFalse(verdict("release-artifact", run))

    def test_builder_stamps_build_mode_fails_closed(self):
        """Verify that removing GargoylBuildMode from the builder fails the preflight gate."""
        builder_path = REPO_ROOT / "tools" / "build_macos_app.py"
        original = builder_path.read_text(encoding="utf-8")
        stripped = original.replace("GargoylBuildMode", "GargoylRemovedKey")
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_repo = Path(tmpdir) / "repo"
            fake_tools = fake_repo / "tools"
            fake_tools.mkdir(parents=True)
            (fake_tools / "build_macos_app.py").write_text(stripped, encoding="utf-8")
            with mock.patch.object(preflight_mod, "REPO_ROOT", fake_repo):
                self.assertFalse(preflight_mod._builder_stamps_build_mode())
        self.assertTrue(preflight_mod._builder_stamps_build_mode())


if __name__ == "__main__":
    unittest.main()
