"""Preflight verification tool for Gargoyl CI workflow, graph integrity, and runner compatibility.

CLI Modes and Exit Codes:
  --check-source     Verify static repository source contracts and graph digests.
                     Exit 0 on success; Exit 1 on contract violation.
  --check-readiness  Evaluate deployment rollout readiness against static recorded infrastructure gates (not live evidence evaluation).
                     Exit 0 if fully ready; Exit 1 on contract violation; Exit 3 if held/blocked.
  --check            Run both source verification and static recorded readiness evaluation.
                     Exit 0 only if fully ready; Exit 1 on contract violation;
                     Exit 3 if source contracts pass but rollout is held.
  --manifest-only    Print declared dependencies extracted from pyproject.toml manifest.
  --json             Output machine-readable JSON report.

Exit Codes:
  0: Success / fully ready
  1: Source contract or graph integrity violation
  2: Command-line usage error or conflicting arguments (argparse error)
  3: Source contracts passed, but deployment rollout readiness is held / blocked
"""

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_YML_PATH = Path(
    os.environ.get(
        "GARGOYL_CI_WORKFLOW_PATH", str(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    )
)
PYPROJECT_PATH = Path(
    os.environ.get("GARGOYL_PYPROJECT_PATH", str(REPO_ROOT / "pyproject.toml"))
)

EXIT_READY = 0
EXIT_CONTRACT_FAILED = 1
EXIT_USAGE_ERROR = 2
EXIT_HELD_BLOCKED = 3

EXPECTED_DIGESTS = {
    ".github/workflows/ci.yml": {
        "sha256": "d43e5301610a1d318b5094c16bfa86d54d2915ec86ed89b35c9c7a9b08d700c4",
        "git": "f6eebc0e70045d4333cdd8bc611d7abce63011f3",
    },
    "pyproject.toml": {
        "sha256": "10f1a10cc95e3b8e2ec5b0931b91f580fe3061f7a00eeac2f4d4215555db3b69",
        "git": "643f86a81242779294bd52355060ab4be8efe214",
    },
    "README.md": {
        "sha256": "55aca4614bec89ce81cb992d3edfc09f59185184132ae9942c47f3c2bca78dc4",
        "git": "ced6a4aeb1ae68d87fe2d7a345a98fcdbb84e33e",
    },
    "tools/run_tests.py": {
        "sha256": "522456210ef5c77d9109388e12088ab4695ed203af8f2f491327b8c9a3f9977f",
        "git": "68232f9278ee542cd1f5fa2f0463e8c30e0863ae",
    },
    "tools/verify_release_artifact.py": {
        "sha256": "eec6c171586a8acb7b52914e04b1209e01a929a2dbd6afd5bdeee65ffbe264a7",
        "git": "ed3bff4559b8bd9e6cc879247a9e256b38aaf806",
    },
    "tools/build_macos_app.py": {
        "sha256": "dbde43749c11f3229b9acae666bcf0d410d1bfc220a67793040bfc4fce153a54",
        "git": "2996bcb2b028142ffa2b7403854530b7c6d9d759",
    },
    "tools/offline_acceptance_evidence.py": {
        "sha256": "1447cd6f98336efa34d23e6bfc411d2ae6498c011c7abd0f76aa6b5e8f2c8734",
        "git": "8dcabdfffcad123a1bb81a07ac2bd011198679b8",
    },
}

HELD_GATES = [
    {
        "gate": "local_fleet_capacity",
        "status": "HELD",
        "reason": "Fleet capacity recorded historical snapshot of 28/28 CPUs and 46/48 GiB memory remains unverified current capacity without allowlisted receipt; proposed Tron resize is unapproved; container sizing is unmeasured candidate estimate.",
    },
    {
        "gate": "repository_enrollment",
        "status": "HELD",
        "reason": "GitHub reports 0 repository runners; Gargoyl is not enrolled in the nhangen/local-ci fleet. The Linux jobs target the derived label local-ci-b6b0a4fed6586b3a (github:nhangen/gargoyl on ml1-wsl), but no runner carries it, so they queue until enrollment.",
    },
    {
        "gate": "branch_protection_visibility",
        "status": "HELD",
        "reason": "Branch-protection API returned HTTP 403; required check constraints remain unconfirmed.",
    },
    {
        "gate": "linux_matrix_runtime",
        "status": "HELD",
        "reason": "Linux Python 3.11–3.14 installation and test execution in container/runner profile not performed (Python 3.11 absent locally; unverified on Linux).",
    },
    {
        "gate": "strict_vulnerability_audit",
        "status": "HELD",
        "reason": "Live network pip-audit --strict over fully resolved transitive dependency tree (including PyYAML 6.0.2) not performed.",
    },
    {
        "gate": "release_packaging_and_verification",
        "status": "HELD",
        "reason": "Wheel build, verify_release_artifact.py, and upload-artifact compatibility in intended unprivileged runner profile not performed.",
    },
    {
        "gate": "container_unprivileged_profile",
        "status": "HELD",
        "reason": "Execution under non-root unprivileged container profile with dropped capabilities (capDropALL unverified; no Docker daemon; no host Docker socket) not validated.",
    },
    {
        "gate": "hosted_pipeline_equivalence",
        "status": "HELD",
        "reason": "Direct execution equivalence between local runner environment and hosted GitHub Actions runners not verified.",
    },
    {
        "gate": "fork_pr_and_state_isolation",
        "status": "HELD",
        "reason": "The local-ci GitHub profile is a persistent (not ephemeral) non-root container with no host bind mounts or Docker socket, one repository per runner. The fork boundary is the repository setting that disables workflows from fork PRs, which is unconfirmed; the same-repository guard is defense in depth because a fork PR runs its own workflow file. The runner HOME, workspace, setup-python tool cache and leftover processes persist between jobs, so a same-repository PR can change state (for example pip.conf or .gitconfig) that a later main or release job reuses. Per-job runner replacement, or a fresh HOME, workspace and tool cache per job, is not available in the profile.",
    },
    {
        "gate": "python314_pyyaml_sdist_build_risk",
        "status": "HELD",
        "reason": "The local macOS cp314 PyYAML 6.0.2 install was built from source (installed WHEEL metadata names setuptools as generator), which proves a local source build only. Whether a published cp314 wheel exists was not checked (offline), and Linux resolution, sdist compilation, and build inputs remain unverified.",
    },
    {
        "gate": "macos_native_full_suite_local_proof",
        "status": "HELD",
        "reason": "The full suite including tests/test_native_app.py and the compiled Swift self-test was not executed at the current head: native, Keychain, and Security paths are prohibited locally until a separately approved isolated boundary exists. The last local full-suite result (612 tests, macOS Python 3.14.7) is from older code head 38a4636.",
    },
    {
        "gate": "macos_runner_enrollment",
        "status": "HELD",
        "reason": "macos-native routes to a self-hosted macOS runner selected by vars.GARGOYL_MACOS_RUNNER_LABEL. No macOS runner is enrolled, the variable is unset, and the Keychain/login-session isolation boundary the native suite needs on that host is unapproved.",
    },
]

PROPOSED_LOCAL_ROUTING = {
    "profile": "nhangen/local-ci",
    "flags": "--no-default-labels",
    "target_label": "local-ci-b6b0a4fed6586b3a",
    "target_label_identity": "github:nhangen/gargoyl:ml1-wsl",
    "target_label_state": "DERIVED_NOT_ENROLLED",
    "macos_label_variable": "GARGOYL_MACOS_RUNNER_LABEL",
    "linux_jobs": ["lint-and-test", "dependency-audit", "release-artifact"],
    "macos_jobs": ["macos-native"],
}

LINUX_RUNS_ON = "local-ci-b6b0a4fed6586b3a"
MACOS_RUNS_ON = "${{ vars.GARGOYL_MACOS_RUNNER_LABEL }}"
EXPECTED_CONCURRENCY = {
    "group": "ci-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || format('push-{0}', github.sha) }}",
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}
EXPECTED_RELEASE_IF = (
    "${{ always() && (github.event_name == 'push' || "
    "github.event.pull_request.head.repo.full_name == github.repository) }}"
)


def extract_declared_dependencies():
    """Extract declared dependencies from pyproject.toml manifest without resolution."""
    with open(PYPROJECT_PATH, "rb") as f:
        p = tomllib.load(f)
    d = p["project"]
    req = (
        p["build-system"]["requires"]
        + d["dependencies"]
        + sum(d["optional-dependencies"].values(), [])
    )
    return list(dict.fromkeys(req))


def verify_graph_digests():
    """Verify cryptographic SHA-256 and Git object hashes of action graph files."""
    results = {}
    all_ok = True
    for rel_path, expected in EXPECTED_DIGESTS.items():
        file_path = REPO_ROOT / rel_path
        if not file_path.is_file():
            results[rel_path] = {"status": "missing"}
            all_ok = False
            continue
        data = file_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        git_sha = subprocess.check_output(
            ["git", "hash-object", str(file_path)], text=True
        ).strip()
        sha_ok = sha256 == expected["sha256"]
        git_ok = git_sha == expected["git"]
        if not (sha_ok and git_ok):
            all_ok = False
        results[rel_path] = {
            "sha256_match": sha_ok,
            "git_match": git_ok,
            "actual_sha256": sha256,
            "actual_git": git_sha,
        }
    return all_ok, results


def inspect_environment():
    """Inspect local runtime environment and available tools."""
    pythons = {}
    for ver in ("3.11", "3.12", "3.13", "3.14"):
        exe = shutil.which(f"python{ver}")
        pythons[ver] = exe if exe else "absent"

    current_tmpdir = os.environ.get("TMPDIR", "")
    canonical_tmpdir = os.path.realpath(tempfile.gettempdir())
    tmpdir_is_canonical = bool(current_tmpdir) and (
        current_tmpdir == os.path.realpath(current_tmpdir)
    )

    swiftc = shutil.which("swiftc")
    xcrun = shutil.which("xcrun")

    return {
        "platform": sys.platform,
        "machine": platform.machine(),
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "pyyaml_version": getattr(yaml, "__version__", "unknown"),
        "matrix_pythons": pythons,
        "canonical_tmpdir": canonical_tmpdir,
        "tmpdir_is_canonical": tmpdir_is_canonical,
        "has_swiftc": bool(swiftc),
        "has_xcrun": bool(xcrun),
        "ruff_available": bool(shutil.which("ruff")),
    }


def _builder_stamps_build_mode() -> bool:
    """Verify the builder source still names the GargoylBuildMode Info.plist key.

    The builder writes the key on every build ('preview' by default,
    'native-actions' with --enable-native-actions). This is a coarse backstop
    to the EXPECTED_DIGESTS pin on the builder; the per-mode value is asserted
    by tests/test_native_bundle.py.
    """
    builder_path = REPO_ROOT / "tools" / "build_macos_app.py"
    if not builder_path.is_file():
        return False
    try:
        source = builder_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return "GargoylBuildMode" in source


_SHELL_SEPARATORS = frozenset(";&|")


def _shell_commands(line: str):
    """Split one shell line into commands, dropping a trailing comment.

    Non-POSIX shlex keeps quotes on tokens, so only an unquoted word that
    starts with '#' begins a comment, as in the shell; '$#' and a quoted '#'
    stay literal. Raises ValueError on an unbalanced quote.
    """
    lexer = shlex.shlex(line, posix=False, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    command = []
    for token in lexer:
        if token.startswith("#"):
            break
        if set(token) <= _SHELL_SEPARATORS:
            if command:
                yield command
            command = []
            continue
        command.append(token.strip("\"'"))
    if command:
        yield command


def _release_builder_uses_native_actions(workflow_doc: dict) -> bool:
    """Verify each builder command in the release-artifact job passes --enable-native-actions.

    Other jobs may build preview bundles. Each shell command is judged on its
    own, after joining backslash continuations and dropping comments, so a
    flag in a comment, an echo, or another command cannot vouch for a builder
    call; an unparseable line fails closed. Passes vacuously while ci.yml
    builds only a wheel. Builder calls hidden behind a script, a composite
    action, or a non-shell step are not visible to this check.
    """
    release_job = workflow_doc.get("jobs", {}).get("release-artifact", {})
    if not isinstance(release_job, dict):
        return False
    for step in release_job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        script = str(step.get("run", "")).replace("\\\n", " ")
        for line in script.splitlines():
            try:
                commands = list(_shell_commands(line))
            except ValueError:
                return False
            for command in commands:
                if not any("build_macos_app" in token for token in command):
                    continue
                if "--enable-native-actions" not in command:
                    return False
    return True


def verify_workflow_contracts():
    """Verify production workflow contract invariants."""
    if not CI_YML_PATH.is_file():
        return False, {"error": f"Workflow file missing: {CI_YML_PATH}"}
    try:
        raw = yaml.safe_load(CI_YML_PATH.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as err:
        return False, {"error": f"Failed to parse workflow: {err}"}
    if not isinstance(raw, dict):
        return False, {"error": "Workflow root is not a mapping"}

    jobs = raw.get("jobs", {})
    lint_job = jobs.get("lint-and-test", {})
    macos_job = jobs.get("macos-native", {})
    audit_job = jobs.get("dependency-audit", {})
    release_job = jobs.get("release-artifact", {})

    checkout_steps = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]

    checks = {
        "permissions_read_only": raw.get("permissions") == {"contents": "read"},
        "self_hosted_routing": (
            lint_job.get("runs-on") == LINUX_RUNS_ON
            and audit_job.get("runs-on") == LINUX_RUNS_ON
            and release_job.get("runs-on") == LINUX_RUNS_ON
            and macos_job.get("runs-on") == MACOS_RUNS_ON
        ),
        "release_needs_all_three": set(release_job.get("needs", []))
        == {"lint-and-test", "macos-native", "dependency-audit"},
        "release_if_always": release_job.get("if") == EXPECTED_RELEASE_IF,
        "checkout_credentials_not_persisted": len(checkout_steps) == 4
        and all(
            (step.get("with") or {}).get("persist-credentials") is False
            for step in checkout_steps
        ),
        "main_validation_not_cancelled": raw.get("concurrency") == EXPECTED_CONCURRENCY,
        "builder_stamps_build_mode": _builder_stamps_build_mode(),
        "release_builder_uses_native_actions": _release_builder_uses_native_actions(
            raw
        ),
    }
    all_passed = all(checks.values())
    return all_passed, checks


def evaluate_deployment_readiness(source_ok):
    """Evaluate rollout readiness against static recorded infrastructure gates.

    Note: Readiness is a static recorded gate state, not live evidence evaluation.
    Requires all static source contracts/graph integrity to pass AND all recorded
    infrastructure gates to be satisfied. Every HELD_GATES entry participates.
    """
    gate_status = {}
    for entry in HELD_GATES:
        gate_name = entry["gate"]
        status = entry["status"]
        gate_status[gate_name] = status == "VERIFIED"

    all_gates_ok = all(gate_status.values())
    is_ready = all_gates_ok and bool(source_ok)
    return is_ready, gate_status


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Gargoyl CI preflight & verification (evaluates static source contracts and static recorded gate state)"
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--check",
        action="store_true",
        help="Run source contract verification and static recorded gate checks (exits 3 while rollout gates held; exits 1 on contract violation)",
    )
    mode_group.add_argument(
        "--check-source",
        action="store_true",
        help="Verify static repository source contracts and graph digests only (exits 0 on success; exits 1 on contract failure)",
    )
    mode_group.add_argument(
        "--check-readiness",
        action="store_true",
        help="Evaluate deployment readiness against static recorded infrastructure gates (exits 3 while held; exits 1 on contract violation)",
    )
    mode_group.add_argument(
        "--manifest-only",
        action="store_true",
        help="Print declared dependencies extracted from pyproject.toml",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON"
    )
    args = parser.parse_args(argv)

    if args.manifest_only:
        deps = extract_declared_dependencies()
        if args.json:
            print(json.dumps({"declared_dependencies": deps}, indent=2))
        else:
            print("\n".join(deps))
        return EXIT_READY

    env = inspect_environment()
    graph_ok, graph_results = verify_graph_digests()
    contracts_ok, contract_results = verify_workflow_contracts()
    source_ok = contracts_ok and graph_ok
    ready_ok, readiness_results = evaluate_deployment_readiness(source_ok=source_ok)
    deps = extract_declared_dependencies()

    held_count = sum(1 for g in HELD_GATES if g["status"] == "HELD")

    report = {
        "source_contracts_passed": source_ok,
        "deployment_ready": ready_ok,
        "contracts": contract_results,
        "digests": graph_results,
        "readiness": readiness_results,
        "environment": env,
        "declared_dependencies": deps,
        "proposed_routing": PROPOSED_LOCAL_ROUTING,
        "held_gates": HELD_GATES,
        "held_gates_count": held_count,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=== Gargoyl CI Preflight & Verification Report (Issue #82) ===")
        print(f"Source Contracts:     {'PASS' if source_ok else 'FAIL'}")
        print(
            "                      (Static source verification; does NOT imply rollout readiness)"
        )
        if ready_ok:
            readiness_text = "READY"
        elif not source_ok:
            readiness_text = (
                f"BLOCKED (source contracts failed; {held_count} held gates)"
            )
        else:
            readiness_text = f"BLOCKED ({held_count} held gates)"
        print(f"Deployment Readiness: {readiness_text}")
        print(
            f"Current Python:       {env['python_version']} ({env['python_executable']})"
        )
        print(f"PyYAML Version:       {env['pyyaml_version']}")
        print(f"Matrix Pythons:       {env['matrix_pythons']}")
        print(
            f"macOS SDK Tools:      xcrun={env['has_xcrun']}, swiftc={env['has_swiftc']}"
        )
        routing_text = (
            f"self-hosted: Linux {LINUX_RUNS_ON}, macOS vars.GARGOYL_MACOS_RUNNER_LABEL"
            if contracts_ok
            else "workflow routing contract FAILED"
        )
        print(f"Routing Status:       {routing_text} (0 repo runners enrolled)")
        print(
            f"Target Custom Label:  {PROPOSED_LOCAL_ROUTING['target_label']} {PROPOSED_LOCAL_ROUTING['target_label_state']} (under {PROPOSED_LOCAL_ROUTING['flags']})"
        )
        print(f"Held Gates Count:     {held_count} held")

    if args.check_source:
        return EXIT_READY if source_ok else EXIT_CONTRACT_FAILED

    if args.check_readiness:
        if not source_ok:
            return EXIT_CONTRACT_FAILED
        return EXIT_READY if ready_ok else EXIT_HELD_BLOCKED

    # Default --check mode: Requires both source contracts AND deployment readiness
    if not source_ok:
        return EXIT_CONTRACT_FAILED
    if not ready_ok:
        return EXIT_HELD_BLOCKED
    return EXIT_READY


if __name__ == "__main__":
    raise SystemExit(main())
