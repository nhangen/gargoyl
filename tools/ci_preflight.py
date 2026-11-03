"""Preflight verification tool for Gargoyl CI workflow, graph integrity, and runner compatibility.

CLI Modes and Exit Codes:
  --check-source    Verify static repository source contracts and graph digests.
                    Exit 0 on success; Exit 1 on contract violation.
  --check-readiness Evaluate deployment rollout readiness against infrastructure gates.
                    Exit 0 if fully ready; Exit 2 if held/blocked.
  --check           Run both source verification and readiness evaluation.
                    Exit 0 only if fully ready; Exit 2 if contracts pass but rollout held;
                    Exit 1 on contract violation.
  --manifest-only   Print declared dependencies extracted from pyproject.toml manifest.
  --json            Output machine-readable JSON report.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_YML_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

EXIT_READY = 0
EXIT_CONTRACT_FAILED = 1
EXIT_HELD_BLOCKED = 2

EXPECTED_DIGESTS = {
    ".github/workflows/ci.yml": {
        "sha256": "1e7c8eda685a3765f2eb1fc47e5ab34a17416913459cc47d72a5e99dd3a78d0b",
        "git": "545f03c2df66a9f9feb72aaa7cf425dca8f40bb2",
    },
    "pyproject.toml": {
        "sha256": "10f1a10cc95e3b8e2ec5b0931b91f580fe3061f7a00eeac2f4d4215555db3b69",
        "git": "643f86a81242779294bd52355060ab4be8efe214",
    },
    "README.md": {
        "sha256": "c1ba02440f8c5cfa07c5457f57b03110f5148e33a6e8aeec8c9aa6c6d197469b",
        "git": "82cf909595abbfb1e469ec85b0063abfbabad1e6",
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
        "sha256": "9627562a2ac1ac3ccf909fd75b07ae8844034d7065fc1e0a6d85434893d375f5",
        "git": "a502c81700737257a7ba0562353bb56537621d29",
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
        "reason": "Current fleet allocation saturated at 28/28 CPUs and 46/48 GiB memory; proposed Tron resize is unapproved.",
    },
    {
        "gate": "repository_enrollment",
        "status": "HELD",
        "reason": "GitHub reports 0 repository runners; Gargoyl is not enrolled in the nhangen/local-ci fleet.",
    },
    {
        "gate": "branch_protection_read",
        "status": "HELD",
        "reason": "Branch-protection API returned HTTP 403; concrete required check constraints remain unconfirmed.",
    },
    {
        "gate": "macos_native_retained",
        "status": "PRESERVED_ON_HOSTED",
        "reason": "macos-native requires real macOS Darwin host with Swift/AppKit/WebKit; retained on hosted macos-15.",
    },
]

PROPOSED_LOCAL_ROUTING = {
    "profile": "nhangen/local-ci",
    "flags": "--no-default-labels",
    "target_label": "UNRESOLVED_HELD (opaque unique custom label local-ci-<hash> assigned upon enrollment; 0 runners currently enrolled)",
    "target_label_state": "UNRESOLVED_HELD",
    "linux_jobs": ["lint-and-test", "dependency-audit", "release-artifact"],
    "macos_jobs_excluded": ["macos-native"],
}


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
    tmpdir_is_canonical = (
        os.path.realpath(current_tmpdir) == canonical_tmpdir
        if current_tmpdir
        else False
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


def verify_workflow_contracts():
    """Verify production workflow contract invariants."""
    raw = yaml.safe_load(CI_YML_PATH.read_text(encoding="utf-8"))
    if True in raw and "on" not in raw:
        raw["on"] = raw[True]

    checks = {
        "permissions_read_only": raw.get("permissions") == {"contents": "read"},
        "has_lint_and_test": "lint-and-test" in raw.get("jobs", {}),
        "has_macos_native": "macos-native" in raw.get("jobs", {}),
        "has_dependency_audit": "dependency-audit" in raw.get("jobs", {}),
        "has_release_artifact": "release-artifact" in raw.get("jobs", {}),
        "current_routing_intact": (
            raw["jobs"]["lint-and-test"]["runs-on"] == "ubuntu-latest"
            and raw["jobs"]["macos-native"]["runs-on"] == "macos-15"
            and raw["jobs"]["dependency-audit"]["runs-on"] == "ubuntu-latest"
            and raw["jobs"]["release-artifact"]["runs-on"] == "ubuntu-latest"
        ),
        "release_needs_all_three": set(raw["jobs"]["release-artifact"].get("needs", []))
        == {"lint-and-test", "macos-native", "dependency-audit"},
        "release_if_always": raw["jobs"]["release-artifact"].get("if")
        == "${{ always() }}",
        "macos_native_retained_on_macos_15": raw["jobs"]["macos-native"]["runs-on"]
        == "macos-15",
    }
    all_passed = all(checks.values())
    return all_passed, checks


def evaluate_deployment_readiness():
    """Evaluate rollout readiness against infrastructure gates."""
    # Saturated fleet capacity, 0 enrolled runners, and denied branch protection mean rollout is blocked.
    readiness = {
        "fleet_capacity_approved": False,
        "repository_enrolled": False,
        "branch_protection_confirmed": False,
        "macos_native_isolation_approved": True,  # retained on macos-15 hosted
    }
    is_ready = all(readiness.values())
    return is_ready, readiness


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gargoyl CI preflight & verification")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--check",
        action="store_true",
        help="Run both source contract and readiness checks (exits 2 while gates held)",
    )
    mode_group.add_argument(
        "--check-source",
        action="store_true",
        help="Verify static repository source contracts and graph digests only (exits 0 on success)",
    )
    mode_group.add_argument(
        "--check-readiness",
        action="store_true",
        help="Evaluate deployment readiness against infrastructure gates (exits 2 while held)",
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
        print("\n".join(deps))
        return EXIT_READY

    env = inspect_environment()
    graph_ok, graph_results = verify_graph_digests()
    contracts_ok, contract_results = verify_workflow_contracts()
    ready_ok, readiness_results = evaluate_deployment_readiness()
    deps = extract_declared_dependencies()

    report = {
        "source_contracts_passed": contracts_ok and graph_ok,
        "deployment_ready": ready_ok,
        "contracts": contract_results,
        "digests": graph_results,
        "readiness": readiness_results,
        "environment": env,
        "declared_dependencies": deps,
        "proposed_routing": PROPOSED_LOCAL_ROUTING,
        "held_gates": HELD_GATES,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("=== Gargoyl CI Preflight & Verification Report (Issue #82) ===")
        print(
            f"Source Contracts:     {'PASS' if (contracts_ok and graph_ok) else 'FAIL'}"
        )
        print(
            "                      (Static source verification; does NOT imply rollout readiness)"
        )
        print(
            f"Deployment Readiness: {'READY' if ready_ok else 'BLOCKED (4 held gates)'}"
        )
        print(
            f"Current Python:       {env['python_version']} ({env['python_executable']})"
        )
        print(f"PyYAML Version:       {env['pyyaml_version']}")
        print(f"Matrix Pythons:       {env['matrix_pythons']}")
        print(
            f"macOS SDK Tools:      xcrun={env['has_xcrun']}, swiftc={env['has_swiftc']}"
        )
        print("Routing Status:       HELD on ubuntu-latest (0 repo runners enrolled)")
        print(
            f"Target Custom Label:  {PROPOSED_LOCAL_ROUTING['target_label_state']} (opaque custom label under {PROPOSED_LOCAL_ROUTING['flags']}; unassigned)"
        )
        print(f"Held Gates Count:     {len(HELD_GATES)}")

    if args.check_source:
        return EXIT_READY if (graph_ok and contracts_ok) else EXIT_CONTRACT_FAILED

    if args.check_readiness:
        return EXIT_READY if ready_ok else EXIT_HELD_BLOCKED

    # Default --check mode: Requires both source contracts AND deployment readiness
    if not (graph_ok and contracts_ok):
        return EXIT_CONTRACT_FAILED
    if not ready_ok:
        return EXIT_HELD_BLOCKED
    return EXIT_READY


if __name__ == "__main__":
    raise SystemExit(main())
