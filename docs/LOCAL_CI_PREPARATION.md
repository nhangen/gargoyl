# Local CI Migration Preparation, Safety Invariants, and Capacity Audit (Issue #82)

## Overview and Context

Gargoyl issue [#82](https://github.com/nhangen/gargoyl/issues/82) tracks preparing repository-specific local CI routing for eligible Linux checks while strictly preserving the real macOS / Swift gate and the release artifact gate's fail-closed dependency on all platform and audit checks.

This document records the called action and script graph inventory, inspected in-tree file provenance, dynamic inputs, transitive dependency vs. manifest extraction boundaries, runner workload capacity requirements, custom label profile specifications, and the concrete infrastructure blockers preventing immediate rollout.

---

## 1. Called Action and Script Graph Scope, Inspected File Provenance, and Boundary Inventory

### 1.1 Inspected In-Tree File Provenance and Called Action Inventory

In-tree workflow definitions, project manifests, execution scripts, and external action references in `.github/workflows/ci.yml` have been inventoried. In-tree files are verified with cryptographic SHA-256 and Git object digests, while external actions and dynamic execution boundaries remain explicitly uninspected offline:

| Component | Target / Path | Type / Identifier | SHA-256 Digest | Git Object SHA | Inspection Scope |
|---|---|---|---|---|---|
| Workflow Definition | `.github/workflows/ci.yml` | GitHub Actions workflow | `1e7c8eda685a3765f2eb1fc47e5ab34a17416913459cc47d72a5e99dd3a78d0b` | `545f03c2df66a9f9feb72aaa7cf425dca8f40bb2` | In-tree verified |
| Project Manifest | `pyproject.toml` | Build & dependency config | `10f1a10cc95e3b8e2ec5b0931b91f580fe3061f7a00eeac2f4d4215555db3b69` | `643f86a81242779294bd52355060ab4be8efe214` | In-tree verified |
| Repository Documentation | `README.md` | Primary documentation | `c1ba02440f8c5cfa07c5457f57b03110f5148e33a6e8aeec8c9aa6c6d197469b` | `82cf909595abbfb1e469ec85b0063abfbabad1e6` | In-tree verified |
| Test Runner | `tools/run_tests.py` | Resource leak check driver | `522456210ef5c77d9109388e12088ab4695ed203af8f2f491327b8c9a3f9977f` | `68232f9278ee542cd1f5fa2f0463e8c30e0863ae` | In-tree verified |
| Release Verification | `tools/verify_release_artifact.py` | Wheel verification script | `eec6c171586a8acb7b52914e04b1209e01a929a2dbd6afd5bdeee65ffbe264a7` | `ed3bff4559b8bd9e6cc879247a9e256b38aaf806` | In-tree verified |
| Native macOS Builder | `tools/build_macos_app.py` | Swift bundle builder | `9627562a2ac1ac3ccf909fd75b07ae8844034d7065fc1e0a6d85434893d375f5` | `a502c81700737257a7ba0562353bb56537621d29` | In-tree verified |
| Acceptance Evidence | `tools/offline_acceptance_evidence.py` | Offline pilot evidence tool | `1447cd6f98336efa34d23e6bfc411d2ae6498c011c7abd0f76aa6b5e8f2c8734` | `8dcabdfffcad123a1bb81a07ac2bd011198679b8` | In-tree verified |
| CI Preflight Tool | `tools/ci_preflight.py` | Local inspection CLI | Tracked in repository | Tracked in repository | In-tree preflight tool |
| Checkout Action | `actions/checkout` | External action pin | `@11d5960a326750d5838078e36cf38b85af677262` (v4.2.2) | External GitHub pin | External action pin only; remote script internals uninspected |
| Setup-Python Action | `actions/setup-python` | External action pin | `@a26af69be951a213d495a4c3e4e4022e16d87065` (v5.6.0) | External GitHub pin | External action pin only; remote script internals uninspected |
| Upload-Artifact Action | `actions/upload-artifact` | External action pin | `@ea165f8d65b6e75b540449e92b4886f43607fa02` (v4.6.1) | External GitHub pin | External action pin only; remote script internals uninspected |

### 1.2 Manifest Extraction vs. Transitive Resolution vs. Security Audit

It is critical to distinguish three separate dependency tiers:
1. **Manifest Extraction**: Static parsing of declared top-level package requirements from `pyproject.toml` via standard library `tomllib`:
   - `build-system.requires`: `setuptools==84.1.0`, `wheel==0.46.2`
   - `project.dependencies`: `cryptography>=46,<51`
   - `project.optional-dependencies.dev`: `ruff==0.14.3`, `PyYAML==6.0.2`
   - `project.optional-dependencies.release`: `setuptools==84.1.0`, `wheel==0.46.2`
   - Yields the 5 declared packages: `setuptools==84.1.0`, `wheel==0.46.2`, `cryptography>=46,<51`, `ruff==0.14.3`, `PyYAML==6.0.2`.
2. **Transitive Dependency Resolution**: Computing the complete dependency tree during `pip install`. For example, `cryptography` resolves transitive dependencies `cffi>=1.12` and `pycparser`.
3. **Vulnerability Audit**: Dynamic querying of external vulnerability databases (OSV, PyPA Advisory DB) via `pip-audit --strict` over the network against resolved wheels. Zero vulnerability waivers or policy relaxations are allowed.

### 1.3 End-to-End Workflow Execution Graph and Dynamic Inputs

Every job in `.github/workflows/ci.yml` was traced for dependencies, dynamic inputs, and runtime capacity:

- **`lint-and-test` (Linux Matrix: Python 3.11, 3.12, 3.13, 3.14)**:
  - *Dynamic Inputs*: Matrix variable `${{ matrix.python-version }}`.
  - *Execution Sequence*: `actions/checkout` -> `actions/setup-python` -> `pip install -e '.[dev]'` -> `ruff check .` -> `python tools/run_tests.py discover -s tests -v`.
  - *Workload Capacity*: Up to 4 concurrent matrix legs (the unchanged workflow at `.github/workflows/ci.yml:14-16` defines 4 matrix versions and no `max-parallel: 1`; legs execute concurrently, not serialized). 612 unit tests passed with 0 skips in verified local macOS Darwin Python 3.14.7 testing; Linux collected/executed/skipped counts remain UNVERIFIED. Exercises in-memory and temporary SQLite stores, cryptographic Ed25519 signatures, thread synchronization, and `unraisablehook` resource warning traps. Sizing candidate is an explicitly UNMEASURED estimate of 4 CPUs / 4 GiB memory per matrix leg (non-root user, no Docker daemon required). Aggregate peak matrix demand can reach up to 16 CPUs / 16 GiB memory if all 4 legs execute concurrently, plus independent `dependency-audit` load; `release-artifact` dependency timing is distinct and executes only after all 3 prior gates succeed. There is NO measured capacity or safe allocation claim.
- **`macos-native` (Native macOS: macOS 15, Python 3.14)**:
  - *Dynamic Inputs*: Canonical temp directory path via `python -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))'`.
  - *Execution Sequence*: `actions/checkout` -> `actions/setup-python` -> `pip install -e '.[dev]'` -> canonical `TMPDIR` export -> `python tools/run_tests.py discover -s tests -v`.
  - *Native Subsystem*: Compiles Swift GUI test harness (`gargoyl/native_app.py:SWIFT`) using `/usr/bin/xcrun swiftc -swift-version 5 -D GARGOYL_NATIVE_TESTS` linking `AppKit`, `WebKit`, `LocalAuthentication`, `Security`, and `SystemConfiguration`. Runs `fixture --self-test` and tests ad-hoc codesigning via `/usr/bin/codesign`.
  - *Workload Capacity*: Strictly requires real macOS Darwin hardware with Xcode CLI tools and GUI subsystem entitlements. Cannot run in a Linux container or on unprivileged Linux runners.
- **`dependency-audit` (Linux: Python 3.14)**:
  - *Dynamic Inputs*: `audit-requirements.txt` generated dynamically via `tomllib` without private PyPI lookup.
  - *Execution Sequence*: `actions/checkout` -> `actions/setup-python` -> `pip install pip-audit==2.10.1` -> manifest generation -> `python -m pip_audit --strict --progress-spinner off -r audit-requirements.txt`.
  - *Workload Capacity*: Requires outbound network access to query the OSV / PyPA vulnerability database APIs.
- **`release-artifact` (Linux: Python 3.12)**:
  - *Dynamic Inputs*: Prior job result variables:
    - `LINUX_RESULT: ${{ needs.lint-and-test.result }}`
    - `MACOS_RESULT: ${{ needs.macos-native.result }}`
    - `AUDIT_RESULT: ${{ needs.dependency-audit.result }}`
    - Artifact name `${{ github.sha }}`.
  - *Execution Sequence*: Shell tri-prerequisite verification -> `actions/checkout` -> `actions/setup-python` -> `pip install -e '.[release]'` -> `pip wheel` -> `tools/verify_release_artifact.py` -> `actions/upload-artifact`.
  - *Fail-Closed Invariant*: `needs: [lint-and-test, macos-native, dependency-audit]` combined with `if: ${{ always() }}` and explicit checks:
    ```sh
    test "$LINUX_RESULT" = success
    test "$MACOS_RESULT" = success
    test "$AUDIT_RESULT" = success
    ```
    If ANY prerequisite is failed, cancelled, or skipped, wheel generation and artifact upload are strictly refused.

### 1.4 External Action Inspection Limits

External actions (`actions/checkout`, `actions/setup-python`, `actions/upload-artifact`) are pinned to immutable 40-character commit SHAs. However, their internal execution scripts (Node.js runtime scripts, `action.yml` metadata, and bundled JavaScript dependencies) are hosted on GitHub. Offline static analysis in this workspace cannot inspect remote external action internals. In a local runner environment, executing these actions requires either runner network connectivity to GitHub Actions services or a pre-cached action runner environment.

### 1.5 Static Source Inventory and Unresolved Execution Boundaries

A static inventory of in-tree source and workflow definitions reveals:
- **In-Tree Python Scope**: 124 Python files (53 in `gargoyl/`, 66 in `tests/`, 5 in `tools/`).
- **Static Imports and Call Sites**: 1,812 imports (919 local imports) and 14,639 AST call-site rows across the codebase.
- **Workflow Step Definitions**: 20 step definitions across 4 jobs.
- **Static Entrypoints**: 3 (`gargoyl/cli.py`, `tools/run_tests.py`, `tools/verify_release_artifact.py`), reaching 27 statically import-reachable files.
- **Embedded Native Boundary**: `gargoyl/native_app.py:SWIFT` (103,604 characters, SHA-256 `7fc68b8ea6ddf069bd01a001ebb3d64e53fb52d26c54c59da08b1249e5e5adfe`) contains embedded Swift source that is opaque to Python AST analysis; native testing compiles and executes separately via `/usr/bin/xcrun swiftc`.
- **Unresolved Execution Boundaries**: External action execution scripts, dynamic unittest discovery, subprocess dispatch, live network queries (`pip-audit`), and container isolation are runtime boundaries that cannot be replaced by static analysis.

---

## 2. Current vs. Potential Target Runner Routing Deltas

### 2.1 Unique Custom Label Profile (`nhangen/local-ci`)

The established local runner profile managed by `nhangen/local-ci` (as deployed for Tron, pcri, and llm-tools) enforces:
- Registration with `--no-default-labels` (strips standard `self-hosted`, `linux`, `x64` tags).
- A single, repository-unique custom label string: the target label is explicitly `UNRESOLVED_HELD` and unassigned; an opaque generated `local-ci-<hash>` may only be assigned after separately approved enrollment (0 runners currently enrolled; no concrete label deployed).
- Multi-label selectors such as `[self-hosted, linux, gargoyl]` are invalid under this profile and will fail to match any runner.

### 2.2 Routing Delta Matrix

| Job Name | Current Production Routing | Potential Target Routing | Status | Notes |
|---|---|---|---|---|
| `lint-and-test` | `runs-on: ubuntu-latest` | `runs-on: UNRESOLVED_HELD` (opaque custom label under `--no-default-labels`; unassigned) | **HELD** | Preserved on `ubuntu-latest` pending approved capacity & enrollment |
| `macos-native` | `runs-on: macos-15` | `runs-on: macos-15` (Unchanged) | **PRESERVED** | Real macOS runner required for Swift/AppKit/WebKit; canonical `TMPDIR` |
| `dependency-audit` | `runs-on: ubuntu-latest` | `runs-on: UNRESOLVED_HELD` (opaque custom label under `--no-default-labels`; unassigned) | **HELD** | Preserved on `ubuntu-latest`; strict audit with zero waivers |
| `release-artifact` | `runs-on: ubuntu-latest` | `runs-on: UNRESOLVED_HELD` (opaque custom label under `--no-default-labels`; unassigned) | **HELD** | Preserved on `ubuntu-latest`; `if: ${{ always() }}` fail-closed tri-gate |

**Policy Invariant**: Actual routing is **HELD** on `ubuntu-latest`. Production `.github/workflows/ci.yml` is kept intact (`runs-on: ubuntu-latest`) to avoid routing jobs to nonexistent local runner labels while Gargoyl enrollment (0 runners) and capacity (28/28 allocated) remain unapproved.

---

## 3. Preflight Tooling and Explicit Exit Semantics

`tools/ci_preflight.py` provides local verification with distinct CLI modes and explicit exit semantics to prevent false passing readiness:

| Mode Flag | Purpose | Exit Code Semantics | Output Status |
|---|---|---|---|
| `--check-source` | Verifies static repository source contracts and graph digests only | `0` = PASS, `1` = Contract Violation | Explicitly notes: static source check only; does not imply rollout readiness |
| `--check-readiness` | Evaluates deployment rollout readiness against infrastructure gates | `0` = Ready (unreachable currently), `2` = BLOCKED (Held gates) | Explicitly details: capacity saturated, 0 repo runners, branch protection denied |
| `--check` (default) | Executes both source contract validation and readiness evaluation | `0` = Fully Ready, `1` = Contract Violation, `2` = Source PASS but Rollout HELD | Prevents false passing readiness by returning non-zero exit code while gates are held |
| `--manifest-only` | Extracts declared dependencies for audit | `0` = Success | Prints 5 declared requirements |

---

## 4. Remaining Action-Time Gates and Capacity Blockers

1. **Local Fleet Capacity Allocation**:
   - Local-CI fleet allocation is fully saturated at 28/28 CPUs and 46/48 GiB memory.
   - Proposed Tron resize is unapproved.
   - Default matrix runs up to 4 concurrent legs; container sizing candidate is an explicitly unmeasured estimate of 4 CPUs / 4 GiB memory per leg (up to 16 CPUs / 16 GiB peak matrix demand plus independent audit load); Gargoyl cannot schedule jobs locally until explicit capacity headroom is authorized.

2. **Repository Runner Enrollment**:
   - GitHub reports 0 repository runners configured for `nhangen/gargoyl`.
   - Registration with the `nhangen/local-ci` fleet controller requires action-time enrollment approval and credential provisioning; target label remains `UNRESOLVED_HELD` under `--no-default-labels`.

3. **Branch Protection Constraints**:
   - Access to GitHub branch protection API was denied (`HTTP 403`).
   - Required status check names remain unconfirmed; exact job names (`lint-and-test`, `macos-native`, `dependency-audit`, `release-artifact`) must be maintained to prevent blocking merges.

4. **Preservation of Non-Root / Unprivileged Profile**:
   - Current runner profile operates with dropped capabilities (`capDropALL`), no Docker daemon, and no host Docker socket.
   - All Linux jobs must remain compatible with this unprivileged container profile.

5. **Capture Receipt Status**:
   - `UNVERIFIED / UNAVAILABLE`: No local capture receipt or readback was produced or observed; coordinator handles canonical nonsecret delivery.
