# Local CI Migration Preparation, Safety Invariants, and Capacity Audit (Issue #82)

## Overview and Context

Gargoyl issue [#82](https://github.com/nhangen/gargoyl/issues/82) tracks preparing repository-specific local CI routing for eligible Linux jobs while strictly preserving the native macOS / Swift gate and the release artifact gate's fail-closed dependency on all platform and audit checks.

This document records the exact called action and script graph digests, job compatibility requirements, container execution profile constraints, current vs. potential runner routing deltas, and the concrete capacity, enrollment, and security blockers preventing immediate rollout.

---

## 1. Called Action and Script Graph Audit

All actions, execution scripts, build definitions, and third-party dependencies referenced by `.github/workflows/ci.yml` have been captured and verified with exact cryptographic SHA-256 and Git object digests:

| Component | Target / Path | Type / Identifier | SHA-256 Digest | Git Object SHA |
|---|---|---|---|---|
| Workflow Definition | `.github/workflows/ci.yml` | GitHub Actions workflow | `1e7c8eda685a3765f2eb1fc47e5ab34a17416913459cc47d72a5e99dd3a78d0b` | `545f03c2df66a9f9feb72aaa7cf425dca8f40bb2` |
| Project Manifest | `pyproject.toml` | Build & dependency config | `7f5ada8949aaa2cdcffbdb61ab8409380d3d4f054c39a262d138d0002429a786` | `f6180f06d3422c57cc0f70c221078d07b279e257` |
| Repository Documentation | `README.md` | Primary documentation | `c1ba02440f8c5cfa07c5457f57b03110f5148e33a6e8aeec8c9aa6c6d197469b` | `82cf909595abbfb1e469ec85b0063abfbabad1e6` |
| Test Runner | `tools/run_tests.py` | Resource leak check driver | `522456210ef5c77d9109388e12088ab4695ed203af8f2f491327b8c9a3f9977f` | `68232f9278ee542cd1f5fa2f0463e8c30e0863ae` |
| Release Verification | `tools/verify_release_artifact.py` | Wheel verification script | `eec6c171586a8acb7b52914e04b1209e01a929a2dbd6afd5bdeee65ffbe264a7` | `ed3bff4559b8bd9e6cc879247a9e256b38aaf806` |
| Native macOS Builder | `tools/build_macos_app.py` | Swift bundle builder | `9627562a2ac1ac3ccf909fd75b07ae8844034d7065fc1e0a6d85434893d375f5` | `a502c81700737257a7ba0562353bb56537621d29` |
| Acceptance Evidence | `tools/offline_acceptance_evidence.py` | Offline pilot evidence tool | `1447cd6f98336efa34d23e6bfc411d2ae6498c011c7abd0f76aa6b5e8f2c8734` | `8dcabdfffcad123a1bb81a07ac2bd011198679b8` |
| Checkout Action | `actions/checkout` | Commit SHA pin | `@11d5960a326750d5838078e36cf38b85af677262` (v4) | External action pin |
| Setup-Python Action | `actions/setup-python` | Commit SHA pin | `@a26af69be951a213d495a4c3e4e4022e16d87065` (v5) | External action pin |
| Upload-Artifact Action | `actions/upload-artifact` | Commit SHA pin | `@ea165f8d65b6e75b540449e92b4886f43607fa02` (v4) | External action pin |

### Declared Third-Party Dependencies (from `pyproject.toml`)
The declared third-party dependency graph extracted without private root lookup:
- Build requires: `setuptools==84.1.0`, `wheel==0.46.2`
- Core dependencies: `cryptography>=46,<51`
- Dev optional-dependencies: `ruff==0.14.3`
- Release optional-dependencies: `setuptools==84.1.0`, `wheel==0.46.2`
- Audit tool: `pip-audit==2.10.1` (pinned explicitly in `ci.yml`)

---

## 2. Job Compatibility Analysis in Intended Safe Runner Profile

The intended local CI execution profile is an unprivileged, non-root Linux x64 container environment (`capDropALL`, `no-new-privileges`, read-only root with writable `/tmp`, no Docker daemon, no host Docker socket mounts).

### 2.1 `lint-and-test` (Linux Matrix: Python 3.11, 3.12, 3.13, 3.14)
- **Commands**:
  - `python -m pip install -e '.[dev]'`
  - `python -m ruff check .`
  - `python tools/run_tests.py discover -s tests -v`
- **Compatibility**:
  - Standard pure Python unit test execution with `ResourceWarning` detection via custom `unraisablehook`.
  - Does not require a Docker daemon or container nesting.
  - Requires isolated Python environments for each matrix version (3.11, 3.12, 3.13, 3.14).
  - Skips Apple-only tests (`NativeGateTests` in `tests/test_native_app.py` has `@unittest.skipUnless(sys.platform == "darwin" and shutil.which("xcrun"))`).

### 2.2 `dependency-audit` (Linux: Python 3.14)
- **Commands**:
  - `python -m pip install pip-audit==2.10.1`
  - Manifest extraction via `tomllib` without PyPI resolution of the private `gargoyl` package.
  - `python -m pip_audit --strict --progress-spinner off -r audit-requirements.txt`
- **Compatibility**:
  - Runs in pure Python 3.14 environment.
  - `--strict` mode requires vulnerability advisory database connectivity (PyPI / OSV vulnerability database) or a local mirror.
  - Zero vulnerability waivers or policy relaxations permitted.

### 2.3 `release-artifact` (Linux: Python 3.12)
- **Prerequisites**: Explicit gate requiring `LINUX_RESULT=success`, `MACOS_RESULT=success`, `AUDIT_RESULT=success`.
- **Commands**:
  - `python -m pip install -e '.[release]'`
  - `python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .`
  - `python tools/verify_release_artifact.py dist/gargoyl-0.1.0-py3-none-any.whl`
  - `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`
- **Compatibility**:
  - Runs in unprivileged container with writable temporary filesystem.
  - `tools/verify_release_artifact.py` performs isolated installation, CLI invocation, lifecycle transition (install, rollback refusal without prior release, uninstall), and SHA-256 integrity checks.
  - Compatible with unprivileged Linux x64 profile.

### 2.4 `macos-native` (Native macOS: macOS 15, Python 3.14)
- **NON-MIGRATABLE TO LINUX RUNNERS**:
  - Requires `/usr/bin/xcrun swiftc -swift-version 5 -O` and Apple SDK frameworks: `AppKit`, `WebKit`, `LocalAuthentication`, `Security`, `SystemConfiguration`.
  - Exercises real native Swift self-test (`fixture --self-test`), WebKit navigation guard fixtures, and AppKit bundle sealing.
  - Canonical `TMPDIR` setup (`export TMPDIR="$(python -c 'import os,tempfile; print(os.path.realpath(tempfile.gettempdir()))')"`) is intentional and strictly required to resolve symlink checks against `/var/folders`.
  - **Invariant**: Must strictly remain on real macOS hardware (`runs-on: macos-15`). Linux fakes, stubs, or skips are strictly rejected. Any future local Mac runner requires an independently reviewed isolation plan and action-time authorization.

---

## 3. Current vs. Potential Runner Routing Deltas

| Job Name | Current Production Routing | Potential Target Routing | Status |
|---|---|---|---|
| `lint-and-test` | `runs-on: ubuntu-latest` | `runs-on: [self-hosted, linux, gargoyl]` | **HELD** (Blocked on capacity & enrollment) |
| `macos-native` | `runs-on: macos-15` | `runs-on: macos-15` (Unchanged) | **PRESERVED** (Native macOS gate retained) |
| `dependency-audit` | `runs-on: ubuntu-latest` | `runs-on: [self-hosted, linux, gargoyl]` | **HELD** (Blocked on capacity & enrollment) |
| `release-artifact` | `runs-on: ubuntu-latest` | `runs-on: [self-hosted, linux, gargoyl]` | **HELD** (Blocked on capacity & enrollment) |

### Routing Delta Policy
- **No Premature Label Switching**: Current routing in `.github/workflows/ci.yml` remains on `ubuntu-latest`. It is **NOT** switched to an unavailable label (such as `self-hosted` or `[self-hosted, linux, gargoyl]`) while repository enrollment and fleet capacity are missing.
- **No Skips or Fake Greens**: No conditional passes or mock skips are introduced.
- **Fail-Closed Release Gate**: `release-artifact` preserves `if: ${{ always() }}` and explicit prerequisite evaluation:
  ```sh
  test "$LINUX_RESULT" = success
  test "$MACOS_RESULT" = success
  test "$AUDIT_RESULT" = success
  ```
  If any prerequisite fails, is cancelled, or is skipped (including `macos-native`), the release job strictly aborts before building or uploading wheels.

---

## 4. Remaining Action-Time Gates and Capacity Blockers

1. **Local CI Fleet Allocation**:
   - Current fleet budget: 28/28 CPUs and 46/48 GiB memory fully allocated.
   - Observed idle compute does not constitute approved headroom.
   - Proposed Tron resize is unapproved.
   - Gargoyl cannot schedule jobs on local runners without an authorized quota allocation.

2. **Repository Enrollment**:
   - GitHub reports **0 repository runners** enrolled for `nhangen/gargoyl`.
   - Neither deployed local-CI configuration enrolls Gargoyl.
   - Enrolling Gargoyl and generating runner credentials requires action-time approval.

3. **Branch Protection Constraints**:
   - Read access to the GitHub branch protection API endpoint was denied (`HTTP 403 / Resource not accessible by personal access token`).
   - Required status check names and enforced merge gate rules remain unknown.
   - Preserving exact check names (`lint-and-test`, `macos-native`, `dependency-audit`, `release-artifact`) is mandatory to avoid breaking merge protection.

4. **Security and Runner Profile Invariants**:
   - No Docker daemon or Docker socket mounts permitted.
   - No privilege escalation, capabilities additions (`capDropALL`), or relaxed seccomp policies.
   - Pinned action SHAs and `permissions: contents: read` must be preserved.
