# Offline release lifecycle for an explicitly approved application root

This release package is Python code, not a deployed service or a self-contained
runtime distribution. There is no operational collection CLI or console entry point:
the module CLI only manages installed code and cannot collect, serve, authenticate
an operator, or execute a repair. Operational CLI integration is separate work.
It requires POSIX, Python >=3.11 and the declared cryptography
dependency. It installs no service, host command, credentials, launch agent, network
listener or production configuration. Building/verifying it does not authorize use
on a live target. The tests and artifact verifier operate in temporary directories.

## Exact layout and semantics

Choose a **new, nonexistent, absolute application root** under a trusted parent.
Existing directories, even empty ones, are never claimed. Existing roots are accepted
only if their full ownership/state/code inventory validates. Root and parent paths
must not contain symlinks; use the canonical physical path on platforms where `/var`
or `/tmp` is a link. Paths within `darkbloom` or `.darkbloom` are explicitly refused.
The application root must be owned by the caller and private (0700).

```text
<approved-root>/
  state.json                 # application/schema, active/previous, hash inventories
  .lock                      # cooperating lifecycle callers, nonblocking POSIX lock
  releases/<wheel-sha256>/    # package and dist-info, code files 0600, directories 0700
  data/                      # opaque evidence/audit state, NEVER traversed or removed
```

The `data` directory is separate from immutable code. Operators supply its evidence
and audit subdirectories to the existing store constructors, with keys supplied
separately; the lifecycle tool neither creates keys nor opens those stores.

- **Install:** require a caller-supplied trusted SHA256 and a supported Gargoyl wheel.
  Validate the complete artifact before touching the destination. Install into a
  staging directory, flush code, rename to the digest directory, atomically replace
  and flush the activation record. No wheel code or install hook executes.
- **Upgrade:** install a second distinct wheel and select it; retain the previous
  code release for rollback. Versions use a bounded numeric release format; digest
  distinguishes builds even with the same version. There is no automatic version
  preference or claim that a higher number is trusted.
- **Rollback:** verify both full code inventories, then atomically swap active and
  previous. Do not restore, migrate, prune or roll back evidence/audit data.
- **Uninstall:** first verify every owned code file and directory; remove only that
  verified code inventory. Retain data, ownership state and lock with no active code.
  Reinstall into this retained owned root is supported. There is no data-delete mode.
- **Capacity:** at most two code releases. A third install and duplicate install
  refuse without changes. For a later deployment cycle, explicitly stop the process,
  retain trusted artifacts externally, uninstall code only, then install the chosen
  artifact. This intentionally has downtime; it is not a rolling-upgrade system.

Stop all running Gargoyl processes before install/upgrade/rollback/uninstall; this
tool does not detect or stop services. Changing active code does not reload a running
Python process. This slice performs no data-schema migration: both release versions
must be compatible with the retained data schema. A compatible rollback cannot be
inferred from a successful file switch.

Unknown files/directories (including `__pycache__`), code hash changes, hardlinks,
symlinks in managed code/control paths, corrupt state or a contended lifecycle lock
cause refusal. No forced removal or repair command exists. Data is opaque: its contents
are preserved without following nested links, parsing secrets, or deciding what is
obsolete. Never place Darkbloom's files inside this application layout.

## Build and verify an artifact

From the reviewed source checkout, in a development environment:

```sh
python -m pip install -e '.[dev,release]'
python -m ruff check .
python -m unittest discover -s tests -v
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
python tools/verify_release_artifact.py dist/gargoyl-0.1.0-py3-none-any.whl
```

Build tooling is pinned to setuptools 80.9.0 and wheel 0.45.1. The result is a normal
`py3-none-any` wheel with declared Python/runtime dependencies, usable with standard
pip installation in an approved environment. Pinning tools alone is not a reproducible
byte-for-byte build claim; record the reviewed source revision and actual artifact
SHA256. CI builds and uploads the wheel by commit after the full test matrix passes.
The verifier performs offline `pip --no-index --no-deps --target` installation and
lifecycle install/import/uninstall/reinstall in fresh temporary roots. Its interpreter
already has the declared dependencies; dependencies are not bundled or downloaded
by the lifecycle tool/verifier.

Only a **trusted artifact digest**, obtained through the reviewed release process,
should be supplied. A matching hash detects changed bytes; it does not establish a
publisher identity or replace review. This is deliberately a narrow pure-Python
Gargoyl wheel installer, not a general wheel/pip implementation. It rejects extra
packages, entry points, native libraries, wheel `.data` trees, executable hooks,
traversal, duplicate paths, symlinks and excessive sizes. Limits: compressed wheel
8 MiB, expanded code 16 MiB, 512 files, 1 MiB per file. No dependency resolution,
index access, certificate setup or model download occurs.

## Explicit local API and CLI

```python
install_release(root, wheel, expected_sha256=trusted_digest) -> state_dict
inspect_release(root) -> state_dict
rollback_release(root) -> state_dict
uninstall_release(root) -> state_dict
```

Import these from `gargoyl.release`. Returned state is detached metadata, not data
contents. Safe `ReleaseError` means inspect what happened before taking another
action; never interpret it as proof that no filesystem change occurred.

The equivalent CLI is `python -B -m gargoyl.release ACTION ABSOLUTE_ROOT` with actions
`inspect`, `rollback`, `uninstall`, or `install --wheel WHEEL --sha256 DIGEST`. It returns
0 and active/previous digest metadata on success, or 2 and fixed refusal text.
These are instructions for a later explicitly authorized installation, not a request
to run them on live paths now. Use a trusted bootstrap interpreter/environment outside
the managed code tree; dependencies and that environment remain caller-owned.

After validating `inspect_release`, a supervisor can place
`<root>/releases/<active-digest>` on its Python import path. Use `python -B` or
`PYTHONDONTWRITEBYTECODE=1` to keep code immutable; bytecode-cache writes intentionally
cause future inventory validation to refuse. No launcher, credential loader or
background supervisor is installed by this milestone.

## Failure and ownership boundaries

Atomic state replacement prevents a partially written activation record. Code/data
migration is not atomic as a whole and filesystem latency is not forcibly bounded.
A crash or write error may leave staging, an unreferenced release, a pending state
file, or partially removed code. Subsequent operations refuse that inconsistent
layout; no automatic retry, prune, rollback, or recovery guesses are made. Preserve
all files and obtain explicit target-specific recovery guidance. Data contents are
never deleted even on an interrupted uninstall. Directory/file fsync improves local
durability but is not power-loss certification, filesystem rollback detection or
secure erasure. An operation may have committed even if its final flush reports error.

The parent directory and process owner are trusted. Locking serializes cooperating
lifecycle callers, not malicious owner mutations; a privileged attacker can forge
state or replace paths. Hash inventories are integrity checks, not signed provenance.
There is no assertion of process isolation or protection against an owner who can
change the installation concurrently outside this API.

## Acceptance and remaining pilot work

Tests install two self-authored synthetic wheel versions and preserve actual encrypted
EvidenceStore snapshots and RepairAuditStore claims across upgrade, rollback, uninstall
and reinstall. They exercise foreign/Darkbloom/symlink paths, changed code, malformed
artifacts, capacity, lock contention and interrupted activation/uninstall. Artifact
smoke tests import code from the actual built wheel rather than the checkout.

This addresses code packaging and a safe local lifecycle model. Actual macOS/three-host
installation, interpreter/dependency distribution, operator signing/enrollment, key
custody, endpoint/service topology, compatible upgrade policy and pilot feedback remain
unverified. Epics #4/#5 stay open. No production paths, settings, credentials, permissions,
DNS, services, Darkbloom assets, or live host operations were changed in this work.
