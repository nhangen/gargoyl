"""Verify one built wheel using temporary pip target and lifecycle roots only."""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from gargoyl.release import (
    inspect_release,
    install_release,
    rollback_release,
    uninstall_release,
)


def verify(wheel):
    wheel = Path(wheel).resolve()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="gargoyl-release-check-") as directory:
        parent = Path(directory).resolve()
        target = parent / "pip-target"
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-index", "--no-deps", "--target", str(target), str(wheel)], check=True)
        root = parent / "application"
        state = install_release(root, wheel, expected_sha256=digest)
        code = root / "releases" / state["active"]
        check = (
            "import pathlib,sys; sys.path.insert(0,sys.argv[1]); "
            "import gargoyl, gargoyl.release, gargoyl.repair_operator, gargoyl.repair_host_adapter; "
            "assert pathlib.Path(gargoyl.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()); "
            "print('installed wheel imports passed')"
        )
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for location in (target, code):
            subprocess.run([sys.executable, "-I", "-B", "-c", check, str(location)],
                           cwd=parent, env=environment, check=True)
        assert inspect_release(root)["active"] == digest
        assert uninstall_release(root)["active"] is None
        assert install_release(root, wheel, expected_sha256=digest)["active"] == digest
        # Rollback without a prior release must refuse, never guess another path.
        from gargoyl.release import ReleaseError
        try:
            rollback_release(root)
        except ReleaseError:
            pass
        else:
            raise AssertionError("rollback unexpectedly succeeded")
        uninstall_release(root)
    print(f"Verified wheel SHA256 {digest}; temporary roots removed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_release_artifact.py path/to/gargoyl.whl")
    verify(sys.argv[1])
