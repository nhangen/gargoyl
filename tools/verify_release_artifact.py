"""Verify one built wheel using temporary pip target and lifecycle roots only."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from gargoyl.release import (
    inspect_release,
    install_release,
    rollback_release,
    uninstall_release,
)


def verify_console(target, parent):
    """Run the pip-generated shim with isolated imports from the installed wheel."""
    script = target / "bin" / "gargoyl"
    assert script.is_file()
    runner = (
        "import pathlib,runpy,sys; sys.path.insert(0,sys.argv[1]); "
        "import gargoyl; "
        "assert pathlib.Path(gargoyl.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve()); "
        "sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    )

    def invoke(*args):
        return subprocess.run([sys.executable, "-I", "-B", "-c", runner, str(target), str(script), *args],
                              cwd=parent, capture_output=True, text=True, check=True, timeout=10).stdout

    assert "capture" in invoke("--help")
    supplied = parent / "synthetic-status.txt"
    supplied.write_text("Daemon: running (pid 12345, up 2h17m)\n")
    parsed = json.loads(invoke("inspect", "status", "--input", str(supplied),
                               "--observed-at", "2026-01-01T00:00:00Z"))
    assert parsed["readings"]["daemon_state"]["value"] == "running"
    state_file = parent / "synthetic-state.json"
    written = 1767225600
    state_file.write_text(json.dumps(dict(schema=1, pid=12345, version="synthetic",
        written_at=written, started_at=written-100, inference_active=False,
        warm_models=["private-model"], stats=dict(requests_served=3, tokens_generated=17))))
    state_file.chmod(0o600)
    state = json.loads(invoke("inspect", "state", "--input", str(state_file),
                              "--owner-uid", str(os.getuid())))
    assert state["observed_at"] == datetime.fromtimestamp(written, timezone.utc).isoformat().replace("+00:00", "Z")
    assert state["readings"]["requests_total"]["value"] == 3
    assert state["readings"]["tokens_total"]["value"] == 17
    assert "daemon_state" not in state["readings"]
    assert "private-model" not in json.dumps(state)
    producer = parent / "synthetic-producer"
    producer.write_text(f"#!{sys.executable}\nimport sys\n"
                        "assert sys.argv[1:] == ['status']\nprint('Status: ○ Stopped')\n")
    producer.chmod(0o700)
    environment = parent / "environment.json"
    environment.write_text("{}")
    captured = json.loads(invoke("capture", "status", "--executable", str(producer),
                                 "--cwd", str(parent), "--environment", str(environment)))
    assert captured["cleanup_complete"] is True
    assert captured["readings"]["daemon_state"]["value"] == "stopped"
    print("installed console help, text/state inspect and synthetic capture passed")


def verify(wheel):
    wheel = Path(wheel).resolve()
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="gargoyl-release-check-") as directory:
        parent = Path(directory).resolve()
        target = parent / "pip-target"
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-index", "--no-deps", "--target", str(target), str(wheel)], check=True)
        verify_console(target, parent)
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
