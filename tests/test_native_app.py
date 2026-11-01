"""Compile real native gate/navigation fixtures without starting AppKit or auth."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gargoyl.gui_runtime import console_owner
from gargoyl.native_app import SWIFT


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("xcrun"), "Apple SDK required"
)
class NativeGateTests(unittest.TestCase):
    def test_compiled_native_authorization_and_navigation_boundaries(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            source = root / "Gargoyl.swift"
            source.write_text(SWIFT)
            binary = root / "fixture"
            compiled = subprocess.run(
                [
                    "/usr/bin/xcrun",
                    "swiftc",
                    "-swift-version",
                    "5",
                    "-D",
                    "GARGOYL_NATIVE_TESTS",
                    "-module-cache-path",
                    str(root / "cache"),
                    "-framework",
                    "AppKit",
                    "-framework",
                    "WebKit",
                    "-framework",
                    "LocalAuthentication",
                    "-framework",
                    "SystemConfiguration",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                timeout=120,
            )
            self.assertEqual(
                compiled.returncode,
                0,
                compiled.stdout.decode() + compiled.stderr.decode(),
            )
            fake = root / ".venv/bin/python"
            fake.parent.mkdir(parents=True)
            payload = (
                json.dumps(dict(kind="view", view="tools", html="x" * 23000)) + "\n"
            )
            fake.write_text(
                "#!/usr/bin/python3\nimport sys\nsys.stdout.write("
                + repr(payload)
                + ")\n"
            )
            fake.chmod(0o700)
            hits = []

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    hits.append(self.path)
                    self.send_response(200)
                    self.end_headers()

                def log_message(self, *_args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                environment = dict(
                    os.environ,
                    GARGOYL_TEST_BLOCKED_RESOURCE=f"http://127.0.0.1:{server.server_port}",
                )
                if console_owner():
                    environment["GARGOYL_FIXTURE_PYTHON"] = str(fake)
                result = subprocess.run(
                    [str(binary), "--self-test"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    env=environment,
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("fixtures passed", result.stdout)
            self.assertEqual(hits, [], "hostile page leaked blocked subresources")
