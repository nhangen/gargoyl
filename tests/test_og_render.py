"""Drive site/og/render.js so its hardening is verified, not just present.

CI is Python-only, so this is the only automation that exercises the render
script: it copies site/ to a temp dir, breaks the self-hosted Archivo font
(setup missing or the @font-face declaration stripped), and asserts that
render.js fails loudly with a non-zero exit instead of capturing a fallback
typeface. Skips when node or playwright is not resolvable.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
FONT = "src/fonts/archivo-latin-variable.woff2"
FONT_FACE = re.compile(
    r"  @font-face \{.*?src: url\(\"../src/fonts/archivo-latin-variable\.woff2\"\)"
    r" format\(\"woff2\"\);\n  \}\n",
    re.S,
)


def _playwright_dir() -> Path | None:
    """The node_modules directory holding playwright, or None."""
    try:
        subprocess.run(
            ["node", "-e", "process.stdout.write(require('playwright/package.json').name)"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    # playwright/package.json resolves through node_modules/<pkg>/package.json.
    module = subprocess.run(
        ["node", "-e", "process.stdout.write(require.resolve('playwright/package.json'))"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    path = Path(module)
    for parent in path.parents:
        if parent.name == "node_modules":
            return parent
    return path.parent.parent


class OgRenderTest(unittest.TestCase):
    """render.js must exit 1 with 'og render failed:' when the Archivo font
    cannot load, whether the file is missing, the declaration is gone, or the
    h1 font-family is misconfigured. Unmodified site/ must render cleanly."""

    def setUp(self):
        if shutil.which("node") is None:
            self.skipTest("node is not installed")
        if _playwright_dir() is None:
            self.skipTest("playwright is not resolvable from node")

    def _render(self, root: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["node", "og/render.js"],
            cwd=root / "site",
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        node_modules = _playwright_dir()
        if node_modules is not None:
            existing = env.get("NODE_PATH")
            env["NODE_PATH"] = (existing + os.pathsep + str(node_modules)) if existing else str(node_modules)
        return env

    def test_missing_font_file_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(SITE, root / "site", symlinks=True)
            (root / "site" / FONT).unlink()
            proc = self._render(root, self._env())
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("og render failed:", proc.stderr)
            self.assertIn("self-hosted Archivo font did not load", proc.stderr)

    def test_stripped_font_face_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(SITE, root / "site", symlinks=True)
            og = root / "site" / "og" / "og.html"
            text = og.read_text(encoding="utf-8")
            stripped, count = FONT_FACE.subn("", text, count=1)
            self.assertEqual(count, 1, "expected exactly one Archivo @font-face block in og.html")
            self.assertNotIn("archivo-latin-variable.woff2", stripped)
            og.write_text(stripped, encoding="utf-8")
            proc = self._render(root, self._env())
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("og render failed:", proc.stderr)
            self.assertIn("self-hosted Archivo font did not load", proc.stderr)

    def test_h1_font_family_typo_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(SITE, root / "site", symlinks=True)
            og = root / "site" / "og" / "og.html"
            text = og.read_text(encoding="utf-8")
            # Replace Archivo with a fallback in the h1 rule only.
            modified, count = re.subn(
                r'(h1\s*\{[^}]*font-family:\s*)"Archivo"',
                r'\1"ArchivoFallback"',
                text,
                count=1,
            )
            self.assertEqual(count, 1, "expected to find h1 font-family declaration in og.html")
            og.write_text(modified, encoding="utf-8")
            proc = self._render(root, self._env())
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn("og render failed:", proc.stderr)
            self.assertIn("h1 font-family does not resolve to Archivo", proc.stderr)

    def test_intact_site_renders_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(SITE, root / "site", symlinks=True)
            proc = self._render(root, self._env())
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((root / "site" / "src" / "og.png").is_file())


if __name__ == "__main__":
    unittest.main()
