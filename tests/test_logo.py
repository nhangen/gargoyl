"""Verify the canonical logo mark is consistent across the repo."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK_PATH = ROOT / "assets" / "gargoyle.svg"
MARK_PATH_D = "M12 8 22 20h20L52 8l-3 22-8 14-9 12-9-12-8-14z"
EYES_PATH_D = "M21 31l8 3-8 1z M43 31l-8 3 8 1z"


class MarkConsistencyTests(unittest.TestCase):
    def test_canonical_mark_exists(self):
        self.assertTrue(MARK_PATH.is_file())
        text = MARK_PATH.read_text(encoding="utf-8")
        self.assertIn(MARK_PATH_D, text)
        self.assertIn(EYES_PATH_D, text)

    def test_favicon_svg_has_mark(self):
        favicon = (ROOT / "assets" / "icon" / "favicon.svg").read_text(encoding="utf-8")
        self.assertIn(MARK_PATH_D, favicon)
        self.assertIn(EYES_PATH_D, favicon)

    def test_design_app_pages_use_mark(self):
        """Every design/app/*.html page carries the gargoyle mark path."""
        for page in sorted((ROOT / "design" / "app").glob("*.html")):
            with self.subTest(page=page.name):
                text = page.read_text(encoding="utf-8")
                self.assertIn(MARK_PATH_D, text)
                self.assertIn(EYES_PATH_D, text)

    def test_site_index_uses_mark(self):
        index = (ROOT / "site" / "src" / "index.html").read_text(encoding="utf-8")
        self.assertIn(MARK_PATH_D, index)
        self.assertIn(EYES_PATH_D, index)

    def test_og_html_uses_mark(self):
        og = (ROOT / "site" / "og" / "og.html").read_text(encoding="utf-8")
        self.assertIn(MARK_PATH_D, og)
        self.assertIn(EYES_PATH_D, og)


if __name__ == "__main__":
    unittest.main()
