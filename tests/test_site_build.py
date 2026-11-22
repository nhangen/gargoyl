import importlib.util
import tempfile
import unittest
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent / "site"
spec = importlib.util.spec_from_file_location("site_build", SITE / "build.py")
site_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site_build)


class RenderTest(unittest.TestCase):
    def test_renders_external_link(self):
        out = site_build.render("<a {{link:gh}}>", {"gh": "https://github.com/a/b"})
        self.assertEqual(out, '<a href="https://github.com/a/b" rel="noopener">')

    def test_marks_placeholder(self):
        out = site_build.render("<a {{link:x}}>", {"x": "https://x.com/REPLACE_ME"})
        self.assertIn(" data-placeholder", out)

    def test_escapes_url(self):
        out = site_build.render("<a {{link:q}}>", {"q": 'https://e.com/?a="b"&c'})
        self.assertIn('href="https://e.com/?a=&quot;b&quot;&amp;c"', out)

    def test_unknown_link_fails(self):
        with self.assertRaises(KeyError):
            site_build.render("<a {{link:missing}}>", {})


class SiteTest(unittest.TestCase):
    def test_build_resolves_every_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            self.assertEqual(site_build.main(["--out", str(out)]), 0)
            page = (out / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("{{", page)
            self.assertIn('href="https://github.com/nhangen/gargoyl"', page)
            self.assertTrue((out / "fonts" / "archivo-latin-variable.woff2").is_file())

    def test_build_includes_icon_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            self.assertEqual(site_build.main(["--out", str(out)]), 0)
            page = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="icon/favicon.svg"', page)
            self.assertIn('href="icon/apple-touch-icon.png"', page)
            self.assertIn('href="icon/manifest.webmanifest"', page)
            for name in (
                "icon/favicon.svg",
                "icon/apple-touch-icon.png",
                "icon/icon-192.png",
                "icon/icon-512.png",
                "icon/icon-maskable-512.png",
                "icon/manifest.webmanifest",
            ):
                with self.subTest(icon=name):
                    self.assertTrue((out / name).is_file())

    def test_strict_fails_while_placeholders_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            pending = site_build.placeholders(site_build.json.loads(
                (SITE / "links.json").read_text(encoding="utf-8")))
            self.assertEqual(site_build.main(["--strict", "--out", str(out)]), 1 if pending else 0)


if __name__ == "__main__":
    unittest.main()
