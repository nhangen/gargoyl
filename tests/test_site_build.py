import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urljoin

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

    def test_built_page_and_manifest_resolve_to_published_icons(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            self.assertEqual(site_build.main(["--out", str(out)]), 0)
            page = (out / "index.html").read_text(encoding="utf-8")
            for href in ("icon/favicon.svg", "icon/apple-touch-icon.png",
                         "icon/icon-192.png", "icon/icon-512.png", "icon/manifest.webmanifest"):
                with self.subTest(href=href):
                    self.assertIn(f'href="{href}"', page)
                    self.assertTrue((out / href).is_file())

            manifest_url = "/icon/manifest.webmanifest"
            manifest = json.loads((out / manifest_url.lstrip("/")).read_text(encoding="utf-8"))
            self.assertCountEqual(
                [(icon["sizes"], icon["purpose"]) for icon in manifest["icons"]],
                [("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")],
            )
            for icon in manifest["icons"]:
                url = urljoin(manifest_url, icon["src"])
                data = (out / url.lstrip("/")).read_bytes()
                size = int(icon["sizes"].split("x")[0])
                self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(data[16:24], size.to_bytes(4, "big") * 2)

    def test_strict_fails_while_placeholders_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            pending = site_build.placeholders(site_build.json.loads(
                (SITE / "links.json").read_text(encoding="utf-8")))
            self.assertEqual(site_build.main(["--strict", "--out", str(out)]), 1 if pending else 0)


if __name__ == "__main__":
    unittest.main()
