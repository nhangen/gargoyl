import html
import importlib.util
import json
import re
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


class DocTokenTest(unittest.TestCase):
    LINKS = {"docs_base": "https://example.com/docs/", "gh": "https://github.com/a/b"}

    def test_renders_doc_href_with_base_and_noopener(self):
        out = site_build.render("<a {{doc:cli.md}}>", self.LINKS)
        self.assertEqual(out, '<a href="https://example.com/docs/cli.md" rel="noopener">')

    def test_missing_docs_base_fails_clearly(self):
        with self.assertRaisesRegex(KeyError, "docs_base is missing; add it to links.json"):
            site_build.render("<a {{doc:cli.md}}>", {})

    def test_docs_base_without_trailing_slash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "must end with"):
            site_build.render("<a {{doc:cli.md}}>", {"docs_base": "https://example.com/docs"})

    def test_placeholder_docs_base_marks_doc_links(self):
        out = site_build.render("<a {{doc:cli.md}}>", {"docs_base": "https://REPLACE_ME/"})
        self.assertIn("data-placeholder", out)

    def test_unresolved_token_fails_the_build(self):
        with self.assertRaisesRegex(ValueError, "unresolved tokens"):
            site_build.render("<a {{doc:CLI.md}}>", self.LINKS)

    def test_doc_token_does_not_affect_link_token(self):
        out = site_build.render("<a {{link:gh}}> <a {{doc:a-b_c.md}}>", self.LINKS)
        self.assertIn('<a href="https://github.com/a/b" rel="noopener">', out)
        self.assertIn('href="https://example.com/docs/a-b_c.md"', out)

    def test_link_without_docs_base_still_renders(self):
        self.assertIn("https://github.com/a/b", site_build.render("<a {{link:gh}}>", {"gh": "https://github.com/a/b"}))


class HeroCopyTest(unittest.TestCase):
    """The h1, the OG card headline, and og:image:alt must stay in sync."""

    H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.S)
    ALT_RE = re.compile(r'<meta property="og:image:alt" content="([^"]*)">')

    def _h1(self, source: str) -> str:
        match = self.H1_RE.search(source)
        self.assertIsNotNone(match, "no h1 found")
        text = html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
        return re.sub(r"\s+", " ", text).strip()

    def test_h1_matches_og_card_headline_and_image_alt(self):
        index = (SITE / "src" / "index.html").read_text(encoding="utf-8")
        og = (SITE / "og" / "og.html").read_text(encoding="utf-8")
        alt_match = self.ALT_RE.search(index)
        self.assertIsNotNone(alt_match, "no og:image:alt in index.html")
        alt_text = html.unescape(alt_match.group(1))
        headline = self._h1(og)
        self.assertEqual(headline, self._h1(index))
        self.assertEqual(headline, alt_text.removeprefix("Gargoyl: "))


class SiteTest(unittest.TestCase):
    def test_build_resolves_every_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            self.assertEqual(site_build.main(["--out", str(out)]), 0)
            page = (out / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("{{", page)
            self.assertIn('href="https://github.com/nhangen/gargoyl"', page)
            self.assertTrue((out / "fonts" / "archivo-latin-variable.woff2").is_file())

    def test_docs_page_builds_with_resolved_doc_links_and_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dist"
            self.assertEqual(site_build.main(["--out", str(out)]), 0)
            page = (out / "docs" / "index.html").read_text(encoding="utf-8")
            self.assertNotIn("{{", page)
            base = site_build.json.loads((SITE / "links.json").read_text(encoding="utf-8"))["docs_base"]
            self.assertIn(f'href="{base}contract.md" rel="noopener"', page)
            docs_dir = SITE.parent / "docs"
            names = set(re.findall(re.escape(base) + r"([a-z0-9_.-]+)\"", page))
            self.assertGreaterEqual(len(names), 13)
            for name in names:
                with self.subTest(doc=name):
                    self.assertTrue((docs_dir / name).is_file())
            for ref in re.findall(r'(?:href|src)="(/(?:styles\.css|fonts/[^"]+|icon/[^"]+))"', page):
                with self.subTest(ref=ref):
                    self.assertTrue((out / ref.lstrip("/")).is_file())
            self.assertIn('href="/docs/"', (out / "index.html").read_text(encoding="utf-8"))
            self.assertIn('<a class="header-link" href="/">', page)
            self.assertIn('<a href="/">Home</a>', page)

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
