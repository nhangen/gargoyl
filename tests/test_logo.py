"""Check that app surfaces and the icon renderer use the canonical mark."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
NAMESPACE = "http://www.w3.org/2000/svg"
ICON_LINKS = (
    ('rel="icon"', "../../assets/icon/favicon.svg"),
    ('rel="apple-touch-icon"', "../../assets/icon/apple-touch-icon.png"),
)

spec = importlib.util.spec_from_file_location("render_icons", ASSETS / "render_icons.py")
render_icons = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_icons)


def paths(svg):
    return [path.get("d") for path in svg.iter(f"{{{NAMESPACE}}}path")]


class MarkConsistencyTests(unittest.TestCase):
    def test_svg_icons_match_the_canonical_geometry(self):
        mark = paths(ET.parse(ASSETS / "gargoyle.svg").getroot())
        self.assertEqual(len(mark), 2)
        for file in ("favicon.svg", "icon-maskable-512.svg"):
            with self.subTest(file=file):
                self.assertEqual(paths(ET.parse(ASSETS / "icon" / file).getroot()), mark)

    def test_inline_headers_match_and_design_app_pages_link_to_icons(self):
        mark = paths(ET.parse(ASSETS / "gargoyle.svg").getroot())
        pages = sorted((ROOT / "design/app").glob("*.html"))
        self.assertIn(ROOT / "design/app/index.html", pages)
        for page in [*pages, ROOT / "site/src/index.html", ROOT / "site/og/og.html"]:
            with self.subTest(page=page.name):
                html = page.read_text(encoding="utf-8")
                for shape in mark:
                    self.assertIn(f'd="{shape}"', html)
                if page in pages:
                    for rel, href in ICON_LINKS:
                        self.assertIn(f'{rel} href="{href}"', html)
                        self.assertTrue((page.parent / href).is_file())

    def test_renderer_uses_edited_source_in_both_icon_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mark = root / "mark.svg"
            mark.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
                '<path d="M2 3L8 9"/><path d="M20 20L30 30"/></svg>',
                encoding="utf-8",
            )
            with (
                patch.multiple(render_icons, MARK=mark, HERE=root, OUT=root / "icons",
                               FAVICON_MODULE=root / "favicon.py"),
                patch.object(render_icons.shutil, "which", return_value="/fixture/rsvg-convert"),
                patch.object(render_icons, "render_png", return_value=b"fixture") as rasterize,
            ):
                self.assertEqual(render_icons.main(), 0)
            for call in rasterize.call_args_list:
                self.assertEqual(paths(ET.fromstring(call.args[1])), ["M2 3L8 9", "M20 20L30 30"])
            self.assertEqual(rasterize.call_count, 4)
            for file in ("favicon.svg", "icon-maskable-512.svg"):
                self.assertEqual(paths(ET.parse(root / "icons" / file).getroot()),
                                 ["M2 3L8 9", "M20 20L30 30"])
