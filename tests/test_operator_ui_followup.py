import unittest
from html.parser import HTMLParser
from pathlib import Path

from test_dashboard import HOST, NOW

from gargoyl.dashboard import render_dashboard


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.append(dict(attrs).get("href", ""))


class OperatorUiTests(unittest.TestCase):
    def test_live_jump_targets_actual_host_table(self):
        page = render_dashboard([], [HOST], NOW)
        self.assertIn('href="#hosts-table">Jump to hosts</a>', page)
        self.assertIn('id="hosts-table"', page)
        self.assertNotIn("Synthetic prototype", page)

    def test_every_prototype_has_visible_label_and_no_false_refresh_claim(self):
        root = Path(__file__).resolve().parents[1] / "design/app"
        for path in root.glob("*.html"):
            with self.subTest(file=path.name):
                text = path.read_text()
                label = text.index("Synthetic prototype")
                self.assertLess(label, text.index("<h1>"))
                self.assertNotIn("Refreshes every", text)
                self.assertNotIn("This page retries automatically", text)
                parsed = Links()
                parsed.feed(text)
                for href in parsed.links:
                    if href and not href.startswith("#"):
                        self.assertTrue((root / href.split("#")[0]).is_file(), href)
        page = (root / "index.html").read_text()
        for host in ("3f9a", "b07d"):
            self.assertIn('href="host-' + host + '.html"', page)
