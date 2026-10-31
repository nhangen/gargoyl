import re
import unittest
from pathlib import Path

PROTOTYPE = Path(__file__).resolve().parent.parent / 'design' / 'app'
PROTOTYPE_HOSTS = ('3f9a', '71aa', '9d40', 'b07d', 'e5c2')


class DesignPrototypeTests(unittest.TestCase):
    def pages(self):
        pages = sorted(PROTOTYPE.glob('*.html'))
        self.assertTrue(pages)
        return pages

    def test_every_page_is_labelled_synthetic(self):
        for page in self.pages():
            with self.subTest(page=page.name):
                self.assertIn('class="proto-banner"', page.read_text(encoding='utf-8'))

    def test_internal_links_resolve_and_every_host_has_a_page(self):
        for page in self.pages():
            text = page.read_text(encoding='utf-8')
            ids = set(re.findall(r'\bid="([^"]+)"', text))
            for link in re.findall(r'href="([^"]+)"', text):
                with self.subTest(page=page.name, link=link):
                    target, _, fragment = link.partition('#')
                    if target:
                        self.assertTrue((PROTOTYPE / target).is_file())
                    elif fragment:
                        self.assertIn(fragment, ids)
        overview = (PROTOTYPE / 'index.html').read_text(encoding='utf-8')
        for host in PROTOTYPE_HOSTS:
            with self.subTest(host=host):
                self.assertIn(f'href="host-{host}.html"', overview)

    def test_prototype_is_not_a_production_input(self):
        package = Path(__file__).resolve().parent.parent / 'gargoyl'
        for source in package.rglob('*.py'):
            with self.subTest(source=source.name):
                # Provenance prose may name the prototype; a path literal would load it.
                self.assertNotRegex(source.read_text(encoding='utf-8'),
                                    r"[\"'](?:\./|\.\./)*design[/\\]app|[\"']design[\"']\s*[,)/]")


if __name__ == '__main__':
    unittest.main()
