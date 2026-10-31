import unittest
from pathlib import Path


class PrototypeRefreshTests(unittest.TestCase):
    def test_static_reference_never_claims_automatic_refresh_or_retry(self):
        root = Path(__file__).resolve().parents[1] / 'design/app'
        for path in root.glob('*.html'):
            with self.subTest(file=path.name):
                text = path.read_text()
                self.assertNotIn('Refreshes every', text)
                self.assertNotIn('This page retries automatically', text)
