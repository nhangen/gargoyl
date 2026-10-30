"""Narrow console metadata acceptance; no execution during lifecycle extraction."""

import tempfile
import unittest
from pathlib import Path

from test_release import make_wheel

from gargoyl.release import ReleaseError, install_release, uninstall_release

ENTRY = b'[console_scripts]\ngargoyl = gargoyl.cli:main\n'


class ReleaseConsoleTests(unittest.TestCase):
    def test_exact_mapping_is_inert_and_no_wrapper_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'app'
            wheel, digest = make_wheel(parent, '0.1.0', additions={
                'gargoyl/cli.py': b'raise RuntimeError("must never execute")\n',
                'gargoyl-0.1.0.dist-info/entry_points.txt': ENTRY})
            self.assertEqual(install_release(root, wheel, expected_sha256=digest)['active'], digest)
            self.assertEqual((root / 'releases' / digest / 'gargoyl-0.1.0.dist-info' / 'entry_points.txt').read_bytes(), ENTRY)
            self.assertFalse((root / 'bin').exists())
            self.assertFalse((root / 'releases' / digest / 'bin').exists())
            self.assertIsNone(uninstall_release(root)['active'])

    def test_extra_duplicate_malformed_or_alternate_metadata_is_rejected(self):
        cases = [b'', ENTRY + b'other = gargoyl.cli:main\n', ENTRY * 2,
                 ENTRY + b'gargoyl = gargoyl.cli:main\n',
                 ENTRY.replace(b'console_scripts', b'gui_scripts'),
                 ENTRY.replace(b'gargoyl =', b'foreign ='),
                 ENTRY.replace(b'cli:main', b'cli:evil'),
                 ENTRY.replace(b'\n', b'\r\n'), ENTRY + b'\0',
                 ENTRY + b'\xff', ENTRY + b'#comment\n', b'x' * 65536]
        for content in cases:
            with self.subTest(content=content[:60]), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                wheel, digest = make_wheel(parent, '0.1.0', additions={
                    'gargoyl/cli.py': b'def main(): pass\n',
                    'gargoyl-0.1.0.dist-info/entry_points.txt': content})
                with self.assertRaises(ReleaseError):
                    install_release(parent / 'app', wheel, expected_sha256=digest)
                self.assertFalse((parent / 'app').exists())

    def test_declared_console_requires_target_module(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            wheel, digest = make_wheel(parent, '0.1.0', additions={
                'gargoyl-0.1.0.dist-info/entry_points.txt': ENTRY})
            with self.assertRaises(ReleaseError):
                install_release(parent / 'app', wheel, expected_sha256=digest)
            self.assertFalse((parent / 'app').exists())
