"""Real subprocess exit checks for clean, direct-warning and finalizer-leak tests."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[1] / 'tools/run_tests.py'


class ResourceWarningRunnerTests(unittest.TestCase):
    def run_fixture(self, body):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test_fixture.py').write_text('import unittest,gc,sqlite3,warnings\n'
                                                'class Fixture(unittest.TestCase):\n'
                                                ' def test_fixture(self):\n' +
                                                '\n'.join('  ' + line for line in body.splitlines()) + '\n')
            return subprocess.run([sys.executable, str(RUNNER), 'discover', '-s', str(root), '-v'],
                                  cwd=root, capture_output=True, text=True, timeout=15,
                                  env={**os.environ, 'PYTHONWARNINGS': 'ignore'})

    def test_clean_fixture_passes(self):
        result = self.run_fixture("with sqlite3.connect(':memory:') as c:\n c.execute('SELECT 1')\nc.close()")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runner_imports_this_checkout_not_an_installed_package(self):
        result = self.run_fixture("import gargoyl,pathlib\n"
                                  "self.assertEqual(str(pathlib.Path(gargoyl.__file__).resolve().parents[1]), "
                                  + repr(str(RUNNER.parents[1])) + ")")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_resource_warning_fails_despite_inherited_ignore(self):
        result = self.run_fixture("warnings.warn('synthetic warning',ResourceWarning)")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('FAILED', result.stderr)

    def test_unclosed_file_finalizer_fails_even_when_unittest_reports_ok(self):
        result = self.run_fixture("f=open(__file__,'rb')\ndel f\ngc.collect()")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('unraisable ResourceWarning', result.stderr)
        self.assertIn('OK', result.stderr)

    @unittest.skipUnless(sys.version_info >= (3, 13), 'sqlite finalizer ResourceWarning added in3.13')
    def test_sqlite_finalizer_leak_fails(self):
        result = self.run_fixture("c=sqlite3.connect(':memory:')\ndel c\ngc.collect()")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('unraisable ResourceWarning', result.stderr)
