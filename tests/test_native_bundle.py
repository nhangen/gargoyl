"""Build/seal temporary bundles only. Never launch code or access credentials."""
import io
import plistlib
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from struct import unpack_from
from unittest.mock import Mock, patch


class NativeBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.python = self.root / '.venv/bin/python'
        self.python.parent.mkdir(parents=True)
        self.python.write_text('synthetic path; never executed')
        self.builder = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/build_macos_app.py'))['build']

    def build(self, runner=None, **options):
        replacements = dict(load_pilot_configuration=Mock(return_value=Mock()),
                            SWIFT='import Foundation\nprint("synthetic; never executed")\n')
        with patch.dict(self.builder.__globals__, replacements), patch('sys.platform', 'darwin'):
            if runner is not None:
                with patch('subprocess.run', runner):
                    return self.builder(self.root / 'output', self.python, **options)
            return self.builder(self.root / 'output', self.python, **options)

    def test_build_mode_stamp_matches_requested_mode(self):
        for options, mode, legacy in (({}, 'preview', True), ({'preview': False}, 'native-actions', False)):
            with self.subTest(mode=mode):
                shutil.rmtree(self.root / 'output', ignore_errors=True)
                with redirect_stdout(io.StringIO()):
                    app = self.build(Mock(), **options)
                values = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
                self.assertEqual((values['GargoylBuildMode'], values['GargoylReadOnlyPreview']), (mode, legacy))

    def test_metadata_exists_before_sealing_and_failure_never_reports_success(self):
        def run(command, **options):
            self.assertTrue(options['check'])
            if command[0] == '/usr/bin/codesign':
                self.assertEqual(plistlib.loads((self.root / 'output/Gargoyl.app/Contents/Info.plist').read_bytes())['GargoylReadOnlyPreview'], True)
                raise subprocess.CalledProcessError(1, command)
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(subprocess.CalledProcessError):
            self.build(Mock(side_effect=run))
        self.assertEqual(output.getvalue(), '')

    @unittest.skipUnless(sys.platform == 'darwin', 'Apple codesign required')
    def test_real_bundle_seal_covers_metadata_and_detects_tampering(self):
        app = self.build()
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True, capture_output=True)
        info = app / 'Contents/Info.plist'
        metadata = info.read_bytes()
        values = plistlib.loads(metadata)
        self.assertTrue(values['GargoylReadOnlyPreview'])
        self.assertEqual(values['CFBundleIconFile'], 'gargoyl.icns')
        icon = app / 'Contents/Resources' / values['CFBundleIconFile']
        data = icon.read_bytes()
        self.assertEqual(unpack_from('>4sI4sI', data), (b'icns', len(data), b'ic09', len(data) - 8))
        subprocess.run(['/usr/bin/sips', '-s', 'format', 'png', str(icon),
                        '--out', str(self.root / 'decoded.png')], check=True, capture_output=True)
        self.assertTrue((self.root / 'decoded.png').is_file())
        values['CFBundleName'] = 'tampered fixture'
        info.write_bytes(plistlib.dumps(values))
        check = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], capture_output=True)
        self.assertNotEqual(check.returncode, 0)
        info.write_bytes(metadata)
        icon.write_bytes(data + b'tampered fixture')
        check = subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], capture_output=True)
        self.assertNotEqual(check.returncode, 0)
