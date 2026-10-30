"""Release lifecycle uses temporary app roots and self-authored wheel fixtures only."""

import hashlib
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_repair_catalog as repair_fixtures

from gargoyl.collector import collect
from gargoyl.ingestion import EvidenceStore
from gargoyl.release import (
    ReleaseError,
    inspect_release,
    install_release,
    rollback_release,
    uninstall_release,
)
from gargoyl.repair_audit import RepairAuditStore
from gargoyl.security import CollectionIdentity, RetentionPolicy, SpoolCipher

HOST = "00000000-0000-4000-8000-000000000001"
NOW = "2026-01-01T00:00:00Z"


def make_wheel(directory, version, *, additions=None, code=None):
    path = directory / f"gargoyl-{version}-py3-none-any.whl"
    info = f"gargoyl-{version}.dist-info"
    files = {"gargoyl/__init__.py": (code or f'VERSION = "{version}"\n').encode(),
             f"{info}/METADATA": f"Metadata-Version: 2.1\nName: gargoyl\nVersion: {version}\n".encode(),
             f"{info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
             f"{info}/RECORD": b""}
    files.update(additions or {})
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.root = self.parent / "application"
        self.first, self.first_sha = make_wheel(self.parent, "0.1.0")
        self.second, self.second_sha = make_wheel(self.parent, "0.2.0")

    def install(self, wheel=None, digest=None):
        return install_release(self.root, wheel or self.first, expected_sha256=digest or self.first_sha)

    def inventory(self, root=None):
        root = root or self.root
        return {path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*") if path.is_file()}

    def test_install_upgrade_rollback_uninstall_preserves_encrypted_evidence_and_audit(self):
        self.assertEqual(self.install()["active"], self.first_sha)
        key, audit_key = os.urandom(32), os.urandom(32)
        cipher = SpoolCipher(CollectionIdentity(HOST), key)
        store = EvidenceStore(self.root / "data" / "evidence", {HOST: cipher}, RetentionPolicy(), NOW)
        snapshot = collect(HOST, NOW, {})
        self.assertTrue(store.accept(snapshot, now=NOW))
        store.close()
        fixture = repair_fixtures.RepairCatalogTests()
        fixture.setUp()
        audit = RepairAuditStore(self.root / "data" / "audit", key=audit_key)
        self.assertTrue(audit.claim(fixture.plan, fixture.confirmation(), now=NOW))
        audit.close()
        before = self.inventory(self.root / "data")
        state = self.install(self.second, self.second_sha)
        self.assertEqual((state["active"], state["previous"]), (self.second_sha, self.first_sha))
        self.assertEqual(rollback_release(self.root)["active"], self.first_sha)
        self.assertEqual(uninstall_release(self.root)["releases"], {})
        self.assertEqual(self.inventory(self.root / "data"), before)
        store = EvidenceStore(self.root / "data" / "evidence", {HOST: cipher}, RetentionPolicy(), NOW)
        self.assertEqual(store.snapshots(now=NOW), [snapshot])
        store.close()
        audit = RepairAuditStore(self.root / "data" / "audit", key=audit_key)
        self.assertEqual(audit.lookup(fixture.confirmation().as_dict()["click_id"]).as_dict()["state"], "started")
        audit.close()
        self.assertEqual(self.install()["active"], self.first_sha)

    def test_hash_mismatch_and_wrong_artifact_create_nothing(self):
        for digest in ("0" * 64, True, "private-secret"):
            with self.assertRaises(ReleaseError) as caught:
                self.install(digest=digest)
            self.assertFalse(self.root.exists())
            self.assertNotIn("private-secret", str(caught.exception))
        wheel, digest = make_wheel(self.parent, "0.3.0", additions={"foreign/__init__.py": b""})
        with self.assertRaises(ReleaseError):
            self.install(wheel, digest)
        self.assertFalse(self.root.exists())

    def test_unowned_existing_empty_or_foreign_root_refused_unchanged(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaises(ReleaseError):
            self.install()
        (self.root / "foreign.txt").write_bytes(b"synthetic-foreign-data")
        before = self.inventory()
        for action in (lambda: self.install(), lambda: rollback_release(self.root), lambda: uninstall_release(self.root)):
            with self.assertRaises(ReleaseError):
                action()
            self.assertEqual(self.inventory(), before)

    def test_darkbloom_and_symlink_roots_or_ancestors_refused(self):
        for name in ("darkbloom", ".Darkbloom"):
            with self.assertRaises(ReleaseError):
                install_release(self.parent / name, self.first, expected_sha256=self.first_sha)
            self.assertFalse((self.parent / name).exists())
        target = self.parent / "foreign"
        target.mkdir()
        (self.parent / "link").symlink_to(target, target_is_directory=True)
        with self.assertRaises(ReleaseError):
            install_release(self.parent / "link" / "new", self.first, expected_sha256=self.first_sha)
        self.assertEqual(list(target.iterdir()), [])

    def test_unknown_modified_symlink_and_hardlinked_code_prevent_all_mutation(self):
        self.install()
        code = self.root / "releases" / self.first_sha / "gargoyl" / "__init__.py"
        original = code.read_bytes()
        code.write_bytes(b"synthetic-modification")
        before = self.inventory()
        for action in (lambda: self.install(self.second, self.second_sha), lambda: rollback_release(self.root),
                       lambda: uninstall_release(self.root)):
            with self.assertRaises(ReleaseError):
                action()
            self.assertEqual(self.inventory(), before)
        code.write_bytes(original)
        foreign = self.root / "foreign.txt"
        foreign.write_bytes(b"preserve")
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)
        foreign.unlink()
        code.unlink()
        code.symlink_to(self.first)
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)
        code.unlink()
        os.link(self.first, code)
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)
        self.assertEqual(self.first.read_bytes(), code.read_bytes())

    def test_traversal_symlink_duplicate_and_oversize_wheels_rejected_before_root(self):
        wheel, digest = make_wheel(self.parent, "0.3.0", additions={"../escape": b"x"})
        with self.assertRaises(ReleaseError):
            self.install(wheel, digest)
        wheel, digest = make_wheel(self.parent, "0.4.0", additions={"gargoyl/huge.py": b"x" * (1024 * 1024 + 1)})
        with self.assertRaises(ReleaseError):
            self.install(wheel, digest)
        wheel, _ = make_wheel(self.parent, "0.5.0")
        with zipfile.ZipFile(wheel, "a") as archive:
            entry = zipfile.ZipInfo("gargoyl/link.py")
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, b"../../foreign")
        with self.assertRaises(ReleaseError):
            self.install(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest())
        self.assertFalse(self.root.exists())
        self.assertFalse((self.parent / "escape").exists())

    def test_repeat_or_third_install_refuses_without_pruning(self):
        self.install()
        with self.assertRaises(ReleaseError):
            self.install()
        with self.assertRaises(ReleaseError):
            rollback_release(self.root)
        self.install(self.second, self.second_sha)
        third, digest = make_wheel(self.parent, "0.3.0")
        before = self.inventory()
        with self.assertRaises(ReleaseError):
            self.install(third, digest)
        self.assertEqual(self.inventory(), before)

    def test_failed_activation_retains_old_pointer_and_refuses_uncertain_state(self):
        self.install()
        old = (self.root / "state.json").read_bytes()
        with patch("gargoyl.release._write_state", side_effect=OSError("private-disk-detail")):
            with self.assertRaises(ReleaseError) as caught:
                self.install(self.second, self.second_sha)
        self.assertNotIn("private-disk-detail", str(caught.exception))
        self.assertEqual((self.root / "state.json").read_bytes(), old)
        self.assertTrue((self.root / "releases" / self.second_sha).exists())
        with self.assertRaises(ReleaseError):
            inspect_release(self.root)
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)

    def test_duplicate_members_and_nonpure_wheel_are_refused(self):
        import warnings
        wheel, _ = make_wheel(self.parent, "0.6.0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("gargoyl/__init__.py", b"duplicate")
        with self.assertRaises(ReleaseError):
            self.install(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest())
        wheel, digest = make_wheel(self.parent, "0.7.0", additions={
            "gargoyl-0.7.0.dist-info/WHEEL": b"Root-Is-Purelib: false\nTag: cp312-linux_x86_64\n"})
        with self.assertRaises(ReleaseError):
            self.install(wheel, digest)
        self.assertFalse(self.root.exists())

    def test_corrupt_inventory_and_unexpected_empty_directory_refused(self):
        self.install()
        extra = self.root / "releases" / self.first_sha / "foreign-empty"
        extra.mkdir()
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)
        self.assertTrue(extra.exists())
        extra.rmdir()
        (self.root / "state.json").write_bytes(b'{"application":"gargoyl","application":"foreign"}')
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)
        self.assertTrue((self.root / "releases" / self.first_sha / "gargoyl" / "__init__.py").exists())

    def test_concurrent_lock_refuses_without_changes(self):
        import fcntl
        self.install()
        before = self.inventory()
        with (self.root / ".lock").open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ReleaseError):
                self.install(self.second, self.second_sha)
            with self.assertRaises(ReleaseError):
                uninstall_release(self.root)
        self.assertEqual(self.inventory(), before)

    def test_uninstall_failure_preserves_data_and_blocks_automatic_retry(self):
        self.install()
        marker = self.root / "data" / "opaque-state"
        marker.write_bytes(b"synthetic-encrypted-placeholder")
        original = Path.unlink
        removed = []
        def partial(path, *args, **kwargs):
            if removed:
                raise OSError("private-uninstall-detail")
            removed.append(path)
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", partial):
            with self.assertRaises(ReleaseError):
                uninstall_release(self.root)
        self.assertEqual(marker.read_bytes(), b"synthetic-encrypted-placeholder")
        with self.assertRaises(ReleaseError):
            uninstall_release(self.root)

    def test_case_collision_file_directory_collision_and_excess_directory_count(self):
        cases = ({"gargoyl/A.py": b"", "gargoyl/a.py": b""},
                 {"gargoyl/a.py": b"", "gargoyl/a.py/b.py": b""},
                 {"gargoyl/d" + str(i) + "/" + "p/" * 100 + "m.py": b"" for i in range(12)})
        for additions in cases:
            wheel, digest = make_wheel(self.parent, "0.8.0", additions=additions)
            with self.assertRaises(ReleaseError):
                self.install(wheel, digest)
            self.assertFalse(self.root.exists())
