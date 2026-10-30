"""Offline, hash-pinned POSIX wheel lifecycle in an explicit application-owned root.

No dependency downloads, service setup, key management, or host operations. A
trusted parent directory and exclusive cooperating users are required; this is
not protection against a privileged owner changing paths during an operation.
"""

import argparse
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile
from contextlib import contextmanager
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

MAX_WHEEL_BYTES = 8 * 1024 * 1024
MAX_RELEASE_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 512
_HEX = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")


class ReleaseError(ValueError):
    """Fixed safe error; filesystem paths and artifact contents are not echoed."""


def _need(ok):
    if not ok:
        raise ReleaseError("release operation refused")


def _sha(value):
    _need(type(value) is str and _HEX.fullmatch(value) is not None)


def _file(path, *, limit=MAX_FILE_BYTES):
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit)
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    _need(len(value) <= limit)
    return value


def _safe_root(root):
    root = Path(root)
    _need(root.is_absolute() and ".." not in root.parts)
    _need(not any(part.casefold() in {"darkbloom", ".darkbloom"} for part in root.parts))
    for ancestor in [root, *root.parents]:
        if ancestor.exists() or ancestor.is_symlink():
            _need(not ancestor.is_symlink())
    return root


def _private_dir(path):
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0)


def _member(name, version):
    _need(type(name) is str and len(name) <= 255 and name.isascii() and "\\" not in name)
    path = PurePosixPath(name)
    _need(not path.is_absolute() and str(path) == name and ".." not in path.parts)
    _need(all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in path.parts))
    metadata = f"gargoyl-{version}.dist-info"
    allowed = (len(path.parts) >= 2 and path.parts[0] == "gargoyl"
               and path.suffix in {".py", ".md"})
    allowed = allowed or (len(path.parts) == 2 and path.parts[0] == metadata
                         and path.parts[1] in {"METADATA", "WHEEL", "RECORD", "top_level.txt"})
    _need(allowed)


def _wheel(wheel, expected_sha256):
    _sha(expected_sha256)
    payload = _file(Path(wheel), limit=MAX_WHEEL_BYTES)
    _need(hashlib.sha256(payload).hexdigest() == expected_sha256)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()
        _need(1 <= len(members) <= MAX_FILES and len({x.filename for x in members}) == len(members))
        _need(sum(x.file_size for x in members) <= MAX_RELEASE_BYTES)
        for item in members:
            _need(item.orig_filename == item.filename and not item.is_dir()
                  and 0 <= item.file_size <= MAX_FILE_BYTES and not item.flag_bits & 1
                  and stat.S_IFMT(item.external_attr >> 16) in {0, stat.S_IFREG})
        metadata = [x for x in members if re.fullmatch(r"gargoyl-[0-9.]+\.dist-info/METADATA", x.filename)]
        _need(len(metadata) == 1)
        parsed = BytesParser().parsebytes(archive.read(metadata[0]))
        versions = parsed.get_all("Version", [])
        _need(parsed.get_all("Name", []) == ["gargoyl"] and len(versions) == 1)
        version = versions[0]
        _need(_VERSION.fullmatch(version) is not None)
        names = {x.filename for x in members}
        required = {"gargoyl/__init__.py", f"gargoyl-{version}.dist-info/METADATA",
                    f"gargoyl-{version}.dist-info/WHEEL", f"gargoyl-{version}.dist-info/RECORD"}
        _need(required <= names)
        files = {}
        for item in members:
            _member(item.filename, version)
            files[item.filename] = archive.read(item)
        directories = _parents(files)
        all_paths = set(files) | directories
        _need(not set(files) & directories and len(all_paths) <= MAX_FILES * 2
              and len({name.casefold() for name in all_paths}) == len(all_paths))
        wheel_metadata = BytesParser().parsebytes(files[f"gargoyl-{version}.dist-info/WHEEL"])
        _need(wheel_metadata.get_all("Root-Is-Purelib", []) == ["true"]
              and wheel_metadata.get_all("Tag", []) == ["py3-none-any"])
        return version, files


def _tree(path):
    """Bounded code inventory; never traverse data, links or foreign assets."""
    files, directories, stack = {}, set(), [path]
    count, total = 0, 0
    while stack:
        parent = stack.pop()
        for entry in parent.iterdir():
            count += 1
            _need(count <= MAX_FILES * 2)
            name = entry.relative_to(path).as_posix()
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                directories.add(name)
                stack.append(entry)
            else:
                data = _file(entry)
                total += len(data)
                _need(total <= MAX_RELEASE_BYTES)
                files[name] = hashlib.sha256(data).hexdigest()
    return files, directories


def _parents(names):
    return {parent.as_posix() for name in names for parent in PurePosixPath(name).parents
            if parent != PurePosixPath(".")}


def _json(payload):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _need(key not in value)
            value[key] = item
        return value
    return json.loads(payload.decode("utf-8"), object_pairs_hook=unique)


def _state(root):
    _private_dir(root)
    _need({p.name for p in root.iterdir()} == {"state.json", ".lock", "releases", "data"})
    _private_dir(root / "releases")
    _private_dir(root / "data")
    _need(_file(root / ".lock") == b"")
    value = _json(_file(root / "state.json"))
    _need(type(value) is dict and set(value) == {"application", "schema_version", "active", "previous", "releases"})
    _need(value["application"] == "gargoyl" and type(value["schema_version"]) is int
          and value["schema_version"] == 1 and type(value["releases"]) is dict
          and len(value["releases"]) <= 2)
    releases = value["releases"]
    for field in ("active", "previous"):
        _need(value[field] is None or type(value[field]) is str and value[field] in releases)
    _need((not releases and value["active"] is None and value["previous"] is None)
          or (bool(releases) and value["active"] in releases
              and value["previous"] != value["active"]
              and (len(releases) == 1) == (value["previous"] is None)))
    _need({p.name for p in (root / "releases").iterdir()} == set(releases))
    for checksum, release in releases.items():
        _sha(checksum)
        _need(type(release) is dict and set(release) == {"version", "files"})
        version, files = release["version"], release["files"]
        _need(type(version) is str and _VERSION.fullmatch(version) is not None
              and type(files) is dict and 1 <= len(files) <= MAX_FILES)
        for name, digest in files.items():
            _member(name, version)
            _sha(digest)
        path = root / "releases" / checksum
        _private_dir(path)
        actual, directories = _tree(path)
        _need(actual == files and directories == _parents(files))
    return value


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_state(root, state):
    payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
    _need(len(payload) <= MAX_FILE_BYTES)
    temp = root / ".state-pending"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, root / "state.json")
    _sync_directory(root)


def _initialize(root):
    # Claim only a nonexistent directory, never a preexisting empty/foreign path.
    root.mkdir(mode=0o700, parents=False)
    (root / "releases").mkdir(mode=0o700)
    (root / "data").mkdir(mode=0o700)
    fd = os.open(root / ".lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    _write_state(root, dict(application="gargoyl", schema_version=1,
                           active=None, previous=None, releases={}))


@contextmanager
def _locked(root):
    _state(root)  # Refuse unowned paths before opening even the lock file.
    fd = os.open(root / ".lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield _state(root)
    finally:
        os.close(fd)


def _safe_call(operation):
    try:
        return operation()
    except Exception:
        raise ReleaseError("release operation refused; inspect state before retry") from None


def inspect_release(root):
    def operation():
        path = _safe_root(root)
        with _locked(path) as state:
            return state  # Detached JSON; no private paths or data contents.
    return _safe_call(operation)


def install_release(root, wheel, *, expected_sha256):
    """Install/activate a trusted pinned wheel, retain at most one prior release.

    Wheel validation precedes filesystem changes. Dependency installation and
    trusted-artifact provenance are caller responsibilities; SHA256 is not a signature.
    """
    def operation():
        path = _safe_root(root)
        version, files = _wheel(wheel, expected_sha256)
        if not path.exists():
            _initialize(path)
        with _locked(path) as state:
            _need(expected_sha256 not in state["releases"] and len(state["releases"]) < 2)
            staging = path / ".release-pending"
            staging.mkdir(mode=0o700)
            for name, payload in files.items():
                destination = staging / name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            for name in sorted(_parents(files), key=lambda x: len(PurePosixPath(x).parts), reverse=True):
                _sync_directory(staging / name)
            _sync_directory(staging)
            os.rename(staging, path / "releases" / expected_sha256)
            _sync_directory(path / "releases")
            state["releases"][expected_sha256] = {
                "version": version,
                "files": {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
            }
            state["previous"], state["active"] = state["active"], expected_sha256
            _write_state(path, state)
            return state
    return _safe_call(operation)


def rollback_release(root):
    def operation():
        path = _safe_root(root)
        with _locked(path) as state:
            _need(state["previous"] is not None)
            state["active"], state["previous"] = state["previous"], state["active"]
            _write_state(path, state)
            return state
    return _safe_call(operation)


def uninstall_release(root):
    """Remove only verified code; preserve root ownership and ALL data contents."""
    def operation():
        path = _safe_root(root)
        with _locked(path) as state:
            for checksum, release in state["releases"].items():
                directory = path / "releases" / checksum
                for name in release["files"]:
                    (directory / name).unlink()
                for name in sorted(_parents(release["files"]), key=lambda x: len(PurePosixPath(x).parts), reverse=True):
                    (directory / name).rmdir()
                directory.rmdir()
            state.update(active=None, previous=None, releases={})
            _write_state(path, state)
            return state
    return _safe_call(operation)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Gargoyl release lifecycle; explicit approved root required")
    parser.add_argument("action", choices=("install", "inspect", "rollback", "uninstall"))
    parser.add_argument("root")
    parser.add_argument("--wheel")
    parser.add_argument("--sha256")
    args = parser.parse_args(argv)
    try:
        if args.action == "install":
            _need(args.wheel is not None and args.sha256 is not None)
            result = install_release(args.root, args.wheel, expected_sha256=args.sha256)
        else:
            _need(args.wheel is None and args.sha256 is None)
            result = {"inspect": inspect_release, "rollback": rollback_release,
                      "uninstall": uninstall_release}[args.action](args.root)
        print(json.dumps({"active": result["active"], "previous": result["previous"], "data_preserved": True}))
        return 0
    except ReleaseError:
        print("Release operation refused; inspect state before retry.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
