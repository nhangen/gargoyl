"""Owner-local installation policy; no discovery, provisioning or action execution.

Absent policy preserves the approved MBP pilot. A policy may describe one local
owner/host, never a remote target, and may only narrow the reviewed version set.
Installing policy for another machine is separate from this implementation.
"""
import json
import os
import pwd
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.telemetry import host_id

PILOT_HOST = '00000000-0000-4000-8000-000000000001'
MAX_POLICY_BYTES = 8192


def require(condition):
    if not condition:
        raise ValueError('pilot configuration unavailable')


@dataclass(frozen=True)
class PilotConfiguration:
    owner_uid: int
    hostname: str
    host_id: str
    source: str
    provider_executable: str
    monitor_executable: str
    versions: frozenset

    def require_local(self, uid=None):
        require(self.owner_uid == os.getuid() == (os.getuid() if uid is None else uid)
                and self.hostname == os.uname().nodename)
        return self


def defaults(home, python):
    # Resolve the directory, not the venv Python symlink (which points outside it).
    cli = str(Path(python).parent.resolve(strict=True) / 'gargoyl')
    return PilotConfiguration(501, 'MBP-2026.local', PILOT_HOST,
                              str(home / '.darkbloom/daemon-state.json'),
                              str(home / '.darkbloom/Darkbloom.app/Contents/MacOS/darkbloom'),
                              cli, frozenset(SUPPORTED_VERSIONS))


def validate_policy(value, baseline):
    require(type(value) is dict and set(value) == {
        'schema', 'owner_uid', 'hostname', 'host_id', 'source',
        'provider_executable', 'monitor_executable', 'versions'})
    require(type(value['schema']) is int and value['schema'] == 1)
    require(type(value['owner_uid']) is int and 0 < value['owner_uid'] < 2**32-1)
    require(type(value['hostname']) is str and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', value['hostname']) is not None)
    host_id(value['host_id'])
    # Current integration supports only this inspected provider layout and the
    # interpreter's own sibling CLI; config cannot select arbitrary commands.
    for key in ('source', 'provider_executable', 'monitor_executable'):
        require(value[key] == getattr(baseline, key))
    versions = value['versions']
    require(type(versions) is dict and 0 < len(versions) <= len(SUPPORTED_VERSIONS))
    require(all(k in SUPPORTED_VERSIONS and type(v) is str and
                v == SUPPORTED_VERSIONS[k] for k, v in versions.items()))
    return PilotConfiguration(value['owner_uid'], value['hostname'], value['host_id'],
                              value['source'], value['provider_executable'],
                              value['monitor_executable'], frozenset(versions))


def load_pilot_configuration(*, home=None, python=None):
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True) if home is None else Path(home)
    require(home.is_absolute() and home.resolve(strict=True) == home)
    baseline = defaults(home, sys.executable if python is None else python)
    parent = home / 'Library/Application Support/Gargoyl'
    require(parent.resolve() == parent)
    try:
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return baseline
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        try:
            fd = os.open('pilot.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return baseline
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                    and 0 < before.st_size <= MAX_POLICY_BYTES)
            payload = os.read(fd, MAX_POLICY_BYTES + 1)
            after = os.fstat(fd)
            require(len(payload) <= MAX_POLICY_BYTES and
                    (before.st_ino, before.st_size, before.st_mtime_ns) ==
                    (after.st_ino, after.st_size, after.st_mtime_ns))
        finally:
            os.close(fd)
    finally:
        os.close(directory)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=unique)
        return validate_policy(value, baseline).require_local()
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ValueError('pilot configuration unavailable') from None
