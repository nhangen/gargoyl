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
import tempfile
from dataclasses import dataclass
from pathlib import Path

from gargoyl.darkbloom_compatibility import SUPPORTED_VERSIONS
from gargoyl.telemetry import host_id

PILOT_HOST = '00000000-0000-4000-8000-000000000001'
MAX_POLICY_BYTES = 8192
SCHEMA = 2
ALLOWED_GRANTS = (
    (),
    ('provider_executable',),
    ('provider_executable', 'operator_tools'),
    ('provider_executable', 'operator_tools', 'restart'),
    ('provider_executable', 'operator_tools', 'restart', 'account_read_only'),
    ('account_read_only',),
    ('provider_executable', 'account_read_only'),
    ('provider_executable', 'operator_tools', 'account_read_only'),
)
# An install that has never recorded grants keeps the approved pilot: the monitor
# runs with provider diagnostics, and manual restart and the read-only account
# remain available behind their own confirmations. Recording grants ends this.
LEGACY_GRANTS = ('provider_executable',)
LEGACY_PERMITS = ('provider_executable', 'restart', 'account_read_only')


def grant_flags(grants, provider_executable=None):
    """Map one grant set to the exact monitor CLI flags; the dependency chain is fixed.

    Each grant maps 1:1 to a flag; the flag order follows the reviewed monitor
    argument order. ``account_read_only`` grants nothing at the monitor level:
    the account scope is read-only by construction and adds no flag.
    """
    if grants not in ALLOWED_GRANTS:
        raise ValueError('grant sequence unavailable')
    if 'provider_executable' in grants:
        yield '--provider-executable'
        if provider_executable is not None:
            yield str(provider_executable)
        yield '--coordinator-errors'
    if 'operator_tools' in grants:
        yield '--operator-tools'
    if 'restart' in grants:
        yield '--enable-restart'


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
    grants: tuple = LEGACY_GRANTS
    recorded: bool = False

    def permits(self, capability):
        return capability in (self.grants if self.recorded else LEGACY_PERMITS)

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
    schema = value.get('schema') if type(value) is dict else None
    base_keys = {'schema', 'owner_uid', 'hostname', 'host_id', 'source',
                 'provider_executable', 'monitor_executable', 'versions'}
    if schema == 1:
        grants = LEGACY_GRANTS
    elif schema == 2:
        grants = validate_grants(value.get('grants'))
    else:
        raise ValueError('pilot configuration unavailable')
    require(type(value) is dict and set(value) == base_keys | ({'grants'} if schema == 2 else set()))
    require(type(value['schema']) is int and value['schema'] in (1, 2))
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
                              value['monitor_executable'], frozenset(versions), grants,
                              schema == 2)


def validate_grants(value):
    """A grant is an explicit per-capability choice, not a value; the list order is fixed."""
    if value is None:
        return ()
    if type(value) not in (list, tuple) or not all(type(name) is str for name in value):
        raise ValueError('pilot configuration unavailable')
    if tuple(value) not in ALLOWED_GRANTS:
        raise ValueError('pilot configuration unavailable')
    return tuple(value)


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


def save_pilot_grants(*, home, python, grants):
    """Persist one explicit per-capability grant set as a schema-2 pilot policy.

    The write is atomic (rename over a 0o600 single-link file in the 0o700
    directory) and refuses to run when the directory, file, identity or grants
    are not exactly the reviewed local configuration. Only ``grants`` changes: an
    existing policy's owner, host, telemetry identity and narrowed versions carry
    over unchanged. Revocation is the empty tuple; any change is a fresh grant set.
    """
    home = Path(home)
    require(home.is_absolute() and home.resolve(strict=True) == home)
    baseline = defaults(home, sys.executable if python is None else python)
    grants = validate_grants(tuple(grants))
    parent = home / 'Library/Application Support/Gargoyl'
    require(os.geteuid() == os.getuid())
    try:
        parent.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise ValueError('pilot configuration unavailable') from None
    require(parent.resolve() == parent)
    # A present policy must already be a reviewed one before grants change it.
    current = load_pilot_configuration(home=home, python=python)
    present = (parent / 'pilot.json').exists()
    policy = dict(
        schema=SCHEMA,
        owner_uid=current.owner_uid if present else os.getuid(),
        hostname=current.hostname if present else os.uname().nodename,
        host_id=current.host_id if present else baseline.host_id,
        source=baseline.source,
        provider_executable=baseline.provider_executable,
        monitor_executable=baseline.monitor_executable,
        versions={k: SUPPORTED_VERSIONS[k] for k in sorted(current.versions)} if present
        else dict(SUPPORTED_VERSIONS),
        grants=list(grants),
    )
    write_pilot_payload(home=home, payload=json.dumps(policy, separators=(',', ':')).encode())
    return load_pilot_configuration(home=home, python=python)


def read_pilot_payload(*, home):
    """Return the current policy bytes, or None when absent, for an exact rollback."""
    try:
        return (Path(home) / 'Library/Application Support/Gargoyl/pilot.json').read_bytes()
    except FileNotFoundError:
        return None


def write_pilot_payload(*, home, payload):
    """Atomically replace pilot.json with ``payload``; None removes it."""
    parent = Path(home) / 'Library/Application Support/Gargoyl'
    require(payload is None or len(payload) <= MAX_POLICY_BYTES)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        target = os.path.join(str(parent), 'pilot.json')
        if payload is None:
            try:
                os.unlink(target)
            except FileNotFoundError:
                pass
        else:
            handle, temp = tempfile.mkstemp(prefix='pilot-', suffix='.json', dir=str(parent))
            try:
                with os.fdopen(handle, 'wb') as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temp, 0o600)
                os.replace(temp, target)
            except Exception:
                os.unlink(temp)
                raise
        os.fsync(fd)
    finally:
        os.close(fd)
