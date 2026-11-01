"""Owner-local friendly labels. Never an identity or provider-control authority."""

import fcntl
import json
import os
import stat
import unicodedata
import uuid
from pathlib import Path

from gargoyl.collector_state_file import _read
from gargoyl.fleet_account import decode_json
from gargoyl.fleet_state import MAX_PROVIDERS, _directory, text

LIMIT = 65536


def alias_text(value):
    if (
        type(value) is not str
        or len(value) > 64
        or len(value.encode("utf-8", "surrogatepass")) > 128
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    ):
        raise ValueError("invalid local alias")
    return value.strip()


def validate_aliases(value):
    if type(value) is not dict or len(value) > MAX_PROVIDERS:
        raise ValueError("invalid local aliases")
    for identity, alias in value.items():
        if text(identity) is None or any(
            unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in identity
        ):
            raise ValueError("invalid provider identity")
        if type(alias) is not str or not alias or alias_text(alias) != alias:
            raise ValueError("invalid local alias")
    return dict(value)


class AliasStore:
    def __init__(self, directory, uid):
        self.directory, self.uid = str(directory), uid

    def read(self):
        try:
            d = _directory(self.directory, self.uid)
        except FileNotFoundError:
            return {}
        os.close(d)
        try:
            value = decode_json(
                _read(str(Path(self.directory) / "aliases.json"), self.uid, LIMIT)
            )
        except FileNotFoundError:
            return {}
        if (
            type(value) is not dict
            or set(value) != {"schema", "aliases"}
            or type(value["schema"]) is not int
            or value["schema"] != 1
        ):
            raise ValueError("invalid local aliases")
        return validate_aliases(value["aliases"])

    def set(self, identity, alias, inventory):
        from gargoyl.fleet_state import validate_inventory

        validate_inventory(inventory)
        if (
            type(identity) is not str
            or sum(p["id"] == identity for p in inventory["providers"]) != 1
        ):
            raise ValueError("provider not in current inventory")
        alias = alias_text(alias)
        directory = _directory(self.directory, self.uid, create=True)
        lock = None
        temporary = ".aliases-" + uuid.uuid4().hex
        try:
            lock = os.open(
                "aliases.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            s = os.fstat(lock)
            if (
                not stat.S_ISREG(s.st_mode)
                or s.st_uid != self.uid
                or s.st_nlink != 1
                or s.st_mode & 0o077
            ):
                raise ValueError("aliases unavailable")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            values = self.read()
            if alias:
                values[identity] = alias
            else:
                values.pop(identity, None)
            validate_aliases(values)
            body = json.dumps(
                dict(schema=1, aliases=values), ensure_ascii=False
            ).encode()
            if len(body) > LIMIT:
                raise ValueError("alias limit")
            try:
                target = os.stat(
                    "aliases.json", dir_fd=directory, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(target.st_mode)
                    or target.st_uid != self.uid
                    or target.st_nlink != 1
                    or target.st_mode & 0o077
                ):
                    raise ValueError("aliases unavailable")
            except FileNotFoundError:
                pass
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            try:
                if os.write(fd, body) != len(body):
                    raise OSError("short alias write")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(
                temporary, "aliases.json", src_dir_fd=directory, dst_dir_fd=directory
            )
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            if lock is not None:
                os.close(lock)
            os.close(directory)
