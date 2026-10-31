"""Read-only Darwin birth-identity verification for an explicitly configured image.

No ps, commands, signalling or permission changes. A denied or unavailable native
query is a refusal. Kernel-call latency is not forcibly bounded by Python.
"""

import ctypes
import os
import sys
from pathlib import Path

from gargoyl.repair_contract import require
from gargoyl.repair_restart_contract import process_identity


class _BSDInfo(ctypes.Structure):
    # sys/proc_info.h proc_bsdinfo (Darwin arm64/x86_64), PROC_PIDTBSDINFO=3.
    _fields_ = [
        (name, ctypes.c_uint32)
        for name in (
            "flags",
            "status",
            "xstatus",
            "pid",
            "ppid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "svuid",
            "svgid",
            "reserved",
        )
    ]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ]
    _fields_ += [
        ("nice", ctypes.c_int32),
        ("start_sec", ctypes.c_uint64),
        ("start_usec", ctypes.c_uint64),
    ]


class MacOSProcessVerifier:
    def __init__(self, *, expected_owner_uid, expected_executable):
        require(
            sys.platform == "darwin"
            and expected_owner_uid == os.getuid()
            and type(expected_owner_uid) is int
        )
        require(
            type(expected_executable) is str
            and expected_executable.startswith("/")
            and str(Path(expected_executable).resolve(strict=True))
            == expected_executable
        )
        require(ctypes.sizeof(_BSDInfo) == 136)
        self._uid, self._executable = expected_owner_uid, expected_executable
        self._lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self._lib.proc_pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self._lib.proc_pidinfo.restype = ctypes.c_int
        self._lib.proc_pidpath.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._lib.proc_pidpath.restype = ctypes.c_int

    def _identity(self, pid):
        value = _BSDInfo()
        count = self._lib.proc_pidinfo(
            pid, 3, 0, ctypes.byref(value), ctypes.sizeof(value)
        )
        require(
            count == ctypes.sizeof(value) and value.pid == pid and value.status != 5
        )
        return dict(
            pid=pid,
            owner_uid=value.uid,
            born_us=value.start_sec * 1000000 + value.start_usec,
        )

    def __call__(self, expected):
        try:
            process_identity(expected)
            require(expected["owner_uid"] == self._uid)
            before = self._identity(expected["pid"])
            path = ctypes.create_string_buffer(4096)
            require(self._lib.proc_pidpath(expected["pid"], path, len(path)) > 0)
            require(path.value.decode("utf-8", "strict") == self._executable)
            # Reject PID replacement during the path query as well as before it.
            return before == expected == self._identity(expected["pid"])
        except Exception:
            return False
