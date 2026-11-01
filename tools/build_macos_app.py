"""Build an unprivileged GUI app; never launch it or request authentication."""

import argparse
import os
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gargoyl.native_app import SWIFT  # noqa: E402


def build(output, python, *, preview=True):
    if sys.platform != "darwin" or os.getuid() != 501:
        raise ValueError("native MBP pilot only")
    python = Path(python).absolute()
    if not python.is_relative_to(Path.home()) or not python.is_file():
        raise ValueError("owner-local isolated interpreter required")
    output = Path(output).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    contents = output / "Gargoyl.app/Contents"
    binary = contents / "MacOS/Gargoyl"
    binary.parent.mkdir(parents=True)
    source = output / "Gargoyl.swift"
    source.write_text(SWIFT)
    cache = output / "module-cache"
    cache.mkdir()
    subprocess.run(
        [
            "/usr/bin/xcrun",
            "swiftc",
            "-swift-version",
            "5",
            "-target",
            platform.machine() + "-apple-macosx13.0",
            "-O",
            "-module-cache-path",
            str(cache),
            "-framework",
            "AppKit",
            "-framework",
            "WebKit",
            "-framework",
            "LocalAuthentication",
            "-framework",
            "SystemConfiguration",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
    )
    info = dict(
        CFBundleExecutable="Gargoyl",
        CFBundleIdentifier="dev.gargoyl.app",
        CFBundleName="Gargoyl",
        CFBundleDisplayName="Gargoyl",
        CFBundlePackageType="APPL",
        CFBundleVersion="1",
        CFBundleShortVersionString="0.1.0",
        LSMinimumSystemVersion="13.0",
        GargoylPython=str(python),
        GargoylReadOnlyPreview=preview,
        NSAppTransportSecurity={
            "NSExceptionDomains": {
                "127.0.0.1": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                    "NSIncludesSubdomains": False,
                }
            }
        },
    )
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    print(output / "Gargoyl.app")
    return output / "Gargoyl.app"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--enable-native-actions", action="store_true")
    args = parser.parse_args()
    build(args.output, args.python, preview=not args.enable_native_actions)
