"""Render validated snapshot files to stdout; never connect to a fleet."""
import argparse
import sys
from pathlib import Path

from gargoyl.dashboard import render_dashboard
from gargoyl.telemetry import PolicyError, decode_snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshots', nargs='*', help='v1 JSON snapshots, at most 64 KiB each')
    parser.add_argument('--host', action='append', default=[], help='expected opaque host UUID (repeatable)')
    parser.add_argument('--now', help='UTC evaluation time, for reproducible fixtures')
    args = parser.parse_args()
    try:
        snapshots = []
        for filename in args.snapshots:
            with Path(filename).open('rb') as stream:
                snapshots.append(decode_snapshot(stream.read(65537)))
        page = render_dashboard(snapshots, args.host, args.now)
    except (PolicyError, OSError):
        print('Dashboard input unavailable or rejected; no report generated.', file=sys.stderr)
        return 2
    print(page)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
