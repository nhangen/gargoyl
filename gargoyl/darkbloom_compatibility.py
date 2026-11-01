"""Reviewed parser/command compatibility; configuration cannot expand this set."""
# Release sources inspected for restart/drain/doctor semantics, with the installed
# executable digests recorded during investigation (docs/darkbloom-restart-evidence.md,
# docs/local-diagnostic-collection.md). Other versions are reported as unsupported.
SUPPORTED_VERSIONS = {
    '0.10.5': 'f568a3de578664bbc4246a3e51688aa9595fe51b7aaac8e26bbd829b8733b85d',
    '0.10.6': '4474b0605343b502f58c45e7e696dba575d4802eb56cd30802ab9b526371c7c3',
}
