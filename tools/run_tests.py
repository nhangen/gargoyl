"""Run unittest with fatal resource warnings, including unraisable finalizer leaks."""
import gc
import sys
import unittest
import warnings


def main(argv=None):
    leaked = 0
    previous_hook = sys.unraisablehook

    def unraisable(event):
        nonlocal leaked
        if isinstance(event.exc_value, ResourceWarning):
            # Keep no exception/object references or arbitrary payload text.
            leaked += 1
        else:
            previous_hook(event)

    with warnings.catch_warnings():
        warnings.simplefilter('error', ResourceWarning)
        sys.unraisablehook = unraisable
        try:
            # Prevent unittest's default warning policy from replacing ours.
            program = unittest.main(module=None, argv=[sys.argv[0], *(sys.argv[1:] if argv is None else argv)],
                                    exit=False, warnings='')
            gc.collect()  # Force cyclic finalizers before restoring the hook.
            if leaked:
                print(f'Resource leak check failed: {leaked} unraisable ResourceWarning(s).', file=sys.stderr)
            return 0 if program.result.wasSuccessful() and not leaked else 1
        finally:
            sys.unraisablehook = previous_hook


if __name__ == '__main__':
    raise SystemExit(main())
