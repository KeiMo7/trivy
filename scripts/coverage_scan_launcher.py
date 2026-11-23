#!/usr/bin/env python3
"""Isolated-mode entry point.

The scanner is meant to run under ``python -I`` against untrusted artifact
directories (a planted ``json.py`` in the cwd must not be importable). Isolated
mode neither imports the cwd nor honors PYTHONPATH, so this thin launcher makes
the package location explicit before handing control to the real CLI. The
launcher lives outside every artifact directory.
"""

import os
import sys

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

from coverage_scan.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
