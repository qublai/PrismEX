"""Pytest configuration.

The PrismEX test suite is meant to run both:
- in editable installs (pip install -e .)
- directly from a source checkout (python -m pytest)

To support the latter, we add the repository root to sys.path.

@QK
"""

from __future__ import annotations

import sys
from pathlib import Path


def pytest_configure():
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
