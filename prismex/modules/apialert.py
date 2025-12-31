#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Suspicious API import matcher.

This module implements a very fast signal:
- Take a list of API name prefixes (e.g. from ``stringmatch.json``)
- Compare them against imported function names
- Return a de-duplicated sorted list of matches

Notes:
- This operates only on the Import Table (IAT). It will not detect dynamically
  resolved APIs (GetProcAddress / hashing) unless other heuristics catch them.
"""

from __future__ import annotations

from typing import List


def get_result(pe, strings_match: List[str]):
    """Return a sorted list of suspicious import names.

    Args:
        pe: A ``pefile.PE`` object.
        strings_match: List of API prefixes or full names to match.

    Returns:
        Sorted unique list of matched API names.
    """

    alerts: List[str] = []

    # The import directory may not exist for stripped/packed samples.
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                # imp.name can be None for ordinal imports.
                if not getattr(imp, "name", None):
                    continue

                try:
                    name = imp.name.decode("ascii", errors="ignore")
                except Exception:
                    # Extremely defensive; in practice pefile returns bytes.
                    name = str(imp.name)

                for prefix in strings_match:
                    if prefix and name.startswith(prefix):
                        alerts.append(name)

    # De-duplicate and provide a deterministic order for reporting.
    return sorted(set(alerts))
