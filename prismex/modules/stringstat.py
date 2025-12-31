#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Printable string extraction.

This is a lightweight, dependency-free implementation intended for static
triage.

It scans a file and extracts contiguous runs of printable ASCII characters of a
minimum length (default: 4).

Notes:
- This is *not* a full-featured strings implementation (e.g., it does not
  detect wide/UTF-16 strings). PrismEX heuristics focus on high-signal ASCII
  artifacts like URLs, IPs, and base64-ish blobs.
"""

from __future__ import annotations

from typing import List


def _wanted_chars_ascii() -> str:
    """Build a translation table to replace non-printable bytes with NUL.

    The strategy mirrors a common "strings" approach:
    - keep bytes in the ASCII printable range
    - replace everything else with "\0" so we can split on it
    """

    wanted = ["\0"] * 256
    for i in range(32, 127):
        wanted[i] = chr(i)

    # Tabs are often useful for configuration-like data.
    wanted[ord("\t")] = "\t"
    return "".join(wanted)


def get_result(filename: str, *, threshold: int = 4) -> List[str]:
    """Extract printable ASCII strings.

    Args:
        filename: Path to file.
        threshold: Minimum string length.

    Returns:
        List of extracted strings (order preserved).
    """

    results: List[str] = []

    # Read with errors ignored so random binary bytes do not break decoding.
    # We then translate non-printables to NUL and split on NUL.
    data = open(filename, errors="ignore").read()
    translated = data.translate(_wanted_chars_ascii())

    for s in translated.split("\0"):
        if len(s) >= threshold:
            results.append(s)

    return results
