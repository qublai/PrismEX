#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Version metadata (VS_VERSIONINFO) extraction.

Many Windows binaries embed a VERSIONINFO resource with fields like:
- CompanyName
- FileDescription
- ProductName
- FileVersion

This module reads those string fields into a simple dict.

Why it matters:
- Malware often forges metadata (e.g. "Microsoft Corporation")
- Some packers strip it entirely

The function returns an **empty dict** if no metadata is present.
"""

from __future__ import annotations

import string
from typing import Dict


def convert_char(char: str) -> str:
    """Convert a character into a safely printable form.

    Printable ASCII characters are returned as-is; everything else becomes a
    ``\\xNN`` escape.
    """

    if (
        char in string.ascii_letters
        or char in string.digits
        or char in string.punctuation
        or char in string.whitespace
    ):
        return char
    return r"\x%02x" % ord(char)


def convert_to_printable(s: str) -> str:
    """Convert a string to a printable string (best-effort)."""

    return "".join([convert_char(c) for c in s])


def get(pe) -> Dict[str, str]:
    """Extract VERSIONINFO key/value pairs from a ``pefile.PE``.

    Returns:
        Dict mapping keys to values. Empty if missing.
    """

    ret: Dict[str, str] = {}

    # pefile populates VS_VERSIONINFO / FileInfo when resources are present.
    if hasattr(pe, "VS_VERSIONINFO") and hasattr(pe, "FileInfo"):
        for finfo in pe.FileInfo:
            for entry in finfo:
                if not hasattr(entry, "StringTable"):
                    continue
                for st_entry in entry.StringTable:
                    for key, val in list(st_entry.entries.items()):
                        try:
                            k = key.decode(errors="ignore")
                            v = val.decode(errors="ignore")
                        except Exception:
                            k = str(key)
                            v = str(val)
                        ret[k] = v

    return ret
