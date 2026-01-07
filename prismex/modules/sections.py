#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""PE section summary.

This module enumerates PE sections and returns:
- Per-section name, size, entropy
- Permission flags (R/W/X)
- Hashes of raw section data

The output is used by heuristics (e.g., RWX sections, low section count) and
included in the report for analyst inspection.

Original logic was inspired by common PE inspection scripts; it has been
cleaned up for deterministic output.
"""

from __future__ import annotations

from typing import Any, Dict, List


def is_section_executable(section: Any) -> bool:
    """Return True if the section has executable permissions."""
    characteristics = int(getattr(section, "Characteristics", 0))
    # IMAGE_SCN_CNT_CODE (0x00000020) or IMAGE_SCN_MEM_EXECUTE (0x20000000)
    return bool(characteristics & 0x00000020) or bool(characteristics & 0x20000000)


def _decode_section_name(raw: bytes) -> str:
    """Decode a section name to a printable ASCII string."""
    # Names are typically null-terminated 8-byte fields.
    try:
        name = raw.decode("utf-8", errors="ignore")
    except Exception:
        name = raw.decode("ISO-8859-1", errors="ignore")
    name = name.encode("ascii", errors="ignore").decode("ascii", errors="ignore")
    name = name.replace("\x00", "").strip()
    return name or ".noname"


def get_result(pe) -> Dict[str, Any]:
    """Return section count + detailed list."""
    details: List[Dict[str, Any]] = []

    for section in getattr(pe, "sections", []) or []:
        name = _decode_section_name(getattr(section, "Name", b""))

        # Hashes/entropy are provided by pefile helpers.
        # We truncate the raw data preview to keep reports lightweight.
        details.append(
            {
                "section_name": name,
                "executable": is_section_executable(section),
                "characteristics": int(getattr(section, "Characteristics", 0)),
                "virtual_address": int(getattr(section, "VirtualAddress", 0)),
                "virtual_size": int(getattr(section, "Misc_VirtualSize", 0)),
                "size_of_raw_data": int(getattr(section, "SizeOfRawData", 0)),
                "hash": {
                    "md5": section.get_hash_md5(),
                    "sha1": section.get_hash_sha1(),
                    "sha256": section.get_hash_sha256(),
                },
                "entropy": section.get_entropy(),
                "data": str(section.get_data())[:50],
            }
        )

    return {
        "count": int(getattr(getattr(pe, "FILE_HEADER", None), "NumberOfSections", 0)),
        "details": details,
    }
