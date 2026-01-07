#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""PE data directory extraction (legacy helper).

This module contains small helpers for extracting information from common PE
data directories:

- imports / exports
- TLS directory
- relocations
- debug directory
- resources

The implementation is intentionally defensive because malformed samples are
common in malware triage.

Notes:
- PrismEX's core engine does *not* depend on this module directly, but it is
  shipped for advanced users and plugins.

@QK
"""

from __future__ import annotations

import binascii
import re
from typing import Any, Dict, List

import pefile


def get_import(pe: pefile.PE) -> Dict[str, List[Dict[str, Any]]]:
    """Return imported functions grouped by DLL name."""
    libdict: Dict[str, List[Dict[str, Any]]] = {}

    try:
        entries = pe.DIRECTORY_ENTRY_IMPORT
    except Exception:
        return libdict

    for entry in entries:
        try:
            dll = entry.dll.decode("ascii", errors="replace")
        except Exception:
            dll = str(entry.dll)

        libdict.setdefault(dll, [])
        for imp in getattr(entry, "imports", []) or []:
            address = getattr(imp, "address", None)
            try:
                function = imp.name.decode("ascii", errors="replace")  # type: ignore[union-attr]
            except Exception:
                function = str(getattr(imp, "name", ""))

            libdict[dll].append({"offset": address, "function": function})

    return libdict


def get_export(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Return exported functions as a list."""
    exports: List[Dict[str, Any]] = []

    try:
        symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
    except Exception:
        return exports

    for exp in symbols:
        try:
            address = pe.OPTIONAL_HEADER.ImageBase + exp.address
        except Exception:
            address = getattr(exp, "address", None)

        try:
            function = exp.name.decode("ascii", errors="replace")  # type: ignore[union-attr]
        except Exception:
            function = str(getattr(exp, "name", ""))

        exports.append({"offset": address, "function": function})

    return exports


def get_debug(pe: pefile.PE) -> Dict[str, Any]:
    """Extract CodeView debug directory information if present."""
    debug_type = {
        "IMAGE_DEBUG_TYPE_UNKNOWN": 0,
        "IMAGE_DEBUG_TYPE_COFF": 1,
        "IMAGE_DEBUG_TYPE_CODEVIEW": 2,
        "IMAGE_DEBUG_TYPE_FPO": 3,
        "IMAGE_DEBUG_TYPE_MISC": 4,
        "IMAGE_DEBUG_TYPE_EXCEPTION": 5,
        "IMAGE_DEBUG_TYPE_FIXUP": 6,
        "IMAGE_DEBUG_TYPE_BORLAND": 9,
    }

    debug_dir = None
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if getattr(d, "name", None) == "IMAGE_DIRECTORY_ENTRY_DEBUG":
            debug_dir = d
            break

    if debug_dir is None:
        return {}

    try:
        debug_directories = pe.parse_debug_directory(debug_dir.VirtualAddress, debug_dir.Size)
    except Exception:
        return {}

    for debug_directory in debug_directories:
        try:
            if debug_directory.struct.Type == debug_type["IMAGE_DEBUG_TYPE_CODEVIEW"]:
                return {
                    "PointerToRawData": debug_directory.struct.PointerToRawData,
                    "size": debug_directory.struct.SizeOfData,
                }
        except Exception:
            continue

    return {}


def get_relocations(pe: pefile.PE) -> Dict[str, Any]:
    """Extract base relocation directory metadata."""
    reloc_dir = None
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if getattr(d, "name", None) == "IMAGE_DIRECTORY_ENTRY_BASERELOC":
            reloc_dir = d
            break

    if reloc_dir is None:
        return {}

    result: Dict[str, Any] = {"VirtualAddress": reloc_dir.VirtualAddress, "Size": reloc_dir.Size}

    try:
        reloc_directories = pe.parse_relocations_directory(reloc_dir.VirtualAddress, reloc_dir.Size)
    except Exception:
        reloc_directories = []

    result["count"] = len(reloc_directories)

    details: Dict[str, Any] = {}
    for i, items in enumerate(reloc_directories, start=1):
        try:
            details[f"reloc_{i}"] = len(items.entries)
        except Exception:
            details[f"reloc_{i}"] = 0
    result["details"] = details

    return result


def get_tls(pe: pefile.PE) -> Dict[str, Any]:
    """Extract TLS directory fields if present."""
    tls_dir = None
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if getattr(d, "name", None) == "IMAGE_DIRECTORY_ENTRY_TLS":
            tls_dir = d
            break

    if tls_dir is None:
        return {}

    try:
        tls_struct = pe.parse_directory_tls(tls_dir.VirtualAddress, tls_dir.Size).struct
    except Exception:
        return {}

    return {
        "StartAddressOfRawData": getattr(tls_struct, "StartAddressOfRawData", None),
        "EndAddressOfRawData": getattr(tls_struct, "EndAddressOfRawData", None),
        "AddressOfIndex": getattr(tls_struct, "AddressOfIndex", None),
        "AddressOfCallBacks": getattr(tls_struct, "AddressOfCallBacks", None),
        "SizeOfZeroFill": getattr(tls_struct, "SizeOfZeroFill", None),
        "Characteristics": getattr(tls_struct, "Characteristics", None),
    }


def get_resources(pe: pefile.PE) -> List[Dict[str, Any]]:
    """Extract a small preview of resources (best effort)."""
    res_array: List[Dict[str, Any]] = []

    try:
        resources = pe.DIRECTORY_ENTRY_RESOURCE.entries
    except Exception:
        return res_array

    for resource_type in resources:
        if resource_type.name is not None:
            name = f"{resource_type.name}"
        else:
            name = f"{pefile.RESOURCE_TYPE.get(resource_type.struct.Id)}"

        if name is None or name == "None":
            name = f"{resource_type.struct.Id}"

        if not hasattr(resource_type, "directory"):
            continue

        for idx, resource_id in enumerate(resource_type.directory.entries, start=1):
            newname = f"{name}_{idx}" if len(resource_type.directory.entries) > 1 else name

            try:
                lang_entries = resource_id.directory.entries
            except Exception:
                continue

            for resource_lang in lang_entries:
                try:
                    data_byte = pe.get_data(
                        resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size
                    )[:50]
                except Exception:
                    data_byte = b""  # type: ignore[assignment]

                is_pe = bool(magic_check(data_byte))

                try:
                    lang = pefile.LANG.get(resource_lang.data.lang, "*unknown*")
                except Exception:
                    lang = "*unknown*"

                try:
                    sublang = pefile.get_sublang_name_for_lang(
                        resource_lang.data.lang, resource_lang.data.sublang
                    )
                except Exception:
                    sublang = "*unknown*"

                try:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size
                except Exception:
                    offset = None
                    size = None

                res_array.append(
                    {
                        "name": newname,
                        "data": str(data_byte),
                        "executable": is_pe,
                        "offset": offset,
                        "size": size,
                        "language": lang,
                        "sublanguage": sublang,
                    }
                )

    return res_array


def magic_check(data: bytes) -> List[str]:
    """Return matches for a minimal MZ header hex pattern."""
    try:
        hex_bytes = binascii.b2a_hex(data)
    except Exception:
        return []
    return re.findall(r"4d5a90", str(hex_bytes))
