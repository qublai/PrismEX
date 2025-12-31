"""Utility helpers used across PrismEX.

These functions are shared across the CLI, engine, heuristics, and modules.

Guiding principles:
- Keep helpers *small* and *testable*.
- Avoid heavy side effects (no global caches, no background threads).
- Prefer "best-effort" behavior (return "unknown" / empty values) rather than
  raising exceptions in non-critical paths.

@QK
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

try:
    import pefile
except Exception:  # pragma: no cover
    pefile = None  # type: ignore

try:
    import magic  # python-magic (libmagic wrapper)
except Exception:  # pragma: no cover
    magic = None


def now_utc() -> str:
    """Return a compact UTC timestamp suitable for logs and metadata."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def is_file(path: str) -> bool:
    """True if *path* exists and is a regular file."""
    return os.path.isfile(path)


def is_dir(path: str) -> bool:
    """True if *path* exists and is a directory."""
    return os.path.isdir(path)


def is_probably_pe(path: str) -> bool:
    """Cheap PE check (no heavy parsing).

    This is used to include extensionless files in recursive scans.

    We do a minimal validation:
    - starts with "MZ"
    - contains a sane e_lfanew pointer
    - has "PE\0\0" signature at that offset

    It intentionally does **not** validate all headers.
    """
    try:
        with open(path, "rb") as f:
            mz = f.read(2)
            if mz != b"MZ":
                return False
            # e_lfanew points to the PE header.
            f.seek(0x3C)
            e_lfanew = int.from_bytes(f.read(4), "little", signed=False)
            if e_lfanew <= 0 or e_lfanew > 10_000_000:
                return False
            f.seek(e_lfanew)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def iter_targets(
    paths: List[str],
    *,
    recursive: bool = False,
    follow_symlinks: bool = False,
    patterns: Optional[List[str]] = None,
    max_files: Optional[int] = None,
) -> Iterator[str]:
    """Yield file targets from a list of paths.

    - File paths are yielded as-is.
    - Directory paths are expanded using glob patterns.
    - If *recursive* is enabled, ``rglob`` is used.
    - If *max_files* is set, scanning stops after N unique files.

    A "seen" set prevents duplicates when multiple patterns overlap.
    """

    globs = patterns or ["*.exe", "*.dll", "*.sys", "*.scr", "*.ocx", "*.cpl"]
    seen: set[str] = set()
    count = 0

    for p in paths:
        pp = Path(p)

        # --------
        # Single file
        # --------
        if pp.is_file():
            rp = str(pp.resolve())
            if rp not in seen:
                seen.add(rp)
                yield str(pp)
                count += 1

        # --------
        # Directory expansion
        # --------
        elif pp.is_dir():
            # Non-recursive scan: only direct children matching patterns.
            if not recursive:
                for g in globs:
                    for fp in pp.glob(g):
                        if not fp.is_file():
                            continue
                        if fp.is_symlink() and not follow_symlinks:
                            continue
                        rp = str(fp.resolve())
                        if rp not in seen:
                            seen.add(rp)
                            yield str(fp)
                            count += 1
                            if max_files and count >= max_files:
                                return
                continue

            # Recursive scan: walk patterns first (fast and expected), then add
            # extensionless candidates if they look like PE files.
            for g in globs:
                for fp in pp.rglob(g):
                    if not fp.is_file():
                        continue
                    if fp.is_symlink() and not follow_symlinks:
                        continue
                    rp = str(fp.resolve())
                    if rp not in seen:
                        seen.add(rp)
                        yield str(fp)
                        count += 1
                        if max_files and count >= max_files:
                            return

            # Add extensionless candidates only when recursive (avoid surprises).
            for fp in pp.rglob("*"):
                if not fp.is_file():
                    continue
                if fp.suffix:
                    continue
                if fp.is_symlink() and not follow_symlinks:
                    continue
                if is_probably_pe(str(fp)):
                    rp = str(fp.resolve())
                    if rp not in seen:
                        seen.add(rp)
                        yield str(fp)
                        count += 1
                        if max_files and count >= max_files:
                            return

        if max_files and count >= max_files:
            return


def compute_overlay_size(pe: "pefile.PE", path: str) -> int:
    """Return overlay size (bytes after last mapped section), best-effort.

    Many packers and droppers append data after the last section.

    The calculation is:
      file_size - max(section.PointerToRawData + section.SizeOfRawData)
    """
    try:
        size = os.path.getsize(path)
        if not hasattr(pe, "sections"):
            return 0

        last_end = 0
        for s in pe.sections:
            end = int(s.PointerToRawData) + int(s.SizeOfRawData)
            if end > last_end:
                last_end = end

        return max(0, size - last_end)
    except Exception:
        return 0


def file_size(path: str) -> int:
    """Return the file size in bytes."""
    return os.path.getsize(path)


def file_type(path: str) -> str:
    """Return a human-readable file type using libmagic (if available)."""
    if magic is None:
        return "unknown"
    try:
        return magic.from_file(path)
    except Exception:
        return "unknown"


def sha256(path: str, chunk: int = 1024 * 1024) -> str:
    """Compute SHA-256 for a file in a streaming manner."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def hashes(path: str, chunk: int = 1024 * 1024) -> Dict[str, str]:
    """Compute MD5/SHA1/SHA256 for a file (single pass)."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256h = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            md5.update(block)
            sha1.update(block)
            sha256h.update(block)

    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256h.hexdigest()}


def load_pe(path: str):
    """Load a PE with :mod:`pefile`.

    ``fast_load=True`` is used for performance; data directories are parsed
    afterwards in a best-effort way.
    """
    if pefile is None:  # pragma: no cover
        raise ImportError("Missing dependency 'pefile'. Install with: pip install -r requirements.txt")

    pe = pefile.PE(path, fast_load=True)

    # Some malformed PEs throw during directory parsing; we still want basic
    # headers when possible.
    try:
        pe.parse_data_directories()
    except Exception:
        pass

    return pe


def pe_basic_info(pe) -> Dict[str, Any]:
    """Extract a small, stable subset of PE header fields."""

    ts = getattr(getattr(pe, "FILE_HEADER", None), "TimeDateStamp", None)
    timestamp = None
    if isinstance(ts, int):
        try:
            timestamp = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = None

    opt = getattr(pe, "OPTIONAL_HEADER", None)
    return {
        "imphash": safe_imphash(pe),
        "timestamp_utc": timestamp,
        "is_dll": bool(getattr(getattr(pe, "FILE_HEADER", None), "IMAGE_FILE_DLL", 0)),
        "machine": hex(getattr(getattr(pe, "FILE_HEADER", None), "Machine", 0)),
        "subsystem": getattr(opt, "Subsystem", None),
        "imagebase": getattr(opt, "ImageBase", None),
        "entrypoint_rva": getattr(opt, "AddressOfEntryPoint", None),
    }


def safe_imphash(pe) -> str | None:
    """Compute imphash, returning None on failure."""
    try:
        return pe.get_imphash()
    except Exception:
        return None


def list_imports(pe) -> Dict[str, list]:
    """Return imports as ``{dll: [func_or_ordinal, ...], ...}``.

    We normalize:
    - DLL names are decoded with errors ignored.
    - Ordinal imports are encoded as ``ordinal:<n>`` for readability.
    """
    imports: Dict[str, list] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return imports

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore") if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode(errors="ignore"))
            else:
                funcs.append(f"ordinal:{imp.ordinal}")
        imports[dll] = funcs

    return imports
