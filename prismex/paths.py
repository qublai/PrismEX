"""PrismEX source file.

@QK
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
DEFAULT_SIGNATURES_DIR = DATA_DIR / "signatures"
DEFAULT_YARA_DIR = DEFAULT_SIGNATURES_DIR / "yara_plugins" / "pe"
DEFAULT_STRINGMATCH_PATH = DEFAULT_SIGNATURES_DIR / "stringsmatch.json"
DEFAULT_CONFIG_PATH = PACKAGE_DIR / "config" / "default.json"


def resolve_path(*parts: str) -> str:
    """Resolve a path inside the PrismEX package."""
    return str((PACKAGE_DIR.joinpath(*parts)).resolve())
