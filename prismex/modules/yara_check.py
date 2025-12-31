#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""YARA scanning helpers.

PrismEX treats YARA as optional at runtime:
- If `yara-python` is not installed, PrismEX can still run with `--no-yara`
  and will surface a clear error if YARA scanning is requested.
"""

from __future__ import annotations

import os
from os import walk
from typing import Any, Dict, List, Optional

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None  # type: ignore


def _require_yara() -> Any:
    if yara is None:
        raise ImportError(
            "Missing dependency 'yara-python'. Install it with: pip install yara-python "
            "(or install PrismEX requirements), or run PrismEX with --no-yara."
        )
    return yara


def yara_match_from_file(fileyara: str, filename: str) -> List[str]:
    y = _require_yara()
    matches: List[str] = []
    rules = y.compile(fileyara)

    try:
        for match in rules.match(filename):
            matches.append(str(match))
    except Exception:
        # fix yara.Error: internal error: 30 (best-effort)
        pass

    return matches


def yara_match_from_folder(folder_yara: str, filename: str, exclude: Optional[List[str]] = None) -> List[Dict[str, str]]:
    y = _require_yara()
    exclude = exclude or []
    matches: List[Dict[str, str]] = []

    for (dirpath, _dirnames, filenames) in walk(folder_yara):
        for f in filenames:
            if not str(f).endswith((".yar", ".yara")):
                continue
            if str(f) in exclude:
                continue

            path_to_file_yara = str(dirpath) + os.sep + str(f)

            try:
                rules = y.compile(path_to_file_yara)
                for match in rules.match(filename, timeout=60):
                    matches.append({f: str(match)})
            except Exception:
                pass

    return matches
