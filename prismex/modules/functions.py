#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @QK

"""Low-level function and IAT helpers (legacy).

Some PrismEX modules were adapted from the original legacy codebase and kept
for compatibility and future expansion.

@QK
"""

import os
import json

def _pkg_root():
    # prismex/modules -> prismex
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def path_to_file(filename, folder):
    # folder relative to prismex package root
    return os.path.join(_pkg_root(), folder, filename)

def load_config(config_file):
    with open(config_file, "r", encoding="utf-8", errors="ignore") as conf:
        return json.load(conf)

def files_to_edit():
    return {
        "api_config": path_to_file('default.json', 'config'),
        "string_match": path_to_file('stringsmatch.json', 'data/signatures'),
        "yara_plugins": path_to_file('yara_plugins', 'data/signatures'),
    }
