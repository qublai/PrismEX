"""PrismEX source file.

@QK
"""

from __future__ import annotations

# This is a small built-in example plugin.
# It demonstrates how plugins can append structured data to the report.

PLUGIN_NAME = "example_metadata"


def prismex_plugin(ctx):
    # Attach a stable place for plugin output
    analysis = ctx.report.setdefault("analysis", {})
    plugins = analysis.setdefault("plugins", {})

    plugins["example_metadata"] = {
        "note": "This is a built-in example plugin. Disable it with --enable-plugin to explicitly choose plugins.",
        "path_basename": ctx.path.split("/")[-1],
    }
