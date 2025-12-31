"""PrismEX plugin template.

Copy this file, edit it, and load it with:

  prismex scan <target> --plugin-dir ./examples/plugins

A plugin must define:

- ``PLUGIN_NAME = "..."``
- ``def prismex_plugin(ctx): ...``

Your plugin can modify:
- ``ctx.report["analysis"][...]`` (attach structured plugin output)
- ``ctx.report["indicators"]`` (append human-facing findings)

Tips:
- Keep plugins deterministic (avoid random / timestamps unless necessary).
- Prefer offline analysis. If you must do network lookups, make it opt-in.

@QK
"""

from __future__ import annotations

PLUGIN_NAME = "my_plugin"


def prismex_plugin(ctx):
    """Example plugin entrypoint.

    The context object provides:
    - ctx.path: target file path
    - ctx.pe: parsed pefile.PE object
    - ctx.report: in-progress PrismEX report dict
    - ctx.options: optional plugin options
    """

    analysis = ctx.report.setdefault("analysis", {})
    plugins = analysis.setdefault("plugins", {})

    # Example: attach a constant marker
    plugins[PLUGIN_NAME] = {"hello": "world"}

    # Example: add an indicator
    ctx.report.setdefault("indicators", []).append(
        {
            "id": "my_plugin_marker",
            "severity": "low",
            "message": "Plugin ran successfully.",
            "score": 1,
        }
    )
