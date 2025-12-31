"""PrismEX plugin system.

PrismEX supports three plugin discovery mechanisms (in this order):

1) **Built-in plugins** shipped in ``prismex/plugins``.
2) **Directory plugins** supplied via ``--plugin-dir`` (each ``*.py`` file can
   act as a plugin).
3) **Installed entrypoint plugins** exposed under the group
   ``prismex.plugins``.

A plugin is a simple callable:

``prismex_plugin(ctx) -> None``

Plugins may mutate ``ctx.report`` to add extra structures and/or indicators.
They should be defensive (catch their own errors) but PrismEX will also
sandbox each plugin call and record failures in the report.

Security note:
Directory plugins are arbitrary Python code. Only load plugins you trust.

@QK
"""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from importlib.metadata import entry_points
except Exception:  # pragma: no cover
    entry_points = None  # type: ignore


# Plugin function signature: receives a PluginContext and mutates ctx.report.
PluginFn = Callable[["PluginContext"], None]


@dataclass
class PluginContext:
    """Context object handed to plugins.

    Fields are intentionally minimal and stable:
    - analyzer: the PrismEXAnalyzer instance (for access to config/rules)
    - path: target file path
    - pe: parsed pefile.PE instance (fast_load + parse_data_directories)
    - report: mutable report dictionary
    - options: optional plugin options (reserved for future CLI exposure)
    """

    analyzer: Any
    path: str
    pe: Any
    report: Dict[str, Any]
    options: Dict[str, Any]


def _load_module_from_file(path: Path) -> Optional[Any]:
    """Load a Python module from a file path, best-effort.

    We use importlib's low-level loader so directory plugins do not need to be
    installed packages.
    """

    try:
        mod_name = f"prismex_ext_{path.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        # NOTE: executing the module runs arbitrary code.
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod
    except Exception:
        return None


def _module_to_plugin(mod: Any) -> Optional[Tuple[str, PluginFn]]:
    """Convert a loaded module into a PrismEX plugin.

    Supported plugin shapes:
    - ``PLUGIN_NAME: str`` and ``prismex_plugin(ctx)`` callable
    - ``prismex_plugin(ctx)`` callable (name defaults to module name)
    """

    fn = getattr(mod, "prismex_plugin", None)
    if not callable(fn):
        return None

    name = getattr(mod, "PLUGIN_NAME", None)
    if not isinstance(name, str) or not name.strip():
        name = getattr(mod, "__name__", "plugin")

    return name, fn


def discover_plugins(
    *,
    plugin_dirs: Optional[List[str]] = None,
    include_builtins: bool = True,
) -> Dict[str, PluginFn]:
    """Discover plugins and return a mapping: ``name -> callable``.

    If a later discovery mechanism finds a plugin with the same name, it
    overrides earlier ones. This makes it easy to replace built-ins in a lab.
    """

    plugins: Dict[str, PluginFn] = {}

    # -----------------------------
    # 1) Built-in plugins
    # -----------------------------
    if include_builtins:
        try:
            import prismex.plugins  # noqa: F401  (ensures package importability)

            pkg_path = Path(__file__).parent / "plugins"
            for py in sorted(pkg_path.glob("*.py")):
                if py.name.startswith("__"):
                    continue
                mod = _load_module_from_file(py)
                if mod is None:
                    continue
                item = _module_to_plugin(mod)
                if item:
                    name, fn = item
                    plugins[name] = fn
        except Exception:
            # Built-ins are optional; failure here should not break scanning.
            pass

    # -----------------------------
    # 2) User-provided plugin directories
    # -----------------------------
    for d in plugin_dirs or []:
        dp = Path(d)
        if not dp.exists() or not dp.is_dir():
            continue
        for py in sorted(dp.glob("*.py")):
            if py.name.startswith("__"):
                continue
            mod = _load_module_from_file(py)
            if mod is None:
                continue
            item = _module_to_plugin(mod)
            if item:
                name, fn = item
                plugins[name] = fn

    # -----------------------------
    # 3) Installed entry points
    # -----------------------------
    if entry_points is not None:
        try:
            eps = entry_points()
            group = (
                eps.select(group="prismex.plugins")
                if hasattr(eps, "select")
                else eps.get("prismex.plugins", [])
            )
            for ep in group:
                try:
                    fn = ep.load()
                    if callable(fn):
                        plugins[getattr(ep, "name", "plugin")] = fn
                except Exception:
                    continue
        except Exception:
            pass

    return plugins


def run_plugins(
    *,
    plugins: Dict[str, PluginFn],
    enabled: Optional[List[str]],
    ctx: PluginContext,
) -> List[Dict[str, Any]]:
    """Run enabled plugins.

    Returns a list of execution results suitable for attaching to the report.

    We isolate exceptions per plugin so one broken plugin doesn't prevent others
    from running.
    """

    results: List[Dict[str, Any]] = []

    enabled_set = None
    if enabled is not None:
        enabled_set = {e.strip() for e in enabled if isinstance(e, str) and e.strip()}

    for name, fn in plugins.items():
        if enabled_set is not None and name not in enabled_set:
            continue
        try:
            fn(ctx)
            results.append({"name": name, "status": "ok"})
        except Exception as e:
            results.append({"name": name, "status": "error", "error": str(e)})

    return results
