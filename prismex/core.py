"""PrismEX analysis engine.

This module contains the high-level orchestration for scanning a single target
file and producing a structured report.

Design goals:
- **Deterministic output**: stable keys so reports diff nicely.
- **Best-effort robustness**: malformed / partially-parsable PEs should still
  yield a report with error fields instead of hard-failing.
- **Explainability**: heuristics and scoring contribute explicit indicators.

The top-level report schema looks roughly like:

- tool: {name, version}
- target: {path, size, type, hashes}
- pe: basic header summary
- analysis: deeper extracted structures (imports, sections, heuristics, yara, …)
- indicators: list of high-level findings for quick triage
- score: {value, level, breakdown}

@QK
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .heuristics import run_heuristics
from .modules import apialert, directories, meta, sections, stringstat, yara_check
from .paths import DEFAULT_CONFIG_PATH, DEFAULT_STRINGMATCH_PATH, DEFAULT_YARA_DIR
from .pluginsystem import PluginContext, discover_plugins, run_plugins
from .scoring import attach_score
from .utils import file_size, file_type, hashes, is_file, list_imports, load_pe, pe_basic_info


class PrismEXAnalyzer:
    """PrismEX static analysis engine for Portable Executables (PE).

    The analyzer is intentionally **stateless per target**: each `analyze()` call
    returns a complete report dict.

    A small amount of state is cached (the JSON config) to avoid repeatedly
    reading/parsing it for batch scans.
    """

    def __init__(
        self,
        yara_rules_dir: Optional[str] = None,
        stringmatch_path: Optional[str] = None,
        config_path: Optional[str] = None,
        plugin_dirs: Optional[List[str]] = None,
        enabled_plugins: Optional[List[str]] = None,
        include_builtin_plugins: bool = True,
    ) -> None:
        # Runtime locations (allow overriding for portability / offline use)
        self.yara_rules_dir = str(yara_rules_dir or DEFAULT_YARA_DIR)
        self.stringmatch_path = str(stringmatch_path or DEFAULT_STRINGMATCH_PATH)
        self.config_path = str(config_path or DEFAULT_CONFIG_PATH)

        # Plugin discovery controls
        self.plugin_dirs = plugin_dirs or []
        self.enabled_plugins = enabled_plugins
        self.include_builtin_plugins = include_builtin_plugins

        # Lazily-loaded JSON config (cached after first read)
        self._config_cache: Optional[Dict[str, Any]] = None

    # ---------------------------------------------------------------------
    # Config loading
    # ---------------------------------------------------------------------

    def _load_config(self) -> Dict[str, Any]:
        """Load PrismEX config JSON (cached).

        The config file is optional. If it is missing or invalid, PrismEX falls
        back to built-in defaults.

        Expected shapes:
        - {"rules": {"scoring": {...}, "heuristics": {...}}}
        - or a plain rules object: {"scoring": {...}, "heuristics": {...}}
        """

        if self._config_cache is not None:
            return self._config_cache

        cfg: Dict[str, Any] = {}
        try:
            with open(self.config_path, "r", encoding="utf-8", errors="ignore") as f:
                cfg = json.load(f) or {}
        except Exception:
            # Best-effort: keep cfg as {}.
            cfg = {}

        self._config_cache = cfg
        return cfg

    def _rules(self) -> Dict[str, Any]:
        """Return the rules section of the config (or an empty dict)."""
        cfg = self._load_config()

        # Support both `{ "rules": {...} }` and plain `{...}` rule files.
        rules = cfg.get("rules") if isinstance(cfg, dict) else None
        return rules if isinstance(rules, dict) else (cfg if isinstance(cfg, dict) else {})

    # ---------------------------------------------------------------------
    # Analysis
    # ---------------------------------------------------------------------

    def analyze(
        self,
        path: str,
        *,
        include_strings: bool = True,
        include_yara: bool = True,
        plugin_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze a single PE file and return a structured report dict."""

        if not is_file(path):
            raise FileNotFoundError(path)

        t0 = time.time()

        # Create the base report first so we can attach partial results even if
        # later steps error.
        report: Dict[str, Any] = {
            "tool": {"name": "PrismEX", "version": __version__},
            "target": {
                "path": os.path.abspath(path),
                "size": file_size(path),
                "type": file_type(path),
                "hashes": hashes(path),
            },
            "pe": {},
            "analysis": {},
            "indicators": [],
        }

        # Parse the file as a PE (pefile). This is the only required dependency
        # for the core engine.
        pe = load_pe(path)
        report["pe"] = pe_basic_info(pe)

        # -----------------------------
        # Core PE structures
        # -----------------------------
        report["analysis"]["imports"] = list_imports(pe)

        # Each extractor is isolated so that one failure does not abort the scan.
        try:
            report["analysis"]["sections"] = sections.get_result(pe)
        except Exception as e:
            report["analysis"]["sections_error"] = str(e)

        try:
            report["analysis"]["directories"] = directories.get(pe)
        except Exception as e:
            report["analysis"]["directories_error"] = str(e)

        try:
            report["analysis"]["metadata"] = meta.get(pe)
        except Exception as e:
            report["analysis"]["metadata_error"] = str(e)

        # -----------------------------
        # Fast indicators (imports-based)
        # -----------------------------
        # `stringmatch.json` provides an additional list of suspicious API names
        # that are cheap to check just from imported symbols.
        try:
            with open(self.stringmatch_path, "r", encoding="utf-8", errors="ignore") as f:
                sm = json.load(f) or {}
            bp_list = sm.get("breakpoint", [])
            hits = apialert.get_result(pe, bp_list)
            if hits:
                report["analysis"]["suspicious_apis"] = hits
                report["indicators"].append(
                    {
                        "id": "suspicious_apis",
                        "severity": "medium",
                        "message": f"Found {len(hits)} suspicious or high-signal API imports.",
                    }
                )
        except Exception:
            # stringmatch.json is optional; ignore if missing/invalid.
            pass

        # -----------------------------
        # Strings (optional)
        # -----------------------------
        # Strings can be expensive on very large files, so the CLI provides
        # `--no-strings`.
        if include_strings:
            try:
                strs = stringstat.get_result(path)
                report["analysis"]["strings"] = {
                    "count": len(strs),
                    "samples": strs[:200],  # keep output manageable
                }
                if len(strs) > 2000:
                    report["indicators"].append(
                        {
                            "id": "many_strings",
                            "severity": "low",
                            "message": "Large number of printable strings; could indicate embedded config or packed content.",
                        }
                    )
            except Exception as e:
                report["analysis"]["strings_error"] = str(e)

        # -----------------------------
        # YARA (optional)
        # -----------------------------
        # YARA is treated as optional: if the dependency isn't installed or rules
        # fail to compile, PrismEX reports an error field instead of crashing.
        if include_yara:
            try:
                matches = yara_check.yara_match_from_folder(self.yara_rules_dir, path, exclude=[])
                report["analysis"]["yara"] = matches
                if matches:
                    report["indicators"].append(
                        {
                            "id": "yara_hits",
                            "severity": "high",
                            "message": f"YARA matched {len(matches)} rule(s).",
                        }
                    )
            except Exception as e:
                report["analysis"]["yara_error"] = str(e)

        # -----------------------------
        # Rich heuristics
        # -----------------------------
        # Heuristics are higher-level checks that combine multiple signals
        # (sections, imports, strings, metadata, etc.) and yield explainable hits.
        try:
            rules = self._rules()
            heur_cfg = rules.get("heuristics") if isinstance(rules, dict) else None
            metrics, hits = run_heuristics(
                pe=pe,
                path=path,
                report=report,
                include_strings=include_strings,
                rules=heur_cfg,
            )
            report["analysis"]["heuristics"] = {
                "metrics": metrics,
                "hits": [h.__dict__ for h in hits],
            }

            # Surface heuristic hits in the top-level indicator list for quick triage.
            for h in hits:
                report["indicators"].append(
                    {"id": h.id, "severity": h.severity, "message": h.message, "score": h.score}
                )
        except Exception as e:
            report["analysis"]["heuristics_error"] = str(e)

        # -----------------------------
        # Plugins
        # -----------------------------
        # Plugins can add analysis outputs and/or add scored indicators.
        try:
            plugins = discover_plugins(
                plugin_dirs=self.plugin_dirs, include_builtins=self.include_builtin_plugins
            )
            ctx = PluginContext(
                analyzer=self,
                path=path,
                pe=pe,
                report=report,
                options=plugin_options or {},
            )
            results = run_plugins(plugins=plugins, enabled=self.enabled_plugins, ctx=ctx)
            report["analysis"]["plugins_run"] = results
        except Exception as e:
            report["analysis"]["plugins_error"] = str(e)

        # -----------------------------
        # Risk scoring (0-100)
        # -----------------------------
        # Scoring consumes heuristic hit scores, YARA presence, API lists, and any
        # indicator entries that provide a numeric `score` field.
        rules = self._rules()
        scoring_cfg = rules.get("scoring") if isinstance(rules, dict) else None
        attach_score(report, scoring_rules=scoring_cfg)

        # End-of-run timing is useful for profiling batch scans.
        report["timing"] = {"seconds": round(time.time() - t0, 4)}
        return report
