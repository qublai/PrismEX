"""PrismEX command-line interface.

This file is intentionally small and dependency-light:
- Argument parsing (argparse)
- Target expansion (files vs directories, recursive scanning, patterns)
- Writing reports in text/json/html

The heavy lifting happens in :class:`prismex.core.PrismEXAnalyzer`.

@QK
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .core import PrismEXAnalyzer
from .paths import DEFAULT_STRINGMATCH_PATH, DEFAULT_YARA_DIR
from .report import format_text, render_html, render_html_index
from .utils import iter_targets, is_dir


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level `prismex` parser.

    The CLI is subcommand-based:
    - `prismex scan ...`    run analysis
    - `prismex rules ...`   YARA helper utilities
    - `prismex plugins ...` plugin discovery utilities
    """

    p = argparse.ArgumentParser(
        prog="prismex",
        description="PrismEX - static analysis for Portable Executables (PE)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # -----------------------------
    # scan
    # -----------------------------
    scan = sub.add_parser("scan", help="Scan one or more files (or a directory) and emit a report")
    scan.add_argument("paths", nargs="+", help="File(s) or directory path(s)")
    scan.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format",
    )
    scan.add_argument("-o", "--out", help="Output file (single target) or output directory (batch)")

    # Directory scanning controls
    scan.add_argument("--recursive", action="store_true", help="Recursively scan directories")
    scan.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Glob pattern(s) for directory scanning (repeatable). Defaults to common PE extensions.",
    )
    scan.add_argument("--max-files", type=int, default=None, help="Stop after scanning N files (batch)")
    scan.add_argument(
        "--follow-symlinks", action="store_true", help="Follow symlinks when scanning directories"
    )

    # Feature toggles
    scan.add_argument("--no-strings", action="store_true", help="Disable printable string extraction")
    scan.add_argument("--no-yara", action="store_true", help="Disable YARA scanning")

    # Data sources
    scan.add_argument("--yara-dir", default=str(DEFAULT_YARA_DIR), help="Custom YARA rules directory")
    scan.add_argument(
        "--stringmatch", default=str(DEFAULT_STRINGMATCH_PATH), help="Custom stringmatch.json path"
    )
    scan.add_argument(
        "--config",
        default=None,
        help="Path to PrismEX config JSON (scoring/heuristics weights, feature toggles)",
    )

    # Batch exports
    scan.add_argument("--csv", action="store_true", help="In batch mode, write a CSV summary")
    scan.add_argument(
        "--csv-out", default=None, help="CSV output path (defaults to <out>/summary.csv or ./summary.csv)"
    )

    # Plugins
    scan.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        help="Add a directory to load PrismEX plugins from (repeatable)",
    )
    scan.add_argument(
        "--enable-plugin",
        action="append",
        default=None,
        help="Only run these plugin names (repeatable). If omitted, all discovered plugins run.",
    )
    scan.add_argument("--no-builtin-plugins", action="store_true", help="Disable built-in plugins")

    # -----------------------------
    # rules
    # -----------------------------
    rules = sub.add_parser("rules", help="Rule utilities")
    rules_sub = rules.add_subparsers(dest="rules_cmd", required=True)
    rules_list = rules_sub.add_parser("list", help="List bundled YARA rules")
    rules_list.add_argument("--yara-dir", default=str(DEFAULT_YARA_DIR))

    # -----------------------------
    # plugins
    # -----------------------------
    plugins = sub.add_parser("plugins", help="Plugin utilities")
    plugins_sub = plugins.add_subparsers(dest="plugins_cmd", required=True)
    plugins_list = plugins_sub.add_parser("list", help="List available plugins")
    plugins_list.add_argument("--plugin-dir", action="append", default=[])
    plugins_list.add_argument("--no-builtin-plugins", action="store_true")

    return p


def _write_text(path: Path, content: str) -> None:
    """Write UTF-8 text, creating parent directories."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")


def _write_csv(path: Path, rows: list[dict]) -> None:
    """Write a CSV (best-effort) from list-of-dicts rows."""

    import csv

    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        # Still create the file to make automation scripts predictable.
        path.write_text("", encoding="utf-8")
        return

    # We take the first row's keys as a stable header order.
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8", errors="ignore") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _summarize_row(rep: dict) -> dict:
    """Create a flat summary row suitable for CSV.

    Keep these fields compact and stable because users often feed batch CSVs
    into spreadsheets or SIEM tools.
    """

    target = rep.get("target", {}) if isinstance(rep, dict) else {}
    pe = rep.get("pe", {}) if isinstance(rep, dict) else {}
    score = rep.get("score", {}) if isinstance(rep, dict) else {}

    h = target.get("hashes", {}) if isinstance(target, dict) else {}

    return {
        "path": target.get("path", ""),
        "size": target.get("size", ""),
        "type": target.get("type", ""),
        "sha256": h.get("sha256", ""),
        "imphash": pe.get("imphash", ""),
        "timestamp_utc": pe.get("timestamp_utc", ""),
        "score": (score.get("value") if isinstance(score, dict) else ""),
        "level": (score.get("level") if isinstance(score, dict) else ""),
        "error": rep.get("error", ""),
    }


def cmd_scan(args: argparse.Namespace) -> int:
    """Entry point for `prismex scan`."""

    t0 = time.time()

    # Expand input paths into a concrete list of file targets.
    # We do this once so we can determine single vs batch output.
    patterns = args.pattern if args.pattern else None
    targets = list(
        iter_targets(
            args.paths,
            recursive=args.recursive,
            follow_symlinks=args.follow_symlinks,
            patterns=patterns,
            max_files=args.max_files,
        )
    )

    if not targets:
        print("No matching targets found.", file=sys.stderr)
        return 2

    # Instantiate the analysis engine.
    # `config_path` can be None to disable config tuning (defaults apply).
    engine = PrismEXAnalyzer(
        yara_rules_dir=args.yara_dir,
        stringmatch_path=args.stringmatch,
        config_path=args.config,
        plugin_dirs=args.plugin_dir,
        enabled_plugins=args.enable_plugin,
        include_builtin_plugins=not args.no_builtin_plugins,
    )

    include_strings = not args.no_strings
    include_yara = not args.no_yara

    # Determine batch vs single:
    # - multiple targets, or
    # - any original CLI path was a directory
    batch = len(targets) > 1 or any(is_dir(p) for p in args.paths)

    # HTML batch needs an output directory to store per-file pages + index.
    if args.format == "html" and batch and not args.out:
        print("For HTML batch reports, please provide --out <output_dir>.", file=sys.stderr)
        return 2

    # Run analysis for each target. Failures are embedded as per-target errors
    # so a single bad file doesn't break the whole batch.
    reports: list[dict] = []
    for tp in targets:
        try:
            rep = engine.analyze(tp, include_strings=include_strings, include_yara=include_yara)
        except Exception as e:
            rep = {
                "tool": {"name": "PrismEX"},
                "target": {"path": str(Path(tp).resolve())},
                "error": str(e),
            }
        reports.append(rep)

    # -----------------------------
    # Single-target output
    # -----------------------------
    if not batch:
        rep = reports[0]

        if args.format == "json":
            out = json.dumps(rep, sort_keys=True, indent=2)
            if args.out:
                _write_text(Path(args.out), out)
            else:
                print(out)
            return 0

        if args.format == "html":
            template_dir = str(Path(__file__).parent / "templates")
            html = render_html(rep, template_dir=template_dir)
            out_path = Path(args.out) if args.out else Path("prismex_report.html")
            _write_text(out_path, html)
            print(str(out_path))
            return 0

        # text (default)
        out = format_text(rep)
        if args.out:
            _write_text(Path(args.out), out)
        else:
            print(out)
        return 0

    # -----------------------------
    # Batch output
    # -----------------------------
    seconds = round(time.time() - t0, 4)
    batch_obj = {
        "tool": {"name": "PrismEX", "version": reports[0].get("tool", {}).get("version", "")},
        "batch": {"count": len(reports), "seconds": seconds},
        "results": reports,
    }

    # CSV summary is supported for any batch mode.
    if args.csv or args.csv_out:
        # Default CSV path: <out>/summary.csv if --out is a directory, else ./summary.csv
        if args.csv_out:
            csv_path = Path(args.csv_out)
        elif args.out:
            op = Path(args.out)
            csv_path = (op if op.is_dir() else op.parent) / "summary.csv"
        else:
            csv_path = Path("summary.csv")

        rows = [_summarize_row(rep) for rep in reports]
        _write_csv(csv_path, rows)

    if args.format == "json":
        out = json.dumps(batch_obj, sort_keys=True, indent=2)
        if args.out:
            op = Path(args.out)

            # If the user gave a .json path, write a single combined batch JSON.
            if op.suffix.lower() == ".json":
                _write_text(op, out)
            else:
                op.mkdir(parents=True, exist_ok=True)

                # Write one file per target for easy ingestion.
                for rep in reports:
                    name = Path(rep.get("target", {}).get("path", "target")).name
                    _write_text(op / f"{name}.json", json.dumps(rep, sort_keys=True, indent=2))

                # Write the aggregated batch JSON as well.
                _write_text(op / "batch.json", out)
        else:
            print(out)
        return 0

    if args.format == "html":
        op = Path(args.out)
        op.mkdir(parents=True, exist_ok=True)
        template_dir = str(Path(__file__).parent / "templates")

        # Per-file HTML reports
        for rep in reports:
            name = Path(rep.get("target", {}).get("path", "target")).name
            html_file = f"{name}.html"

            # The batch index uses this to link out to per-file pages.
            rep["_html_file"] = html_file

            html = render_html(rep, template_dir=template_dir)
            _write_text(op / html_file, html)

        # Batch index (sortable/filterable client-side)
        index_html = render_html_index(batch_obj, template_dir=template_dir)
        _write_text(op / "index.html", index_html)
        print(str(op / "index.html"))
        return 0

    # text batch
    if args.out:
        op = Path(args.out)

        # If it's a directory, write one txt per file.
        if op.is_dir() or str(op).endswith(("/", "\\")):
            op.mkdir(parents=True, exist_ok=True)
            for rep in reports:
                name = Path(rep.get("target", {}).get("path", "target")).name
                _write_text(op / f"{name}.txt", format_text(rep))
            return 0

        # Otherwise, write a single combined file separated by rulers.
        parts: list[str] = []
        for rep in reports:
            parts.append(format_text(rep))
            parts.append("\n" + ("=" * 80) + "\n")
        _write_text(op, "\n".join(parts))
        return 0

    # If no --out is provided, print all text reports to stdout.
    for i, rep in enumerate(reports):
        if i:
            print("\n" + ("=" * 80) + "\n")
        print(format_text(rep))
    return 0


def cmd_rules_list(args: argparse.Namespace) -> int:
    """List bundled YARA rules in the configured directory."""

    yara_dir = Path(args.yara_dir)
    if not yara_dir.exists():
        print(f"YARA directory not found: {yara_dir}", file=sys.stderr)
        return 2

    rules = sorted([p for p in yara_dir.rglob("*") if p.suffix in {".yar", ".yara"}])
    for r in rules:
        print(str(r))
    return 0


def cmd_plugins_list(args: argparse.Namespace) -> int:
    """List discovered plugin names."""

    from .pluginsystem import discover_plugins

    plugins = discover_plugins(plugin_dirs=args.plugin_dir, include_builtins=not args.no_builtin_plugins)
    if not plugins:
        print("No plugins discovered.")
        return 0

    for n in sorted(plugins.keys()):
        print(n)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point used by the console_script `prismex`."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)

    if args.command == "rules":
        if args.rules_cmd == "list":
            return cmd_rules_list(args)

    if args.command == "plugins":
        if args.plugins_cmd == "list":
            return cmd_plugins_list(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
