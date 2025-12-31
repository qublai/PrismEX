"""Report formatting and rendering.

PrismEX produces a single *canonical* report object (a Python ``dict``) in the
analysis engine. This module converts that dict into human-facing formats:

- **Text**: quick terminal-friendly summary.
- **HTML**: a single-file, offline report (no external assets).
- **Batch HTML index**: navigable overview for directory scans.

HTML rendering uses Jinja2 templates shipped with the package.

@QK
"""

from __future__ import annotations

import json
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape


def format_text(report: Dict[str, Any]) -> str:
    """Format a report dict as a compact text summary.

    This is intentionally a *summary* (not a full dump). For full fidelity,
    use JSON output.
    """

    lines: list[str] = []

    tool = report.get("tool", {})
    target = report.get("target", {})
    pe = report.get("pe", {})
    indicators = report.get("indicators", [])

    # Header
    lines.append(f"{tool.get('name','PrismEX')} v{tool.get('version','')}")
    lines.append("")

    # Target section
    lines.append("Target")
    lines.append("------")
    lines.append(f"Path:  {target.get('path','')}")
    lines.append(f"Type:  {target.get('type','')}")
    lines.append(f"Size:  {target.get('size','')} bytes")
    h = target.get("hashes", {})
    lines.append(f"MD5:   {h.get('md5','')}")
    lines.append(f"SHA1:  {h.get('sha1','')}")
    lines.append(f"SHA256:{h.get('sha256','')}")
    lines.append("")

    # PE summary
    lines.append("PE Summary")
    lines.append("----------")
    for k in [
        "imphash",
        "timestamp_utc",
        "machine",
        "subsystem",
        "imagebase",
        "entrypoint_rva",
        "is_dll",
    ]:
        if k in pe:
            lines.append(f"{k}: {pe.get(k)}")
    lines.append("")

    # Score (if present)
    score = report.get("score", {})
    if score:
        lines.append("Risk Score")
        lines.append("----------")
        lines.append(f"Score: {score.get('value')} / 100 ({str(score.get('level','')).upper()})")

        # Include the top few contributors for explainability.
        for c in (score.get("breakdown") or [])[:8]:
            lines.append(f"  +{c.get('points')}: {c.get('id')} - {c.get('message')}")
        lines.append("")

    # Indicators are the quick-triage queue.
    lines.append("Indicators")
    lines.append("----------")
    if not indicators:
        lines.append("None")
    else:
        for ind in indicators:
            lines.append(f"[{ind.get('severity','').upper()}] {ind.get('id')}: {ind.get('message')}")
    lines.append("")

    # YARA matches are often useful to surface even in text output.
    yara = report.get("analysis", {}).get("yara", [])
    if yara:
        lines.append("YARA")
        lines.append("----")
        for m in yara[:50]:
            lines.append(str(m))
        if len(yara) > 50:
            lines.append(f"... ({len(yara)-50} more)")
        lines.append("")

    return "\n".join(lines)


def render_html(report: Dict[str, Any], *, template_dir: str, template_name: str = "report.html.j2") -> str:
    """Render a single-report HTML page.

    The output is a *single, self-contained HTML file* suitable for sharing.
    We also embed ``report_json`` so the page can offer a "Download JSON"
    button without requiring a server.
    """

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template(template_name)

    # Provide a JSON blob for in-page downloads.
    report_json = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    return tpl.render(report=report, report_json=report_json)


def render_html_index(
    batch: Dict[str, Any],
    *,
    template_dir: str,
    template_name: str = "index.html.j2",
) -> str:
    """Render the batch index HTML.

    ``batch`` is a dict containing:
    - tool: {name, version}
    - batch: {count, seconds}
    - results: list[report]

    Each report is expected to have an ``_html_file`` key injected by the CLI.
    """

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tpl = env.get_template(template_name)
    return tpl.render(batch=batch)
