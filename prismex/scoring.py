"""Explainable risk scoring for PrismEX.

PrismEX produces a 0–100 *risk* score meant for analyst triage.

This is deliberately **not** a machine-learning classifier. Instead, it is a
transparent additive model:

- Heuristics contribute explicit point values.
- Certain strong signals (e.g., YARA hits) add capped bonuses.
- Plugins can add their own scored indicators without modifying core code.

Scoring and thresholds are configurable via the rules JSON file
(see ``prismex_rules.example.json``).

@QK
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class ScoreComponent:
    """One scored contribution to the overall risk score."""

    id: str
    points: int
    message: str


def score_level(score: int, thresholds: Dict[str, int] | None = None) -> str:
    """Map a numeric score to a qualitative level.

    Thresholds are configurable; default values are conservative:
    - medium: 20+
    - high: 50+
    - critical: 75+
    """

    th = thresholds or {"medium": 20, "high": 50, "critical": 75}
    if score >= int(th.get("critical", 75)):
        return "critical"
    if score >= int(th.get("high", 50)):
        return "high"
    if score >= int(th.get("medium", 20)):
        return "medium"
    return "low"


def compute_score(
    report: Dict[str, Any],
    scoring_rules: Dict[str, Any] | None = None,
) -> Tuple[int, List[ScoreComponent]]:
    """Compute a 0–100 risk score from heuristics + indicators.

    Sources of score:
    1) Heuristic hits (``analysis.heuristics.hits[*].score``)
    2) YARA hits (baseline + per-hit increment, capped)
    3) Suspicious API list (apialert)
    4) Top-level indicators that carry a numeric ``score`` (plugin-friendly)

    Returns:
        (score, breakdown)

    Notes:
        - The function is resilient to missing keys and type mismatches.
        - A final cap is applied to prevent runaway scoring.
    """

    sr = scoring_rules or {}
    total = 0
    breakdown: List[ScoreComponent] = []

    # ---------------------------------------------------------------------
    # 1) Heuristic hits
    # ---------------------------------------------------------------------
    heur = (report.get("analysis", {}).get("heuristics") or {}).get("hits", [])
    if isinstance(heur, list):
        for h in heur:
            # Each heuristic hit is produced by prismex.heuristics.HeuristicHit.
            # We treat missing/invalid values as 0 points.
            try:
                pts = int(h.get("score") or 0)
            except Exception:
                continue

            if pts <= 0:
                continue

            total += pts
            breakdown.append(
                ScoreComponent(
                    id=str(h.get("id", "heuristic")),
                    points=pts,
                    message=str(h.get("message", "")),
                )
            )

    # ---------------------------------------------------------------------
    # 2) YARA hits
    # ---------------------------------------------------------------------
    yara = report.get("analysis", {}).get("yara", [])
    if isinstance(yara, list) and yara:
        # Default: YARA is treated as a strong signal.
        y = sr.get("yara", {}) if isinstance(sr.get("yara"), dict) else {}
        base = int(y.get("base", 25))
        per_hit = int(y.get("per_hit", 5))
        cap = int(y.get("cap", 40))

        # Baseline + per-hit increment, capped.
        pts = min(cap, base + per_hit * max(0, len(yara) - 1))
        total += pts
        breakdown.append(
            ScoreComponent(
                id="yara",
                points=pts,
                message=f"YARA matched {len(yara)} rule(s).",
            )
        )

    # ---------------------------------------------------------------------
    # 3) Suspicious APIs list (apialert)
    # ---------------------------------------------------------------------
    apis = report.get("analysis", {}).get("suspicious_apis", [])
    if isinstance(apis, list) and apis:
        a = sr.get("suspicious_apis", {}) if isinstance(sr.get("suspicious_apis"), dict) else {}
        base = int(a.get("base", 5))
        per_api = int(a.get("per_api", 1))
        cap = int(a.get("cap", 25))

        pts = min(cap, base + per_api * len(apis))
        total += pts
        breakdown.append(
            ScoreComponent(
                id="suspicious_apis",
                points=pts,
                message=f"High-signal API imports ({len(apis)}).",
            )
        )

    # ---------------------------------------------------------------------
    # 4) Indicator-scored contributions (plugin-friendly)
    # ---------------------------------------------------------------------
    inds = report.get("indicators", [])
    if isinstance(inds, list):
        for i in inds:
            if not isinstance(i, dict):
                continue
            try:
                pts = int(i.get("score") or 0)
            except Exception:
                continue
            if pts <= 0:
                continue

            total += pts
            breakdown.append(
                ScoreComponent(
                    id=str(i.get("id", "indicator")),
                    points=pts,
                    message=str(i.get("message", "")),
                )
            )

    # ---------------------------------------------------------------------
    # Normalize / cap
    # ---------------------------------------------------------------------
    overall_cap = int(sr.get("overall_cap", 100))
    total = max(0, min(overall_cap, total))

    # Sort to show the most influential components first.
    breakdown.sort(key=lambda x: x.points, reverse=True)
    return total, breakdown


def attach_score(report: Dict[str, Any], scoring_rules: Dict[str, Any] | None = None) -> None:
    """Attach ``report['score']`` in-place."""

    score, breakdown = compute_score(report, scoring_rules=scoring_rules)

    thresholds = None
    if isinstance(scoring_rules, dict) and isinstance(scoring_rules.get("thresholds"), dict):
        thresholds = scoring_rules.get("thresholds")

    report["score"] = {
        "value": score,
        "level": score_level(score, thresholds=thresholds),
        "breakdown": [b.__dict__ for b in breakdown],
    }
