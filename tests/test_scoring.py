"""PrismEX source file.

@QK
"""

from prismex.scoring import compute_score, score_level


def test_score_level_buckets():
    assert score_level(0) == "low"
    assert score_level(19) == "low"
    assert score_level(20) == "medium"
    assert score_level(50) == "high"
    assert score_level(75) == "critical"


def test_compute_score_from_heuristics_and_yara():
    report = {
        "analysis": {
            "heuristics": {
                "hits": [
                    {"id": "rwx_section", "message": "...", "score": 18},
                    {"id": "overlay", "message": "...", "score": 8},
                ]
            },
            "yara": [{"rule": "X"}, {"rule": "Y"}],
            "suspicious_apis": ["CreateRemoteThread", "WriteProcessMemory"],
        }
    }

    score, breakdown = compute_score(report)
    assert 0 <= score <= 100
    assert any(b.id == "yara" for b in breakdown)
