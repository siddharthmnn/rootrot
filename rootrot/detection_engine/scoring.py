"""keep rule scoring consistent and easy to explain."""

from __future__ import annotations


severity_order = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def score_finding(base_score: int, evidence_count: int) -> int:
    """increase a rule score modestly when the same signal repeats."""
    if isinstance(base_score, bool) or not isinstance(base_score, int) or not 0 <= base_score <= 100:
        raise ValueError("base_score must be an integer between 0 and 100")
    if isinstance(evidence_count, bool) or not isinstance(evidence_count, int) or evidence_count < 1:
        raise ValueError("evidence_count must be a positive integer")
    repeat_bonus = min(15, (evidence_count - 1) * 3)
    return min(100, base_score + repeat_bonus)


def severity_for_score(score: int) -> str:
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("score must be an integer between 0 and 100")
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def meets_minimum_severity(severity: str, minimum: str) -> bool:
    if minimum not in severity_order or severity not in severity_order:
        raise ValueError("severity must be info, low, medium, high, or critical")
    return severity_order[severity] >= severity_order[minimum]
