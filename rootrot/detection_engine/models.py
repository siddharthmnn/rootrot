"""small result types shared by detection rules and the engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


def event_reference(event: Mapping[str, Any], fallback_sequence: int) -> dict[str, Any]:
    """keep the useful event fields without copying the full event payload."""
    return {
        "run_id": event.get("run_id"),
        "sequence": event.get("sequence", fallback_sequence),
        "timestamp": event.get("timestamp"),
        "source": event.get("source"),
        "action": event.get("action"),
    }


@dataclass(frozen=True, slots=True)
class detection_finding:
    rule_id: str
    rule: str
    severity: str
    score: int
    explanation: str
    evidence: dict[str, Any]
    events: tuple[dict[str, Any], ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule,
            "severity": self.severity,
            "score": self.score,
            "explanation": self.explanation,
            "evidence": dict(self.evidence),
            "events": [dict(item) for item in self.events],
            "mitre_techniques": list(self.mitre_techniques),
        }
