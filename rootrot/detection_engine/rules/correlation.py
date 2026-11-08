"""correlate different simulated behaviour categories within one run."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping

from ..models import detection_finding, event_reference
from ..scoring import score_finding, severity_for_score
from .base import detection_rule


_event_categories = {
    "file.inspected": "file_activity",
    "inventory.completed": "file_activity",
    "file.extension_mismatch": "file_activity",
    "persistence.would_write": "persistence",
    "c2.command_queued": "c2_activity",
    "c2.command_completed": "c2_activity",
    "c2.beacon": "c2_activity",
    "data.staged_in_memory": "data_staging",
    "ransomware.dry_run": "file_targeting",
}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class multi_stage_correlation_rule(detection_rule):
    rule_id = "rr.sequence.001"
    name = "multi_stage_activity_sequence"
    description = "correlates multiple simulated behaviour categories in a single run"
    base_score = 72
    required_categories = 3

    def __init__(self, window_seconds: int = 120) -> None:
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int):
            raise ValueError("window_seconds must be an integer")
        if not 1 <= window_seconds <= 3600:
            raise ValueError("window_seconds must be between 1 and 3600")
        self.window_seconds = window_seconds

    def evaluate(
        self,
        events: list[Mapping[str, Any]],
    ) -> list[detection_finding]:
        groups: dict[str, list[tuple[datetime, int, Mapping[str, Any], str]]] = {}
        for index, event in enumerate(events, start=1):
            action = event.get("action")
            category = _event_categories.get(action)
            timestamp = _parse_timestamp(event.get("timestamp"))
            if category is None or timestamp is None:
                continue
            run_id = event.get("run_id")
            group_key = run_id if isinstance(run_id, str) and run_id else "unknown"
            sequence = event.get("sequence", index)
            if isinstance(sequence, bool) or not isinstance(sequence, int):
                sequence = index
            groups.setdefault(group_key, []).append((timestamp, sequence, event, category))

        findings = []
        for run_id, records in groups.items():
            records.sort(key=lambda item: (item[0], item[1]))
            counts: Counter[str] = Counter()
            left = 0
            best_window: list[tuple[datetime, int, Mapping[str, Any], str]] | None = None
            best_duration: float | None = None

            for right, current in enumerate(records):
                counts[current[3]] += 1
                while left <= right:
                    duration = (current[0] - records[left][0]).total_seconds()
                    if duration <= self.window_seconds:
                        break
                    counts[records[left][3]] -= 1
                    if counts[records[left][3]] == 0:
                        del counts[records[left][3]]
                    left += 1

                while left <= right and len(counts) >= self.required_categories:
                    candidate = records[left:right + 1]
                    duration = (candidate[-1][0] - candidate[0][0]).total_seconds()
                    if best_duration is None or duration < best_duration:
                        best_duration = duration
                        best_window = candidate
                    counts[records[left][3]] -= 1
                    if counts[records[left][3]] == 0:
                        del counts[records[left][3]]
                    left += 1

            if not best_window:
                continue

            categories = sorted({item[3] for item in best_window})
            matched_events = [item[2] for item in best_window]
            score = score_finding(self.base_score, len(categories))
            references = tuple(
                event_reference(item, index + 1)
                for index, item in enumerate(matched_events[-25:])
            )
            findings.append(
                detection_finding(
                    rule_id=self.rule_id,
                    rule=self.name,
                    severity=severity_for_score(score),
                    score=score,
                    explanation=(
                        "several simulated behaviour categories occurred close together "
                        "in one run; this is a correlation example, not proof of compromise"
                    ),
                    evidence={
                        "run_id": run_id,
                        "categories": categories,
                        "category_count": len(categories),
                        "event_count": len(matched_events),
                        "window_seconds": round(best_duration or 0.0, 3),
                    },
                    events=references,
                )
            )

        return findings
