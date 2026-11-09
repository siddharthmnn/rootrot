"""build compact forensic summaries from events and detection findings."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

from .integrity import verify_event_chain
from .timeline import build_timeline


def build_forensic_summary(
    events: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    records = list(events)
    finding_records = list(findings)
    integrity = verify_event_chain(records)
    timeline = build_timeline(records)

    sources = Counter()
    actions = Counter()
    severities = Counter()
    finding_severities = Counter()
    finding_rules = Counter()

    for event in records:
        if not isinstance(event, Mapping):
            raise ValueError("each event must be an object")
        sources[str(event.get("source", "unknown"))] += 1
        actions[str(event.get("action", "unknown"))] += 1
        severities[str(event.get("severity", "unknown"))] += 1

    for finding in finding_records:
        if not isinstance(finding, Mapping):
            raise ValueError("each finding must be an object")
        finding_severities[str(finding.get("severity", "unknown"))] += 1
        finding_rules[str(finding.get("rule", finding.get("rule_id", "unknown")))] += 1

    run_ids = sorted({
        event.get("run_id")
        for event in records
        if isinstance(event.get("run_id"), str)
    })

    return {
        "event_count": len(records),
        "run_count": len(run_ids),
        "run_ids": run_ids,
        "time_range": {
            "start": timeline[0]["timestamp"] if timeline else None,
            "end": timeline[-1]["timestamp"] if timeline else None,
            "duration_ms": (
                timeline[-1]["elapsed_ms"] if timeline else 0.0
            ),
        },
        "events_by_source": dict(sorted(sources.items())),
        "events_by_action": dict(sorted(actions.items())),
        "events_by_severity": dict(sorted(severities.items())),
        "findings": {
            "count": len(finding_records),
            "by_severity": dict(sorted(finding_severities.items())),
            "by_rule": dict(sorted(finding_rules.items())),
        },
        "integrity": integrity,
    }
