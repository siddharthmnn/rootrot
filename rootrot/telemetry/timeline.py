"""turn event records into a readable chronological timeline."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _timestamp(event: Mapping[str, Any]) -> datetime:
    value = event.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("every timeline event needs an iso 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timeline event contains an invalid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_timeline(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """sort events by time and add elapsed milliseconds from the first event."""
    if isinstance(events, (str, bytes, Mapping)):
        raise ValueError("events must be an iterable of event objects")

    records = []
    for index, event in enumerate(events, start=1):
        if not isinstance(event, Mapping):
            raise ValueError(f"event at position {index} is not an object")
        sequence = event.get("sequence", index)
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError(f"event at position {index} has an invalid sequence")
        records.append((_timestamp(event), sequence, event))

    records.sort(key=lambda item: (item[0], item[1]))
    if not records:
        return []

    origin = records[0][0]
    timeline = []
    for timestamp, sequence, event in records:
        timeline.append({
            "sequence": sequence,
            "timestamp": timestamp.isoformat(),
            "elapsed_ms": round((timestamp - origin).total_seconds() * 1000, 3),
            "run_id": event.get("run_id"),
            "source": event.get("source"),
            "action": event.get("action"),
            "severity": event.get("severity"),
            "details": dict(event.get("details", {}))
            if isinstance(event.get("details", {}), Mapping)
            else {},
        })
    return timeline
