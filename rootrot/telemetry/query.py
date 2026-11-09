"""filter recorded events without mutating the original event list."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _as_datetime(value: datetime | str | None, field: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{field} must be an iso 8601 timestamp") from exc
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime or iso 8601 string")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def filter_events(
    events: Iterable[Mapping[str, Any]],
    *,
    run_id: str | None = None,
    source: str | None = None,
    action: str | None = None,
    severities: Iterable[str] | None = None,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """apply exact-match filters and return copies in their original order."""
    if isinstance(events, (str, bytes, Mapping)):
        raise ValueError("events must be an iterable of event objects")

    if run_id is not None and (not isinstance(run_id, str) or not run_id):
        raise ValueError("run_id must be a non-empty string")
    if source is not None and (not isinstance(source, str) or not source):
        raise ValueError("source must be a non-empty string")
    if action is not None and (not isinstance(action, str) or not action):
        raise ValueError("action must be a non-empty string")

    selected_severities: set[str] | None = None
    if severities is not None:
        if isinstance(severities, (str, bytes)):
            raise ValueError("severities must be an iterable of severity names")
        selected_severities = set(severities)
        if any(not isinstance(item, str) or not item for item in selected_severities):
            raise ValueError("severity names must be non-empty strings")

    start_at = _as_datetime(start, "start")
    end_at = _as_datetime(end, "end")
    if start_at is not None and end_at is not None and start_at > end_at:
        raise ValueError("start must not be later than end")
    if limit is not None and (
        isinstance(limit, bool) or not isinstance(limit, int) or limit < 1
    ):
        raise ValueError("limit must be a positive integer")

    results = []
    for event in events:
        if not isinstance(event, Mapping):
            raise ValueError("each event must be an object")
        if run_id is not None and event.get("run_id") != run_id:
            continue
        if source is not None and event.get("source") != source:
            continue
        if action is not None and event.get("action") != action:
            continue
        if selected_severities is not None and event.get("severity") not in selected_severities:
            continue

        if start_at is not None or end_at is not None:
            timestamp = _as_datetime(event.get("timestamp"), "event timestamp")
            if timestamp is None:
                continue
            if start_at is not None and timestamp < start_at:
                continue
            if end_at is not None and timestamp > end_at:
                continue

        results.append(dict(event))
        if limit is not None and len(results) >= limit:
            break

    return results
