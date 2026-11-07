"""small, validated data structures shared across the runtime."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


event_severities = frozenset(
    {"debug", "info", "low", "medium", "warning", "high", "critical", "alert", "error"}
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class event_record:
    """the common shape for one event in a run's audit trail."""

    run_id: str
    sequence: int
    timestamp: str
    source: str
    action: str
    severity: str
    details: dict[str, Any]
    previous_hash: str
    event_hash: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "source": self.source,
            "action": self.action,
            "severity": self.severity,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "event_hash": self.event_hash}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "event_record":
        if not isinstance(value, Mapping):
            raise ValueError("event record must be an object")
        required = {
            "run_id", "sequence", "timestamp", "source", "action",
            "severity", "details", "previous_hash", "event_hash",
        }
        if set(value) != required:
            raise ValueError("event record has missing or unexpected fields")

        for name in ("run_id", "timestamp", "source", "action", "severity", "previous_hash", "event_hash"):
            if not isinstance(value[name], str) or not value[name]:
                raise ValueError(f"event field '{name}' must be a non-empty string")

        if isinstance(value["sequence"], bool) or not isinstance(value["sequence"], int):
            raise ValueError("event sequence must be an integer")
        if value["sequence"] < 1:
            raise ValueError("event sequence must be positive")
        if value["severity"] not in event_severities:
            raise ValueError("event severity is not supported")
        if not isinstance(value["details"], dict):
            raise ValueError("event details must be an object")

        try:
            datetime.fromisoformat(value["timestamp"])
        except ValueError as exc:
            raise ValueError("event timestamp must be iso 8601") from exc

        for name in ("previous_hash", "event_hash"):
            digest = value[name]
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError(f"event field '{name}' must be a sha256 hex digest")

        return cls(
            run_id=value["run_id"],
            sequence=value["sequence"],
            timestamp=value["timestamp"],
            source=value["source"],
            action=value["action"],
            severity=value["severity"],
            details=dict(value["details"]),
            previous_hash=value["previous_hash"],
            event_hash=value["event_hash"],
        )


@dataclass(frozen=True, slots=True)
class simulation_result:
    """the outcome and timing information for one registered simulation."""

    module: str
    started_at: str
    completed_at: str
    duration_ms: float
    output: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": "completed",
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "output": self.output,
        }
