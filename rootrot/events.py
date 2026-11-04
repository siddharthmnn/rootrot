"""keep a simple event trail and check whether anything was changed later."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(data: dict[str, Any]) -> bytes:
    # using a stable json format means the same event always hashes the same way
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class event_logger:
    """store events in memory and link each one to the event before it."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._previous_hash = "0" * 64

    def emit(
        self,
        source: str,
        action: str,
        severity: str = "info",
        **details: Any,
    ) -> dict[str, Any]:
        record = {
            "timestamp": _now(),
            "source": source,
            "action": action,
            "severity": severity,
            "details": details,
            "previous_hash": self._previous_hash,
        }

        event_hash = hashlib.sha256(_canonical(record)).hexdigest()
        record["event_hash"] = event_hash
        self.events.append(record)
        self._previous_hash = event_hash
        return record

    def verify_integrity(self) -> bool:
        previous_hash = "0" * 64

        for event in self.events:
            # the current hash is left out while we recalculate it
            record = {
                key: value
                for key, value in event.items()
                if key != "event_hash"
            }

            if record.get("previous_hash") != previous_hash:
                return False

            expected = hashlib.sha256(_canonical(record)).hexdigest()
            if expected != event.get("event_hash"):
                return False

            previous_hash = expected

        return True
