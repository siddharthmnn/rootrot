"""keep a simple event trail and check whether anything was changed later."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from .core.schemas import event_record, utc_now


def _canonical(data: dict[str, Any]) -> bytes:
    # stable json formatting keeps the hash independent of dictionary order
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class event_logger:
    """store structured events in memory and link each one to the event before it."""

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id or secrets.token_hex(12)
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        self.events: list[dict[str, Any]] = []
        self._previous_hash = "0" * 64

    def emit(
        self,
        source: str,
        action: str,
        severity: str = "info",
        **details: Any,
    ) -> dict[str, Any]:
        if not isinstance(source, str) or not source.strip():
            raise ValueError("event source must be a non-empty string")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("event action must be a non-empty string")

        payload = event_record(
            run_id=self.run_id,
            sequence=len(self.events) + 1,
            timestamp=utc_now(),
            source=source,
            action=action,
            severity=severity,
            details=dict(details),
            previous_hash=self._previous_hash,
            event_hash="0" * 64,
        )
        unsigned = payload.unsigned_dict()
        event_hash = hashlib.sha256(_canonical(unsigned)).hexdigest()
        record = {**unsigned, "event_hash": event_hash}

        # validate the exact shape before it becomes part of the event trail
        event_record.from_mapping(record)
        self.events.append(record)
        self._previous_hash = event_hash
        return record

    def verify_integrity(self) -> bool:
        previous_hash = "0" * 64

        for expected_sequence, raw_event in enumerate(self.events, start=1):
            try:
                event = event_record.from_mapping(raw_event)
            except (TypeError, ValueError):
                return False

            if event.run_id != self.run_id or event.sequence != expected_sequence:
                return False
            if event.previous_hash != previous_hash:
                return False

            expected_hash = hashlib.sha256(_canonical(event.unsigned_dict())).hexdigest()
            if not secrets.compare_digest(expected_hash, event.event_hash):
                return False
            previous_hash = expected_hash

        return True
