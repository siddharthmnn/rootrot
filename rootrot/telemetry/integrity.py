"""verify event chains and create checkpoints for later runs."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..core.schemas import event_record


_genesis_hash = "0" * 64


def _canonical(data: Mapping[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _event_hash(event: event_record) -> str:
    return hashlib.sha256(_canonical(event.unsigned_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class integrity_checkpoint:
    run_id: str
    sequence: int
    event_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "sequence": self.sequence,
            "event_hash": self.event_hash,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "integrity_checkpoint":
        if not isinstance(value, Mapping):
            raise ValueError("checkpoint must be an object")
        run_id = value.get("run_id")
        sequence = value.get("sequence")
        event_hash = value.get("event_hash")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("checkpoint run_id must be a non-empty string")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError("checkpoint sequence must be a positive integer")
        if (
            not isinstance(event_hash, str)
            or len(event_hash) != 64
            or any(char not in "0123456789abcdef" for char in event_hash)
        ):
            raise ValueError("checkpoint event_hash must be a sha256 digest")
        return cls(run_id, sequence, event_hash)


def verify_event_chain(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """verify the complete chain and explain the first broken link."""
    if isinstance(events, (str, bytes, Mapping)):
        raise ValueError("events must be an iterable of event objects")
    try:
        records = list(events)
    except TypeError as exc:
        raise ValueError("events must be an iterable of event objects") from exc

    previous_hash = _genesis_hash
    run_id: str | None = None

    for expected_sequence, raw_event in enumerate(records, start=1):
        try:
            event = event_record.from_mapping(raw_event)
        except (TypeError, ValueError) as exc:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "run_id": run_id,
                "failed_sequence": expected_sequence,
                "reason": "invalid_event",
                "message": str(exc),
                "expected_previous_hash": previous_hash,
                "actual_previous_hash": (
                    raw_event.get("previous_hash")
                    if isinstance(raw_event, Mapping)
                    else None
                ),
            }

        if run_id is None:
            run_id = event.run_id
        elif event.run_id != run_id:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "run_id": run_id,
                "failed_sequence": expected_sequence,
                "reason": "run_id_mismatch",
                "expected_run_id": run_id,
                "actual_run_id": event.run_id,
            }

        if event.sequence != expected_sequence:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "run_id": run_id,
                "failed_sequence": expected_sequence,
                "reason": "sequence_mismatch",
                "expected_sequence": expected_sequence,
                "actual_sequence": event.sequence,
            }

        if event.previous_hash != previous_hash:
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "run_id": run_id,
                "failed_sequence": expected_sequence,
                "reason": "previous_hash_mismatch",
                "expected_previous_hash": previous_hash,
                "actual_previous_hash": event.previous_hash,
            }

        expected_hash = _event_hash(event)
        if not secrets.compare_digest(expected_hash, event.event_hash):
            return {
                "valid": False,
                "events_checked": expected_sequence - 1,
                "run_id": run_id,
                "failed_sequence": expected_sequence,
                "reason": "event_hash_mismatch",
                "expected_event_hash": expected_hash,
                "actual_event_hash": event.event_hash,
            }

        previous_hash = expected_hash

    return {
        "valid": True,
        "events_checked": len(records),
        "run_id": run_id,
        "failed_sequence": None,
        "reason": None,
        "final_hash": previous_hash,
    }


def create_checkpoint(events: Iterable[Mapping[str, Any]]) -> integrity_checkpoint:
    """anchor the latest event after checking the complete chain."""
    records = list(events)
    result = verify_event_chain(records)
    if not result["valid"]:
        raise ValueError(
            f"cannot checkpoint an invalid event chain: {result['reason']}"
        )
    if not records:
        raise ValueError("cannot checkpoint an empty event chain")
    last_event = event_record.from_mapping(records[-1])
    return integrity_checkpoint(
        run_id=last_event.run_id,
        sequence=last_event.sequence,
        event_hash=last_event.event_hash,
    )


def verify_checkpoint(
    events: Iterable[Mapping[str, Any]],
    checkpoint: integrity_checkpoint | Mapping[str, Any],
) -> dict[str, Any]:
    """verify events written after a separately stored checkpoint.

    The checkpoint must be stored somewhere independent of the event file.
    This verifies the supplied suffix; it does not re-verify the prefix that
    existed when the checkpoint was created.
    """
    anchor = (
        checkpoint
        if isinstance(checkpoint, integrity_checkpoint)
        else integrity_checkpoint.from_mapping(checkpoint)
    )
    if isinstance(events, (str, bytes, Mapping)):
        raise ValueError("events must be an iterable of event objects")
    try:
        records = list(events)
    except TypeError as exc:
        raise ValueError("events must be an iterable of event objects") from exc

    previous_hash = anchor.event_hash
    expected_sequence = anchor.sequence + 1

    for index, raw_event in enumerate(records):
        try:
            event = event_record.from_mapping(raw_event)
        except (TypeError, ValueError) as exc:
            return {
                "valid": False,
                "events_checked": index,
                "run_id": anchor.run_id,
                "failed_sequence": expected_sequence,
                "reason": "invalid_event",
                "message": str(exc),
            }

        if event.run_id != anchor.run_id:
            reason = "run_id_mismatch"
        elif event.sequence != expected_sequence:
            reason = "sequence_mismatch"
        elif event.previous_hash != previous_hash:
            reason = "previous_hash_mismatch"
        else:
            calculated = _event_hash(event)
            if not secrets.compare_digest(calculated, event.event_hash):
                reason = "event_hash_mismatch"
            else:
                previous_hash = calculated
                expected_sequence += 1
                continue

        return {
            "valid": False,
            "events_checked": index,
            "run_id": anchor.run_id,
            "failed_sequence": expected_sequence,
            "reason": reason,
        }

    return {
        "valid": True,
        "events_checked": len(records),
        "run_id": anchor.run_id,
        "checkpoint_sequence": anchor.sequence,
        "final_sequence": expected_sequence - 1,
        "final_hash": previous_hash,
        "reason": None,
    }
