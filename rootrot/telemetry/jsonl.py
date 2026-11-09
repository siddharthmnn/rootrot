"""read and write event streams as newline-delimited json."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..core.schemas import event_record
from .integrity import verify_event_chain


def _clean_json_value(value: Any) -> None:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("event data must not contain non-finite numbers")
    elif isinstance(value, dict):
        for item in value.values():
            _clean_json_value(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _clean_json_value(item)


def export_jsonl(
    events: Iterable[Mapping[str, Any]],
    destination: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """write a verified event chain atomically as one json object per line."""
    records = list(events)
    integrity = verify_event_chain(records)
    if not integrity["valid"]:
        raise ValueError(
            f"refusing to export an invalid event chain: {integrity['reason']}"
        )

    path = Path(destination)
    if path.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {path}")
    if not path.parent.exists() or not path.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {path.parent}")

    for event in records:
        event_record.from_mapping(event)
        _clean_json_value(dict(event))

    encoded = "".join(
        json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"
        for event in records
    )

    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(f"output already exists: {path}")
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    return {
        "path": str(path),
        "event_count": len(records),
        "run_id": integrity["run_id"],
        "final_hash": integrity["final_hash"],
    }


def load_jsonl(
    source: str | Path,
    *,
    max_line_bytes: int = 1_048_576,
    max_events: int = 100_000,
    verify_integrity: bool = True,
) -> list[dict[str, Any]]:
    """load a bounded event stream and reject malformed or broken records."""
    if isinstance(max_line_bytes, bool) or not isinstance(max_line_bytes, int) or max_line_bytes < 1:
        raise ValueError("max_line_bytes must be a positive integer")
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
        raise ValueError("max_events must be a positive integer")
    if not isinstance(verify_integrity, bool):
        raise TypeError("verify_integrity must be a boolean")

    path = Path(source)
    records: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        line_number = 0
        while True:
            raw_line = handle.readline(max_line_bytes + 1)
            if not raw_line:
                break
            line_number += 1
            if len(raw_line) > max_line_bytes:
                raise ValueError(f"event line {line_number} exceeds the configured size limit")
            if not raw_line.strip():
                continue
            try:
                parsed = json.loads(
                    raw_line.decode("utf-8"),
                    parse_constant=lambda value: (_ for _ in ()).throw(
                        ValueError(f"invalid numeric constant: {value}")
                    ),
                )
                event = event_record.from_mapping(parsed)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid event on line {line_number}: {exc}") from exc

            records.append(event.to_dict())
            if len(records) > max_events:
                raise ValueError("event file exceeds the configured event limit")

    if verify_integrity:
        result = verify_event_chain(records)
        if not result["valid"]:
            raise ValueError(
                f"event chain failed at sequence {result['failed_sequence']}: {result['reason']}"
            )
    return records
