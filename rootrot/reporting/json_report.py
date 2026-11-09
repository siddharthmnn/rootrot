"""serialize a run report as stable, readable json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .common import write_text


def render_json_report(report: Mapping[str, Any]) -> str:
    if not isinstance(report, Mapping):
        raise TypeError("report must be an object")
    try:
        return json.dumps(
            dict(report),
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        ) + "\n"
    except (TypeError, ValueError) as exc:
        raise ValueError("report contains values that cannot be represented as json") from exc


def write_json_report(
    report: Mapping[str, Any],
    destination: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, object]:
    content = render_json_report(report)
    result = write_text(destination, content, overwrite=overwrite)
    return {**result, "format": "json"}
