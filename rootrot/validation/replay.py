"""re-run a synthetic scenario and compare its event and finding digests."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..detection import detection_engine
from ..events import event_logger
from ..telemetry.integrity import verify_event_chain
from .scenarios import build_scenario_events, get_scenario


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def replay_scenario(scenario_id: str, repetitions: int = 3) -> dict[str, Any]:
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 25:
        raise ValueError("repetitions must be between 1 and 25")

    definition = get_scenario(scenario_id)
    event_digests = []
    finding_digests = []
    event_count = 0
    final_findings: list[dict[str, Any]] = []
    integrity_results = []

    for index in range(repetitions):
        events = build_scenario_events(scenario_id)
        event_count = len(events)
        integrity = verify_event_chain(events)
        integrity_results.append(integrity["valid"])

        observer = event_logger(run_id=f"replay-observer-{index}")
        findings = detection_engine(observer).analyze(events)
        event_digests.append(_digest(events))
        finding_digests.append(_digest(findings))
        final_findings = findings

    deterministic = (
        len(set(event_digests)) == 1
        and len(set(finding_digests)) == 1
        and all(integrity_results)
    )
    return {
        "scenario_id": scenario_id,
        "description": definition.description,
        "repetitions": repetitions,
        "event_count": event_count,
        "expected_rule_ids": list(definition.expected_rule_ids),
        "detected_rule_ids": sorted({item["rule_id"] for item in final_findings}),
        "event_sha256": event_digests[0],
        "findings_sha256": finding_digests[0],
        "integrity_valid_every_run": all(integrity_results),
        "deterministic": deterministic,
    }
