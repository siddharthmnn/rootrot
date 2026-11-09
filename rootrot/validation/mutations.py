"""controlled event mutations for integrity and detection-sequence regression checks."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..detection import detection_engine
from ..events import event_logger
from ..telemetry.integrity import verify_event_chain
from .scenarios import build_scenario_events


mutation = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


def _integrity_mutations() -> dict[str, mutation]:
    def tamper_details(events):
        changed = copy.deepcopy(events)
        changed[0]["details"]["mutation"] = "changed"
        return changed

    def remove_event(events):
        changed = copy.deepcopy(events)
        del changed[1]
        return changed

    def duplicate_event(events):
        changed = copy.deepcopy(events)
        changed.insert(2, copy.deepcopy(changed[1]))
        return changed

    def reorder_events(events):
        changed = copy.deepcopy(events)
        changed[0], changed[1] = changed[1], changed[0]
        return changed

    def break_previous_hash(events):
        changed = copy.deepcopy(events)
        changed[1]["previous_hash"] = "f" * 64
        return changed

    def break_event_hash(events):
        changed = copy.deepcopy(events)
        changed[1]["event_hash"] = "f" * 64
        return changed

    def add_unknown_field(events):
        changed = copy.deepcopy(events)
        changed[0]["unexpected"] = True
        return changed

    def break_timestamp(events):
        changed = copy.deepcopy(events)
        changed[0]["timestamp"] = "not-a-timestamp"
        return changed

    return {
        "details_tampering": tamper_details,
        "event_removal": remove_event,
        "event_duplication": duplicate_event,
        "event_reordering": reorder_events,
        "previous_hash_corruption": break_previous_hash,
        "event_hash_corruption": break_event_hash,
        "unexpected_field": add_unknown_field,
        "timestamp_corruption": break_timestamp,
    }


def run_integrity_mutation_suite() -> dict[str, Any]:
    baseline = build_scenario_events("multi_stage_chain")
    baseline_result = verify_event_chain(baseline)
    if not baseline_result["valid"]:
        raise RuntimeError("the unmodified mutation fixture has an invalid event chain")

    results = []
    for name, mutate in _integrity_mutations().items():
        changed = mutate(baseline)
        verification = verify_event_chain(changed)
        results.append(
            {
                "mutation": name,
                "rejected": not verification["valid"],
                "reason": verification["reason"],
                "failed_sequence": verification["failed_sequence"],
            }
        )

    return {
        "baseline_valid": baseline_result["valid"],
        "mutation_count": len(results),
        "rejected_count": sum(item["rejected"] for item in results),
        "mutations": results,
        "passed": all(item["rejected"] for item in results),
    }


def _detected_rules(events: list[dict[str, Any]], run_id: str) -> set[str]:
    observer = event_logger(run_id=run_id)
    findings = detection_engine(observer).analyze(events)
    return {item["rule_id"] for item in findings}


def run_sequence_mutation_suite() -> dict[str, Any]:
    baseline = build_scenario_events("minimal_sequence")
    baseline_rules = _detected_rules(baseline, "sequence-baseline")
    sequence_rule = "rr.sequence.001"
    if sequence_rule not in baseline_rules:
        raise RuntimeError("the baseline sequence fixture did not trigger correlation")

    removed = copy.deepcopy(baseline)
    removed = [event for event in removed if event["action"] != "c2.command_queued"]

    split_run = copy.deepcopy(baseline)
    split_run[-1]["run_id"] = "validation-other-run"

    outside_window = copy.deepcopy(baseline)
    parsed = datetime.fromisoformat(outside_window[-1]["timestamp"].replace("Z", "+00:00"))
    outside_window[-1]["timestamp"] = (parsed + timedelta(seconds=300)).astimezone(
        timezone.utc
    ).isoformat()

    duplicate_category = copy.deepcopy(baseline)
    duplicate_category.insert(1, copy.deepcopy(duplicate_category[0]))

    unrelated_noise = copy.deepcopy(baseline)
    unrelated_noise.append(
        {
            "run_id": "validation-noise",
            "sequence": 1,
            "timestamp": "2026-01-01T00:00:01+00:00",
            "source": "test",
            "action": "process.status",
            "severity": "info",
            "details": {},
            "previous_hash": "0" * 64,
            "event_hash": "0" * 64,
        }
    )

    cases = (
        ("remove_required_category", removed, False),
        ("split_behaviour_across_runs", split_run, False),
        ("move_event_outside_window", outside_window, False),
        ("duplicate_existing_category", duplicate_category, True),
        ("append_unrelated_run_noise", unrelated_noise, True),
    )
    results = []
    for index, (name, events, should_detect) in enumerate(cases):
        found = sequence_rule in _detected_rules(events, f"sequence-mutation-{index}")
        results.append(
            {
                "mutation": name,
                "expected_sequence_finding": should_detect,
                "sequence_finding": found,
                "passed": found is should_detect,
            }
        )

    return {
        "baseline_sequence_finding": True,
        "mutation_count": len(results),
        "mutations": results,
        "passed": all(item["passed"] for item in results),
    }
