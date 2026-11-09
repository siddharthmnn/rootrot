"""measure detection rules against explicit synthetic scenario labels."""

from __future__ import annotations

from typing import Any, Iterable

from ..detection import detection_engine
from ..events import event_logger
from ..telemetry.integrity import verify_event_chain
from .scenarios import get_scenario, list_scenarios, build_scenario_events


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def evaluate_detection_scenarios(
    scenario_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    selected = (
        [item["scenario_id"] for item in list_scenarios()]
        if scenario_ids is None
        else list(scenario_ids)
    )
    if not selected:
        raise ValueError("at least one scenario is required")
    if len(set(selected)) != len(selected):
        raise ValueError("scenario ids must not contain duplicates")

    # Load the rule catalog once; metrics are calculated over every scenario/rule pair.
    catalog_logger = event_logger(run_id="validation-catalog")
    rule_catalog = detection_engine(catalog_logger).list_rules()
    rule_ids = {item["rule_id"] for item in rule_catalog}
    if not rule_ids:
        raise RuntimeError("the detection engine has no registered rules")

    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    scenario_results = []

    for scenario_id in selected:
        definition = get_scenario(scenario_id)
        expected = set(definition.expected_rule_ids)
        unknown_expected = expected - rule_ids
        if unknown_expected:
            raise ValueError(
                f"scenario {scenario_id!r} references unknown rules: "
                + ", ".join(sorted(unknown_expected))
            )

        events = build_scenario_events(scenario_id)
        integrity = verify_event_chain(events)
        if not integrity["valid"]:
            raise RuntimeError(f"scenario {scenario_id!r} produced an invalid event chain")

        detector_logger = event_logger(run_id=f"evaluation-{scenario_id}")
        findings = detection_engine(detector_logger).analyze(events)
        detected = {item["rule_id"] for item in findings}

        true_positive = expected & detected
        false_positive = detected - expected
        false_negative = expected - detected
        true_negative = rule_ids - (expected | detected)

        totals["tp"] += len(true_positive)
        totals["fp"] += len(false_positive)
        totals["fn"] += len(false_negative)
        totals["tn"] += len(true_negative)

        scenario_results.append(
            {
                "scenario_id": scenario_id,
                "event_count": len(events),
                "expected_rule_ids": sorted(expected),
                "detected_rule_ids": sorted(detected),
                "true_positive_rule_ids": sorted(true_positive),
                "false_positive_rule_ids": sorted(false_positive),
                "false_negative_rule_ids": sorted(false_negative),
                "integrity_valid": integrity["valid"],
                "passed": not false_positive and not false_negative,
            }
        )

    tp, fp, fn, tn = (totals[key] for key in ("tp", "fp", "fn", "tn"))
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall) if precision + recall else 0.0
    accuracy = _ratio(tp + tn, tp + fp + fn + tn)
    false_positive_rate = _ratio(fp, fp + tn)

    return {
        "evaluation_basis": (
            "synthetic ground-truth scenario labels; these metrics are for regression "
            "and rule validation, not a field-performance estimate"
        ),
        "scenario_count": len(scenario_results),
        "rule_count": len(rule_ids),
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "false_positive_rate": false_positive_rate,
        },
        "scenarios": scenario_results,
        "passed": all(item["passed"] for item in scenario_results),
    }
