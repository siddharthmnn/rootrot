"""bounded, seeded mutation fuzzing for event and run-configuration parsers."""

from __future__ import annotations

import copy
import random
from typing import Any, Callable

from ..core.config import rootrot_config
from ..core.schemas import event_record
from .scenarios import build_scenario_events


event_mutator = Callable[[dict[str, Any]], dict[str, Any]]
config_mutator = Callable[[dict[str, Any]], dict[str, Any]]


def _event_mutators() -> tuple[event_mutator, ...]:
    def remove_required_field(value):
        value.pop("source")
        return value

    def add_unknown_field(value):
        value["unexpected"] = True
        return value

    def boolean_sequence(value):
        value["sequence"] = True
        return value

    def non_positive_sequence(value):
        value["sequence"] = 0
        return value

    def non_string_timestamp(value):
        value["timestamp"] = 123
        return value

    def malformed_timestamp(value):
        value["timestamp"] = "not-a-timestamp"
        return value

    def unsupported_severity(value):
        value["severity"] = "trace"
        return value

    def invalid_details(value):
        value["details"] = ["not", "an", "object"]
        return value

    def invalid_previous_hash(value):
        value["previous_hash"] = "not-a-digest"
        return value

    def invalid_event_hash(value):
        value["event_hash"] = "g" * 64
        return value

    return (
        remove_required_field,
        add_unknown_field,
        boolean_sequence,
        non_positive_sequence,
        non_string_timestamp,
        malformed_timestamp,
        unsupported_severity,
        invalid_details,
        invalid_previous_hash,
        invalid_event_hash,
    )


def _config_mutators() -> tuple[config_mutator, ...]:
    def unknown_profile(value):
        value["profile"] = "not_a_profile"
        return value

    def unsupported_version(value):
        value["version"] = 99
        return value

    def string_module_list(value):
        value["enabled_modules"] = "file_intel"
        return value

    def boolean_file_limit(value):
        value["file_max_size"] = True
        return value

    def invalid_severity(value):
        value["detection_min_severity"] = "urgent"
        return value

    def invalid_rule_exclusion(value):
        value["detection_excluded_rules"] = ["../outside"]
        return value

    def unsafe_excluded_path(value):
        value["ransomware_excluded_paths"] = ["../../outside"]
        return value

    def invalid_platform(value):
        value["persistence_platform"] = "unknown-os"
        return value

    def non_finite_ttl(value):
        value["c2_command_ttl_seconds"] = float("nan")
        return value

    return (
        unknown_profile,
        unsupported_version,
        string_module_list,
        boolean_file_limit,
        invalid_severity,
        invalid_rule_exclusion,
        unsafe_excluded_path,
        invalid_platform,
        non_finite_ttl,
    )


def run_parser_fuzz(seed: int = 1337, cases: int = 250) -> dict[str, Any]:
    """mutate valid inputs in memory and make sure parsers reject malformed data."""
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if isinstance(cases, bool) or not isinstance(cases, int) or not 2 <= cases <= 10_000:
        raise ValueError("cases must be between 2 and 10000")

    rng = random.Random(seed)
    event_template = build_scenario_events("clean_inventory")[0]
    config_template = rootrot_config().to_dict()
    event_count = cases // 2
    config_count = cases - event_count
    event_rejected = 0
    config_rejected = 0
    accepted_inputs: list[str] = []
    unexpected_errors: list[dict[str, Any]] = []

    event_mutators = _event_mutators()
    for index in range(event_count):
        candidate = rng.choice(event_mutators)(copy.deepcopy(event_template))
        try:
            event_record.from_mapping(candidate)
        except (TypeError, ValueError):
            event_rejected += 1
        except Exception as exc:  # keep unexpected parser failures visible in the report
            unexpected_errors.append(
                {"parser": "event", "case": index, "error_type": type(exc).__name__}
            )
        else:
            accepted_inputs.append(f"event:{index}")

    config_mutators = _config_mutators()
    for index in range(config_count):
        candidate = rng.choice(config_mutators)(copy.deepcopy(config_template))
        try:
            rootrot_config.from_mapping(candidate)
        except (TypeError, ValueError):
            config_rejected += 1
        except Exception as exc:
            unexpected_errors.append(
                {"parser": "config", "case": index, "error_type": type(exc).__name__}
            )
        else:
            accepted_inputs.append(f"config:{index}")

    return {
        "seed": seed,
        "requested_cases": cases,
        "event_cases": event_count,
        "config_cases": config_count,
        "rejected_cases": event_rejected + config_rejected,
        "accepted_invalid_inputs": accepted_inputs,
        "unexpected_errors": unexpected_errors,
        "passed": (
            event_rejected == event_count
            and config_rejected == config_count
            and not accepted_inputs
            and not unexpected_errors
        ),
        "scope": "bounded deterministic mutation fuzzing; not a replacement for coverage-guided fuzzing",
    }
