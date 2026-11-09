"""deterministic validation tools for rootrot's detection and telemetry layers."""

from .benchmark import run_detection_benchmark
from .fuzz import run_parser_fuzz
from .metrics import evaluate_detection_scenarios
from .mutations import run_integrity_mutation_suite, run_sequence_mutation_suite
from .replay import replay_scenario
from .scenarios import build_scenario_events, get_scenario, list_scenarios
from .suite import run_validation_suite

__all__ = [
    "build_scenario_events",
    "evaluate_detection_scenarios",
    "get_scenario",
    "list_scenarios",
    "replay_scenario",
    "run_detection_benchmark",
    "run_integrity_mutation_suite",
    "run_parser_fuzz",
    "run_sequence_mutation_suite",
    "run_validation_suite",
]
