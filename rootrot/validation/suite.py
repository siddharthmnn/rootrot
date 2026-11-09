"""run the deterministic validation checks used by the CLI and CI."""

from __future__ import annotations

from typing import Any

from .fuzz import run_parser_fuzz
from .metrics import evaluate_detection_scenarios
from .mutations import run_integrity_mutation_suite, run_sequence_mutation_suite


def run_validation_suite(seed: int = 1337, fuzz_cases: int = 250) -> dict[str, Any]:
    detection = evaluate_detection_scenarios()
    integrity_mutations = run_integrity_mutation_suite()
    sequence_mutations = run_sequence_mutation_suite()
    parser_fuzz = run_parser_fuzz(seed=seed, cases=fuzz_cases)

    sections = {
        "detection_scenarios": detection["passed"],
        "integrity_mutations": integrity_mutations["passed"],
        "sequence_mutations": sequence_mutations["passed"],
        "parser_fuzz": parser_fuzz["passed"],
    }
    return {
        "validation": "rootrot_synthetic_validation",
        "seed": seed,
        "fuzz_cases": fuzz_cases,
        "sections": {
            "detection_scenarios": detection,
            "integrity_mutations": integrity_mutations,
            "sequence_mutations": sequence_mutations,
            "parser_fuzz": parser_fuzz,
        },
        "passed": all(sections.values()),
        "failed_sections": [name for name, passed in sections.items() if not passed],
    }
