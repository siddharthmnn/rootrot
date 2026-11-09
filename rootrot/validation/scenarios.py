"""small, deterministic event sequences with explicit expected detections."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from ..events import event_logger


@dataclass(frozen=True, slots=True)
class scenario_step:
    source: str
    action: str
    severity: str = "info"
    details: Mapping[str, Any] = field(default_factory=dict)
    delay_ms: int = 250


@dataclass(frozen=True, slots=True)
class scenario_definition:
    scenario_id: str
    description: str
    steps: tuple[scenario_step, ...]
    expected_rule_ids: tuple[str, ...]


class _scenario_clock:
    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def advance(self, milliseconds: int) -> None:
        self.current += timedelta(milliseconds=milliseconds)

    def __call__(self) -> str:
        return self.current.isoformat()


_scenarios = (
    scenario_definition(
        scenario_id="clean_inventory",
        description="routine file inventory with no suspicious behaviour",
        steps=(
            scenario_step(
                "file_intel",
                "file.inspected",
                details={"file": "notes.txt", "classification": "text"},
            ),
        ),
        expected_rule_ids=(),
    ),
    scenario_definition(
        scenario_id="benign_admin_noise",
        description="ordinary inventory and one isolated local agent heartbeat",
        steps=(
            scenario_step("file_intel", "file.inspected", details={"file": "report.csv"}),
            scenario_step("inventory", "inventory.completed", details={"files": 12}),
            scenario_step("c2", "c2.beacon", details={"agent_id": "demo-agent"}),
        ),
        expected_rule_ids=(),
    ),
    scenario_definition(
        scenario_id="persistence_preview",
        description="a simulator records a hypothetical persistence location",
        steps=(
            scenario_step(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                {"technique": "scheduled_task", "performed": False},
            ),
        ),
        expected_rule_ids=("rr.persistence.001",),
    ),
    scenario_definition(
        scenario_id="in_memory_staging",
        description="synthetic data is divided into in-memory chunks",
        steps=(
            scenario_step(
                "staging_simulator",
                "data.staged_in_memory",
                "warning",
                {"chunk_count": 4, "transmitted": False},
            ),
        ),
        expected_rule_ids=("rr.staging.001",),
    ),
    scenario_definition(
        scenario_id="repeated_heartbeats",
        description="the same simulated agent emits repeated local heartbeat events",
        steps=tuple(
            scenario_step(
                "c2",
                "c2.beacon",
                details={"agent_id": "demo-agent", "heartbeat": index},
            )
            for index in range(3)
        ),
        expected_rule_ids=("rr.c2.001",),
    ),
    scenario_definition(
        scenario_id="multi_stage_chain",
        description="file activity, persistence, local tasking, staging and targeting preview",
        steps=(
            scenario_step("file_intel", "file.inspected", details={"file": "notes.txt"}),
            scenario_step(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                {"technique": "scheduled_task", "performed": False},
            ),
            scenario_step("c2", "c2.command_queued", details={"command": "inventory"}),
            scenario_step(
                "staging_simulator",
                "data.staged_in_memory",
                "warning",
                {"chunk_count": 4, "transmitted": False},
            ),
            scenario_step(
                "ransomware_simulator",
                "ransomware.dry_run",
                "warning",
                {"candidate_count": 2, "files_changed": 0},
            ),
        ),
        expected_rule_ids=(
            "rr.persistence.001",
            "rr.staging.001",
            "rr.ransomware.001",
            "rr.sequence.001",
        ),
    ),
    scenario_definition(
        scenario_id="command_rejections",
        description="the local task queue rejects a bad signature and a replayed command",
        steps=(
            scenario_step("c2", "c2.bad_signature", "alert", {"command_id": "task-01"}),
            scenario_step("c2", "c2.command_replayed", "alert", {"command_id": "task-02"}),
        ),
        expected_rule_ids=("rr.c2.002", "rr.c2.003"),
    ),
    scenario_definition(
        scenario_id="extension_mismatch",
        description="file signature telemetry disagrees with a synthetic file extension",
        steps=(
            scenario_step(
                "file_intel",
                "file.extension_mismatch",
                "warning",
                {"file": "invoice.txt", "extension": ".txt", "detected_type": "pdf"},
            ),
        ),
        expected_rule_ids=("rr.file.001",),
    ),
    scenario_definition(
        scenario_id="slow_multi_stage",
        description="three behaviour categories occur, but outside the correlation window",
        steps=(
            scenario_step("file_intel", "file.inspected", details={"file": "notes.txt"}),
            scenario_step(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                {"technique": "scheduled_task", "performed": False},
                delay_ms=90_000,
            ),
            scenario_step(
                "c2",
                "c2.command_queued",
                details={"command": "inventory"},
                delay_ms=90_000,
            ),
        ),
        expected_rule_ids=("rr.persistence.001",),
    ),
    scenario_definition(
        scenario_id="minimal_sequence",
        description="the smallest three-category sequence that should correlate",
        steps=(
            scenario_step("file_intel", "file.inspected", details={"file": "notes.txt"}),
            scenario_step(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                {"technique": "scheduled_task", "performed": False},
            ),
            scenario_step("c2", "c2.command_queued", details={"command": "inventory"}),
        ),
        expected_rule_ids=("rr.persistence.001", "rr.sequence.001"),
    ),
)

_scenario_index = {item.scenario_id: item for item in _scenarios}


def list_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": item.scenario_id,
            "description": item.description,
            "event_count": len(item.steps),
            "expected_rule_ids": list(item.expected_rule_ids),
        }
        for item in _scenarios
    ]


def get_scenario(scenario_id: str) -> scenario_definition:
    if not isinstance(scenario_id, str) or scenario_id not in _scenario_index:
        available = ", ".join(_scenario_index)
        raise ValueError(f"unknown scenario {scenario_id!r}; available scenarios: {available}")
    return _scenario_index[scenario_id]


def build_scenario_events(scenario_id: str) -> list[dict[str, Any]]:
    """build an identical, hash-valid event chain every time the scenario is run."""
    definition = get_scenario(scenario_id)
    clock = _scenario_clock()
    logger = event_logger(run_id=f"validation-{scenario_id}", clock=clock)

    for step in definition.steps:
        if isinstance(step.delay_ms, bool) or not isinstance(step.delay_ms, int) or step.delay_ms < 0:
            raise ValueError("scenario step delay_ms must be a non-negative integer")
        clock.advance(step.delay_ms)
        logger.emit(
            step.source,
            step.action,
            step.severity,
            **dict(step.details),
        )

    if not logger.verify_integrity():
        raise RuntimeError(f"scenario {scenario_id!r} generated an invalid event chain")
    return [dict(event) for event in logger.events]
