"""connect the modules and run everything in a temporary workspace."""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .c2_simulator import c2_agent, c2_controller
from .core.config import rootrot_config
from .core.context import run_context
from .core.orchestrator import simulation_orchestrator
from .core.registry import simulation_registry
from .detection import detection_engine
from .events import event_logger
from .file_intel import file_intel
from .persistence_simulator import persistence_simulator
from .ransomware_simulator import ransomware_simulator
from .staging_simulator import staging_simulator


def _make_demo_files(workspace: Path) -> None:
    demo = workspace / "demo_files"
    demo.mkdir(parents=True)

    (demo / "notes.txt").write_text(
        "synthetic malware research notes\nno personal data here\n",
        encoding="utf-8",
    )
    (demo / "settings.json").write_text(
        json.dumps(
            {"environment": "isolated_lab", "agent": "demo_agent"},
            indent=2,
        ),
        encoding="utf-8",
    )
    (demo / "sample.csv").write_text(
        "id,label,value\n1,demo,123\n2,test,456\n",
        encoding="utf-8",
    )


def _build_registry() -> simulation_registry:
    registry = simulation_registry()

    def run_file_intel(context: run_context) -> list[dict[str, Any]]:
        scanner = file_intel(
            context.workspace,
            context.logger,
            max_file_size=context.config.file_max_size,
        )
        return scanner.inventory()

    def run_persistence(context: run_context) -> list[dict[str, Any]]:
        return persistence_simulator(context.logger).run()

    def run_c2(context: run_context) -> list[dict[str, Any]]:
        secret = secrets.token_bytes(32)
        controller = c2_controller(secret, context.logger)
        agent = c2_agent(
            "demo-agent-01",
            context.workspace,
            controller,
            context.logger,
        )

        # these are local log events, not network heartbeats
        for _ in range(context.config.beacon_count):
            controller.beacon(agent.agent_id)

        controller.dispatch("status")
        controller.dispatch("inventory")
        controller.dispatch(
            "hash_file",
            {"path": "demo_files/notes.txt"},
        )
        return list(agent.poll())

    def run_ransomware(context: run_context) -> dict[str, Any]:
        return ransomware_simulator(context.workspace, context.logger).dry_run()

    def run_staging(context: run_context) -> dict[str, Any]:
        simulator = staging_simulator(
            context.logger,
            chunk_size=context.config.staging_chunk_size,
        )
        return simulator.run(b"synthetic lab data " * 80)

    registry.register("file_intel", run_file_intel, "inspect synthetic files in the temporary workspace")
    registry.register("persistence", run_persistence, "record hypothetical persistence actions")
    registry.register("c2", run_c2, "run authenticated tasks through an in-memory queue")
    registry.register("ransomware", run_ransomware, "identify file candidates without changing them")
    registry.register("staging", run_staging, "chunk synthetic bytes in memory")
    return registry


def run_lab(config: rootrot_config | None = None) -> dict[str, Any]:
    active_config = config or rootrot_config()
    logger = event_logger()

    with tempfile.TemporaryDirectory(prefix="rootrot_") as temp_dir:
        workspace = Path(temp_dir).resolve()
        _make_demo_files(workspace)
        context = run_context.create(workspace, active_config, logger)

        # the registry keeps module wiring out of the run loop
        outcomes = simulation_orchestrator(context, _build_registry()).run()
        outputs = {name: result.output for name, result in outcomes.items()}
        findings = (
            detection_engine(logger).analyze()
            if active_config.detection_enabled
            else []
        )

        report: dict[str, Any] = {
            "project": "rootrot",
            "version": __version__,
            "run_id": context.run_id,
            "profile": active_config.profile,
            "enabled_modules": list(active_config.enabled_modules or ()),
            "detections": findings,
            "event_count": len(logger.events),
            "event_log_integrity": logger.verify_integrity(),
            "safety": {
                "temporary_workspace_only": True,
                "network_connections": False,
                "system_persistence": False,
                "shell_commands": False,
                "files_encrypted": False,
                "data_transmitted": False,
            },
        }

        # keep the original report keys so existing users and tests keep working
        output_keys = {
            "file_intel": "file_inventory",
            "persistence": "persistence_simulation",
            "c2": "c2_simulation",
            "ransomware": "ransomware_simulation",
            "staging": "staging_simulation",
        }
        for module, report_key in output_keys.items():
            if module in outputs:
                report[report_key] = outputs[module]

        return report
