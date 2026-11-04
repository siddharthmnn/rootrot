"""connect the modules and run everything in a temporary workspace."""

from __future__ import annotations

import json
import secrets
import tempfile
from pathlib import Path
from typing import Any

from .c2_simulator import c2_agent, c2_controller
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


def run_lab() -> dict[str, Any]:
    logger = event_logger()

    # TemporaryDirectory removes the demo files when the run is finished
    with tempfile.TemporaryDirectory(prefix="rootrot_") as temp_dir:
        workspace = Path(temp_dir).resolve()
        _make_demo_files(workspace)

        scanner = file_intel(workspace, logger)
        inventory = scanner.inventory()
        persistence = persistence_simulator(logger).run()

        secret = secrets.token_bytes(32)
        controller = c2_controller(secret, logger)
        agent = c2_agent("demo-agent-01", workspace, controller, logger)

        # a few local beacons make the detection rule easy to demonstrate
        for _ in range(3):
            controller.beacon(agent.agent_id)

        controller.dispatch("status")
        controller.dispatch("inventory")
        controller.dispatch(
            "hash_file",
            {"path": "demo_files/notes.txt"},
        )
        c2_results = list(agent.poll())

        ransomware = ransomware_simulator(workspace, logger).dry_run()
        staging = staging_simulator(logger).run(b"synthetic lab data " * 80)
        findings = detection_engine(logger).analyze()

        return {
            "project": "rootrot",
            "version": "1.0.0",
            "file_inventory": inventory,
            "persistence_simulation": persistence,
            "c2_simulation": c2_results,
            "ransomware_simulation": ransomware,
            "staging_simulation": staging,
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
