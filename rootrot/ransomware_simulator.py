"""find sample files that ransomware might target, without encrypting them."""

from pathlib import Path
from typing import Any


class ransomware_simulator:
    target_extensions = {".txt", ".csv", ".json", ".log", ".pdf"}

    def __init__(self, workspace: Path, logger: Any) -> None:
        self.workspace = workspace.resolve()
        self.logger = logger

    def dry_run(self) -> dict[str, Any]:
        targets = []

        for path in sorted(self.workspace.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            if not path.resolve().is_relative_to(self.workspace):
                continue
            if path.suffix.lower() not in self.target_extensions:
                continue

            targets.append(
                {
                    "name": path.name,
                    "size": path.stat().st_size,
                    "would_be_targeted": True,
                    "encrypted": False,
                }
            )

        self.logger.emit(
            "ransomware_simulator",
            "ransomware.dry_run",
            "warning",
            candidate_count=len(targets),
            files_changed=0,
        )
        return {
            "mode": "dry_run",
            "targets": targets,
            "files_encrypted": 0,
        }
