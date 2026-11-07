"""shared state for one isolated rootrot execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..events import event_logger
from .config import rootrot_config


@dataclass(slots=True)
class run_context:
    """pass the same config, workspace, and event logger to every module."""

    run_id: str
    config: rootrot_config
    logger: event_logger
    workspace: Path
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        workspace: str | Path,
        config: rootrot_config | None = None,
        logger: event_logger | None = None,
    ) -> "run_context":
        workspace_path = Path(workspace).resolve(strict=True)
        if not workspace_path.is_dir():
            raise ValueError("run workspace must be a directory")

        active_logger = logger or event_logger()
        return cls(
            run_id=active_logger.run_id,
            config=config or rootrot_config(),
            logger=active_logger,
            workspace=workspace_path,
        )
