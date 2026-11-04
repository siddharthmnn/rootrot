"""inspect and fingerprint files inside the lab workspace only."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any


class file_intel:
    """collect basic file details without changing the files."""

    def __init__(
        self,
        workspace: Path,
        logger: Any,
        max_file_size: int = 5_000_000,
    ) -> None:
        self.workspace = workspace.resolve()
        self.logger = logger
        self.max_file_size = max_file_size

    def safe_path(self, relative_path: str) -> Path:
        raw_candidate = self.workspace / relative_path

        # check path parts before resolving so a symlink cannot lead outside the lab
        current = raw_candidate
        while current != self.workspace and self.workspace in current.parents:
            if current.is_symlink():
                raise ValueError("symbolic links are not allowed in the lab")
            current = current.parent

        candidate = raw_candidate.resolve()
        if not candidate.is_relative_to(self.workspace):
            raise ValueError("path is outside the lab workspace")
        return candidate

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0

        counts = Counter(data)
        size = len(data)
        return -sum(
            (count / size) * math.log2(count / size)
            for count in counts.values()
        )

    def fingerprint(self, path: Path) -> dict[str, Any]:
        # only regular files under the workspace are accepted here
        resolved_path = path.resolve()
        if path.is_symlink() or not path.is_file():
            raise ValueError("expected a regular file")
        if not resolved_path.is_relative_to(self.workspace):
            raise ValueError("file is outside the lab workspace")
        if path.stat().st_size > self.max_file_size:
            raise ValueError("file is larger than the configured limit")

        data = path.read_bytes()
        result = {
            "name": path.name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": round(self.entropy(data), 4),
            "extension": path.suffix.lower(),
        }
        self.logger.emit(
            "file_intel",
            "file.inspected",
            file=path.name,
            sha256=result["sha256"],
        )
        return result

    def inventory(self) -> list[dict[str, Any]]:
        results = []

        for path in sorted(self.workspace.rglob("*")):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                results.append(self.fingerprint(path))
            except (OSError, ValueError):
                # skip files we cannot safely inspect and carry on with the rest
                continue

        self.logger.emit(
            "file_intel",
            "inventory.completed",
            file_count=len(results),
        )
        return results
