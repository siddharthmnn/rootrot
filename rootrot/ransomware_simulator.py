"""find sample files that might be targeted, without modifying them."""

from __future__ import annotations

from pathlib import Path, PureWindowsPath
from typing import Any, Iterable


class ransomware_simulator:
    """perform a bounded file-selection dry run in the demo workspace."""

    target_extensions = {".txt", ".csv", ".json", ".log", ".pdf"}

    def __init__(
        self,
        workspace: Path,
        logger: Any,
        target_extensions: Iterable[str] | None = None,
        exclude_paths: Iterable[str] = (),
        max_candidates: int = 1000,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        raw_extensions = self.target_extensions if target_extensions is None else target_extensions
        if isinstance(raw_extensions, (str, bytes)):
            raise ValueError("target_extensions must be an iterable of extensions")
        try:
            extensions = tuple(raw_extensions)
        except TypeError as exc:
            raise ValueError("target_extensions must be an iterable of extensions") from exc
        if not extensions or any(
            not isinstance(ext, str)
            or not ext.startswith(".")
            or "/" in ext
            or "\\" in ext
            for ext in extensions
        ):
            raise ValueError("target_extensions must contain file extensions such as '.txt'")
        if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
            raise ValueError("max_candidates must be a positive integer")
        if isinstance(exclude_paths, (str, bytes)):
            raise ValueError("exclude_paths must be an iterable of relative paths")

        exclusions = set()
        for raw_path in exclude_paths:
            if (
                not isinstance(raw_path, str)
                or not raw_path
                or Path(raw_path).is_absolute()
                or PureWindowsPath(raw_path).is_absolute()
                or ".." in Path(raw_path).parts
            ):
                raise ValueError("excluded paths must be safe relative paths")
            exclusions.add(Path(raw_path))

        self.logger = logger
        self.target_extensions = {ext.lower() for ext in extensions}
        self.exclude_paths = exclusions
        self.max_candidates = max_candidates

    def _is_excluded(self, relative_path: Path) -> bool:
        return any(
            relative_path == excluded or excluded in relative_path.parents
            for excluded in self.exclude_paths
        )

    def dry_run(self) -> dict[str, Any]:
        targets = []
        scanned_count = 0
        truncated = False

        for path in sorted(self.workspace.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(self.workspace):
                continue
            scanned_count += 1
            relative_path = resolved.relative_to(self.workspace)
            if self._is_excluded(relative_path) or resolved.suffix.lower() not in self.target_extensions:
                continue
            if len(targets) >= self.max_candidates:
                truncated = True
                break

            targets.append({
                "name": resolved.name,
                "path": relative_path.as_posix(),
                "size": resolved.stat().st_size,
                "extension": resolved.suffix.lower(),
                "reason": "extension matched the configured dry-run profile",
                "would_be_targeted": True,
                "encrypted": False,
                "modified": False,
            })

        self.logger.emit(
            "ransomware_simulator",
            "ransomware.dry_run",
            "warning",
            candidate_count=len(targets),
            scanned_count=scanned_count,
            files_changed=0,
            truncated=truncated,
        )
        return {
            "mode": "dry_run",
            "targets": targets,
            "target_count": len(targets),
            "scanned_count": scanned_count,
            "files_encrypted": 0,
            "files_modified": 0,
            "truncated": truncated,
        }
