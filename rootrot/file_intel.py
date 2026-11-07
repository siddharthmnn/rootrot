"""inspect and fingerprint files inside the lab workspace only."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any


class file_intel:
    """collect file details without loading whole files into memory."""

    _signatures = (
        (b"%PDF-", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"PK\x03\x04", "zip"),
        (b"\x1f\x8b", "gzip"),
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
        (b"SQLite format 3\x00", "sqlite"),
    )
    _compatible_extensions = {
        "pdf": {".pdf"}, "png": {".png"}, "jpeg": {".jpg", ".jpeg"},
        "gif": {".gif"}, "zip": {".zip", ".docx", ".xlsx", ".pptx"},
        "gzip": {".gz"}, "elf": {".elf", ""}, "pe": {".exe", ".dll", ".sys"},
        "sqlite": {".db", ".sqlite", ".sqlite3"}, "json": {".json"},
        "text": {".txt", ".csv", ".log", ".md", ".ini", ".cfg", ".json"},
        "empty": {""},
    }

    def __init__(
        self,
        workspace: Path,
        logger: Any,
        max_file_size: int = 5_000_000,
        chunk_size: int = 64 * 1024,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        if isinstance(max_file_size, bool) or not isinstance(max_file_size, int) or max_file_size < 1:
            raise ValueError("max_file_size must be a positive integer")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1024:
            raise ValueError("chunk_size must be at least 1024 bytes")
        self.logger = logger
        self.max_file_size = max_file_size
        self.chunk_size = chunk_size

    def safe_path(self, relative_path: str) -> Path:
        if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
            raise ValueError("a valid relative path is required")
        candidate_path = Path(relative_path)
        if candidate_path.is_absolute() or PureWindowsPath(relative_path).is_absolute():
            raise ValueError("absolute paths are not allowed")
        if ".." in candidate_path.parts or ".." in PureWindowsPath(relative_path).parts:
            raise ValueError("parent directory references are not allowed")

        current = self.workspace
        for part in candidate_path.parts:
            if part in {"", "."}:
                continue
            current = current / part
            if current.is_symlink():
                raise ValueError("symbolic links are not allowed in the lab")

        resolved = current.resolve()
        if not resolved.is_relative_to(self.workspace):
            raise ValueError("path is outside the lab workspace")
        return resolved

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

    @classmethod
    def _detect_type(cls, prefix: bytes) -> str:
        for signature, file_type in cls._signatures:
            if prefix.startswith(signature):
                return file_type
        if not prefix:
            return "empty"
        if b"\x00" in prefix:
            return "unknown"
        try:
            decoded = prefix.decode("utf-8")
        except UnicodeDecodeError:
            return "unknown"
        stripped = decoded.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                json.loads(decoded)
                return "json"
            except json.JSONDecodeError:
                pass
        return "text"

    def fingerprint(self, path: Path) -> dict[str, Any]:
        raw_path = Path(path)
        if raw_path.is_absolute():
            try:
                relative_parts = raw_path.relative_to(self.workspace).parts
            except ValueError as exc:
                raise ValueError("file is outside the lab workspace") from exc
            if ".." in relative_parts:
                raise ValueError("parent directory references are not allowed")
            candidate = raw_path
            current = self.workspace
            for part in relative_parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError("symbolic links are not allowed in the lab")
        else:
            candidate = self.safe_path(str(raw_path))

        resolved_path = candidate.resolve(strict=True)
        if not resolved_path.is_relative_to(self.workspace):
            raise ValueError("file is outside the lab workspace")

        initial_stat = resolved_path.stat()
        if not stat.S_ISREG(initial_stat.st_mode):
            raise ValueError("expected a regular file")
        if initial_stat.st_size > self.max_file_size:
            raise ValueError("file is larger than the configured limit")

        digest = hashlib.sha256()
        byte_counts: Counter[int] = Counter()
        prefix = bytearray()
        total_size = 0
        with resolved_path.open("rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_stat.st_mode):
                raise ValueError("expected a regular file")
            while chunk := handle.read(self.chunk_size):
                total_size += len(chunk)
                if total_size > self.max_file_size:
                    raise ValueError("file grew beyond the configured limit")
                digest.update(chunk)
                byte_counts.update(chunk)
                if len(prefix) < 8192:
                    prefix.extend(chunk[:8192 - len(prefix)])

        final_stat = resolved_path.stat()
        if total_size != initial_stat.st_size or final_stat.st_mtime_ns != initial_stat.st_mtime_ns:
            raise OSError("file changed while it was being inspected")

        file_type = self._detect_type(bytes(prefix))
        extension = resolved_path.suffix.lower()
        compatible = self._compatible_extensions.get(file_type)
        extension_mismatch = compatible is not None and extension not in compatible
        entropy = 0.0
        if total_size:
            entropy = -sum(
                (count / total_size) * math.log2(count / total_size)
                for count in byte_counts.values()
            )
        modified_at = datetime.fromtimestamp(final_stat.st_mtime, timezone.utc).isoformat()
        result = {
            "name": resolved_path.name,
            "relative_path": resolved_path.relative_to(self.workspace).as_posix(),
            "size": total_size,
            "sha256": digest.hexdigest(),
            "entropy": round(entropy, 4),
            "extension": extension,
            "file_type": file_type,
            "extension_mismatch": extension_mismatch,
            "modified_at": modified_at,
            "mtime_ns": final_stat.st_mtime_ns,
        }
        self.logger.emit(
            "file_intel",
            "file.inspected",
            file=resolved_path.name,
            sha256=result["sha256"],
            file_type=file_type,
        )
        if extension_mismatch:
            self.logger.emit(
                "file_intel",
                "file.extension_mismatch",
                "warning",
                file=resolved_path.name,
                extension=extension,
                detected_type=file_type,
            )
        return result

    def inventory(self) -> list[dict[str, Any]]:
        results = []
        skipped = 0
        for path in sorted(self.workspace.rglob("*")):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                results.append(self.fingerprint(path))
            except (OSError, ValueError):
                skipped += 1
        self.logger.emit(
            "file_intel",
            "inventory.completed",
            file_count=len(results),
            skipped_count=skipped,
        )
        return results
