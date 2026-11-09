"""shared atomic output helper for report writers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text(
    destination: str | Path,
    content: str,
    *,
    overwrite: bool = False,
) -> dict[str, object]:
    path = Path(destination)
    if path.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {path}")
    if not path.parent.exists() or not path.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {path.parent}")
    if path.exists() and path.is_dir():
        raise IsADirectoryError(f"output path is a directory: {path}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(f"output already exists: {path}")
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    return {
        "path": str(path),
        "bytes_written": path.stat().st_size,
    }
