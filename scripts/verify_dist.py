"""check that built rootrot distributions contain the expected files."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


_REQUIRED_PACKAGE_FILES = {
    "rootrot/__init__.py",
    "rootrot/__main__.py",
    "rootrot/cli.py",
    "rootrot/lab.py",
}
_FORBIDDEN_PARTS = {
    ".git",
    ".ruff_cache",
    ".venv",
    "__pycache__",
}


def _check_common_paths(paths: list[str], label: str) -> list[str]:
    problems = []
    for raw_path in paths:
        parts = Path(raw_path).parts
        if any(part in _FORBIDDEN_PARTS for part in parts):
            problems.append(f"{label} contains an unwanted path: {raw_path}")
        if raw_path.endswith((".pyc", ".pyo")):
            problems.append(f"{label} contains compiled python: {raw_path}")
    return problems


def verify_wheel(path: Path) -> list[str]:
    problems = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    problems.extend(_check_common_paths(names, "wheel"))

    missing = sorted(_REQUIRED_PACKAGE_FILES - set(names))
    if missing:
        problems.append(f"wheel is missing required package files: {', '.join(missing)}")
    if any(name.startswith("tests/") for name in names):
        problems.append("wheel must not include the test suite")
    if not any(name.endswith(".dist-info/METADATA") for name in names):
        problems.append("wheel is missing distribution metadata")
    return problems


def verify_sdist(path: Path) -> list[str]:
    problems = []
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
    problems.extend(_check_common_paths(names, "source distribution"))

    required_suffixes = {
        "pyproject.toml",
        "README.md",
        "LICENSE",
        *_REQUIRED_PACKAGE_FILES,
    }
    present_suffixes = {name.split("/", 1)[-1] for name in names if "/" in name}
    missing = sorted(required_suffixes - present_suffixes)
    if missing:
        problems.append("source distribution is missing required files: " + ", ".join(missing))
    return problems


def main() -> int:
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    if not directory.is_dir():
        print(f"distribution directory does not exist: {directory}", file=sys.stderr)
        return 2

    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(
            f"expected one wheel and one source distribution; found {len(wheels)} and {len(sdists)}",
            file=sys.stderr,
        )
        return 2

    problems = verify_wheel(wheels[0]) + verify_sdist(sdists[0])
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    print(f"verified wheel: {wheels[0].name}")
    print(f"verified source distribution: {sdists[0].name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
