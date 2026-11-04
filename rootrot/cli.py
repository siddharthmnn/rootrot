"""small command line interface for running the rootrot lab."""

import argparse
import json

from . import __version__
from .lab import run_lab


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rootrot",
        description="run the isolated malware-behaviour simulation lab",
    )
    parser.add_argument(
        "command",
        choices={"run"},
        help="run the demo and print its json report",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rootrot {__version__}",
    )
    args = parser.parse_args()

    if args.command == "run":
        print(json.dumps(run_lab(), indent=2))


if __name__ == "__main__":
    main()
