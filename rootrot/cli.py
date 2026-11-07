"""small command line interface for running the rootrot lab."""

import argparse
import json
from pathlib import Path

from . import __version__
from .core.config import profile_modules, configuration_error, rootrot_config
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
        "--config",
        type=Path,
        help="load run settings from a json file",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(profile_modules),
        help="use a built-in simulation profile",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rootrot {__version__}",
    )
    args = parser.parse_args()

    if args.config and args.profile:
        parser.error("--config and --profile cannot be used together")

    try:
        if args.config:
            config = rootrot_config.from_file(args.config)
        elif args.profile:
            config = rootrot_config(profile=args.profile)
        else:
            config = rootrot_config()
    except configuration_error as exc:
        parser.error(str(exc))

    if args.command == "run":
        print(json.dumps(run_lab(config), indent=2))


if __name__ == "__main__":
    main()
