"""small command line interface for running and exporting rootrot reports."""

import argparse
from pathlib import Path

from . import __version__
from .core.config import profile_modules, configuration_error, rootrot_config
from .lab import run_lab
from .reporting.html_report import write_html_report
from .reporting.json_report import render_json_report, write_json_report
from .telemetry.jsonl import export_jsonl


def _validate_output_paths(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    paths = [
        path for path in (args.events_jsonl, args.report_json, args.report_html)
        if path is not None
    ]
    resolved = [path.expanduser().resolve(strict=False) for path in paths]
    if len(set(resolved)) != len(resolved):
        parser.error("event, json, and html outputs must use different paths")

    for path in paths:
        expanded = path.expanduser()
        if not expanded.parent.exists() or not expanded.parent.is_dir():
            parser.error(f"output directory does not exist: {expanded.parent}")
        if expanded.exists() and expanded.is_dir():
            parser.error(f"output path is a directory: {expanded}")
        if expanded.exists() and not args.overwrite:
            parser.error(f"output already exists: {expanded}; pass --overwrite to replace it")


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
        "--events-jsonl",
        type=Path,
        help="write the verified event stream as newline-delimited json",
    )
    parser.add_argument(
        "--report-json",
        type=Path,
        help="write the complete run report as json",
    )
    parser.add_argument(
        "--report-html",
        type=Path,
        help="write a self-contained html report",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace output files that already exist",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rootrot {__version__}",
    )
    args = parser.parse_args()

    if args.config and args.profile:
        parser.error("--config and --profile cannot be used together")
    _validate_output_paths(parser, args)

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
        report = run_lab(config)
        try:
            if args.events_jsonl:
                export_jsonl(
                    report.get("events", []),
                    args.events_jsonl.expanduser(),
                    overwrite=args.overwrite,
                )
            if args.report_json:
                write_json_report(
                    report,
                    args.report_json.expanduser(),
                    overwrite=args.overwrite,
                )
            if args.report_html:
                write_html_report(
                    report,
                    args.report_html.expanduser(),
                    overwrite=args.overwrite,
                )
            print(render_json_report(report), end="")
        except (OSError, TypeError, ValueError) as exc:
            parser.error(f"could not write requested output: {exc}")


if __name__ == "__main__":
    main()
