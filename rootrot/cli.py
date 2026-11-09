"""small command line interface for running and validating rootrot."""

import argparse
from pathlib import Path

from . import __version__
from .core.config import profile_modules, configuration_error, rootrot_config
from .lab import run_lab
from .reporting.html_report import write_html_report
from .reporting.json_report import render_json_report, write_json_report
from .telemetry.jsonl import export_jsonl
from .validation import (
    list_scenarios,
    replay_scenario,
    run_detection_benchmark,
    run_validation_suite,
)


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


def _parse_benchmark_sizes(parser: argparse.ArgumentParser, value: str) -> tuple[int, ...]:
    try:
        sizes = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError:
        parser.error("--sizes must be comma-separated positive integers")
    if not sizes:
        parser.error("--sizes must contain at least one size")
    return sizes


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rootrot",
        description="run the isolated malware-behaviour simulation and validation lab",
    )
    parser.add_argument(
        "command",
        choices={"run", "validate", "replay", "benchmark"},
        help="run the lab, validate detection, replay a scenario, or benchmark the pipeline",
    )
    parser.add_argument("--config", type=Path, help="load run settings from a json file")
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
    parser.add_argument("--report-json", type=Path, help="write the complete run report as json")
    parser.add_argument("--report-html", type=Path, help="write a self-contained html report")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace output files that already exist",
    )
    parser.add_argument(
        "--scenario",
        help="scenario id to replay; use 'rootrot validate' to list the available scenarios",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=3,
        help="number of deterministic replay repetitions (default: 3)",
    )
    parser.add_argument("--seed", type=int, default=1337, help="seed for parser mutation fuzzing")
    parser.add_argument(
        "--fuzz-cases",
        type=int,
        default=250,
        help="number of parser mutation cases (default: 250)",
    )
    parser.add_argument(
        "--sizes",
        default="100,1000,10000",
        help="comma-separated event counts for the benchmark",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="measurement iterations per benchmark size (default: 3)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"rootrot {__version__}",
    )
    args = parser.parse_args()

    run_only_options = (
        args.config,
        args.profile,
        args.events_jsonl,
        args.report_json,
        args.report_html,
    )
    if args.command != "run" and any(value is not None for value in run_only_options):
        parser.error("--config, --profile and report output options are only valid with 'run'")
    if args.command != "run" and args.overwrite:
        parser.error("--overwrite is only valid with 'run'")
    if args.command != "replay" and args.scenario is not None:
        parser.error("--scenario is only valid with 'replay'")

    if args.command == "run":
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
        return

    if args.command == "validate":
        report = run_validation_suite(seed=args.seed, fuzz_cases=args.fuzz_cases)
    elif args.command == "replay":
        available = {item["scenario_id"] for item in list_scenarios()}
        if args.scenario not in available:
            parser.error(
                "--scenario must be one of: " + ", ".join(sorted(available))
            )
        try:
            report = replay_scenario(args.scenario, repetitions=args.repeat)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        sizes = _parse_benchmark_sizes(parser, args.sizes)
        try:
            report = run_detection_benchmark(sizes=sizes, iterations=args.iterations)
        except ValueError as exc:
            parser.error(str(exc))

    print(render_json_report(report), end="")
    if not report.get("passed", report.get("deterministic", True)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
