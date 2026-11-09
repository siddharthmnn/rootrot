"""repeatable microbenchmarks for detection, event integrity, and event filtering."""

from __future__ import annotations

import platform
import statistics
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from ..detection import detection_engine
from ..events import event_logger
from ..telemetry.integrity import verify_event_chain
from ..telemetry.query import filter_events


class _benchmark_clock:
    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> str:
        value = self.current.isoformat()
        self.current += timedelta(milliseconds=1)
        return value


def _measure(operation: Callable[[], Any], iterations: int) -> dict[str, float]:
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1000)

    return {
        "min_ms": round(min(samples), 3),
        "median_ms": round(statistics.median(samples), 3),
        "max_ms": round(max(samples), 3),
    }


def _build_benchmark_events(count: int) -> list[dict[str, Any]]:
    logger = event_logger(
        run_id=f"benchmark-{count}",
        clock=_benchmark_clock(),
    )
    actions = (
        ("file_intel", "file.inspected", "info"),
        ("persistence_simulator", "persistence.would_write", "warning"),
        ("c2", "c2.command_queued", "info"),
        ("staging_simulator", "data.staged_in_memory", "warning"),
        ("ransomware_simulator", "ransomware.dry_run", "warning"),
        ("c2", "c2.beacon", "info"),
    )
    for index in range(count):
        source, action, severity = actions[index % len(actions)]
        logger.emit(source, action, severity, sample=index)
    return [dict(event) for event in logger.events]


def run_detection_benchmark(
    sizes: Iterable[int] = (100, 1000, 10_000),
    iterations: int = 3,
) -> dict[str, Any]:
    if isinstance(sizes, (str, bytes)):
        raise ValueError("sizes must be an iterable of positive integers")
    try:
        selected_sizes = tuple(sizes)
    except TypeError as exc:
        raise ValueError("sizes must be an iterable of positive integers") from exc
    if not selected_sizes:
        raise ValueError("at least one benchmark size is required")
    if any(
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= 100_000
        for size in selected_sizes
    ):
        raise ValueError("each size must be an integer between 1 and 100000")
    if len(set(selected_sizes)) != len(selected_sizes):
        raise ValueError("benchmark sizes must be unique")
    if (
        isinstance(iterations, bool)
        or not isinstance(iterations, int)
        or not 1 <= iterations <= 20
    ):
        raise ValueError("iterations must be between 1 and 20")

    results = []
    for size in selected_sizes:
        events = _build_benchmark_events(size)
        observer = event_logger(run_id=f"benchmark-observer-{size}")
        detector = detection_engine(observer)

        analysis = _measure(lambda: detector.analyze(events), iterations)
        integrity = _measure(lambda: verify_event_chain(events), iterations)
        filtering = _measure(
            lambda: filter_events(events, action="data.staged_in_memory"),
            iterations,
        )
        median_seconds = analysis["median_ms"] / 1000
        results.append(
            {
                "event_count": size,
                "iterations": iterations,
                "detection": {
                    **analysis,
                    "events_per_second": (
                        round(size / median_seconds, 2) if median_seconds else None
                    ),
                },
                "integrity_verification": integrity,
                "event_filtering": filtering,
            }
        )

    return {
        "benchmark": "rootrot_detection_pipeline",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "results": results,
        "notes": [
            "event generation is excluded from the timed operations",
            "timings are environment-specific and should be compared on the same runner",
            "this benchmark is diagnostic and does not impose a flaky wall-clock CI threshold",
        ],
    }
