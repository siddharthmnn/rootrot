"""run selected simulations in a predictable order and record their outcomes."""

from __future__ import annotations

from time import perf_counter
from typing import Any

from .context import run_context
from .registry import simulation_registry
from .schemas import simulation_result, utc_now


class simulation_error(RuntimeError):
    """wrap a failed module with its name while preserving the original cause."""

    def __init__(self, module: str) -> None:
        super().__init__(f"simulation '{module}' failed")
        self.module = module


class simulation_orchestrator:
    """execute configured handlers and keep failures visible to the caller."""

    def __init__(self, context: run_context, registry: simulation_registry) -> None:
        self.context = context
        self.registry = registry

    def run(self) -> dict[str, simulation_result]:
        selected = self.context.config.enabled_modules or ()
        available = set(self.registry.names())
        missing = [name for name in selected if name not in available]
        if missing:
            raise ValueError(
                f"configured simulations are not registered: {', '.join(missing)}"
            )

        results: dict[str, simulation_result] = {}
        for name in selected:
            definition = self.registry.get(name)
            started_at = utc_now()
            started_clock = perf_counter()
            self.context.logger.emit(
                "orchestrator",
                "simulation.started",
                module=name,
            )

            try:
                output: Any = definition.handler(self.context)
            except Exception as exc:
                duration_ms = round((perf_counter() - started_clock) * 1000, 3)
                self.context.logger.emit(
                    "orchestrator",
                    "simulation.failed",
                    "error",
                    module=name,
                    error_type=type(exc).__name__,
                    duration_ms=duration_ms,
                )
                raise simulation_error(name) from exc

            completed_at = utc_now()
            duration_ms = round((perf_counter() - started_clock) * 1000, 3)
            result = simulation_result(
                module=name,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                output=output,
            )
            results[name] = result
            self.context.logger.emit(
                "orchestrator",
                "simulation.completed",
                module=name,
                duration_ms=duration_ms,
            )

        return results
