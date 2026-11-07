"""explicit registry for the simulation handlers available to a run."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .context import run_context


_name_pattern = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class simulation_definition:
    name: str
    handler: Callable[[run_context], Any]
    description: str


class simulation_registry:
    """keep simulator registration explicit and reject accidental overrides."""

    def __init__(self) -> None:
        self._definitions: dict[str, simulation_definition] = {}

    def register(
        self,
        name: str,
        handler: Callable[[run_context], Any],
        description: str = "",
    ) -> None:
        if not isinstance(name, str) or not _name_pattern.fullmatch(name):
            raise ValueError("simulation names must use lowercase letters and underscores")
        if not callable(handler):
            raise TypeError("simulation handler must be callable")
        if not isinstance(description, str):
            raise TypeError("simulation description must be a string")
        if name in self._definitions:
            raise ValueError(f"simulation '{name}' is already registered")
        self._definitions[name] = simulation_definition(name, handler, description)

    def get(self, name: str) -> simulation_definition:
        try:
            return self._definitions[name]
        except KeyError as exc:
            raise KeyError(f"simulation '{name}' is not registered") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._definitions)

    def describe(self) -> list[dict[str, str]]:
        return [
            {"name": item.name, "description": item.description}
            for item in self._definitions.values()
        ]
