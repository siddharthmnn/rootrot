"""load and validate settings for a rootrot run."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


_module_name = re.compile(r"^[a-z][a-z0-9_]*$")
profile_modules = {
    "basic": ("file_intel", "persistence", "ransomware"),
    "file_analysis": ("file_intel",),
    "multi_stage": ("file_intel", "persistence", "c2", "ransomware", "staging"),
}
config_version = 1


class configuration_error(ValueError):
    """raised when a run configuration is invalid."""


@dataclass(frozen=True, slots=True)
class rootrot_config:
    """validated settings shared by the lab and its simulation modules."""

    profile: str = "multi_stage"
    enabled_modules: tuple[str, ...] | None = None
    file_max_size: int = 5_000_000
    staging_chunk_size: int = 256
    beacon_count: int = 3
    detection_enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or self.profile not in (*profile_modules, "custom"):
            raise configuration_error(
                f"unknown profile {self.profile!r}. available profiles: "
                f"{', '.join((*profile_modules, 'custom'))}"
            )

        modules = self.enabled_modules
        if modules is None:
            if self.profile == "custom":
                raise configuration_error(
                    "a custom profile needs an enabled_modules list"
                )
            modules = profile_modules[self.profile]
        else:
            if isinstance(modules, (str, bytes)):
                raise configuration_error("enabled_modules must be a list of names")
            modules = tuple(modules)
            if any(not isinstance(name, str) or not _module_name.fullmatch(name) for name in modules):
                raise configuration_error(
                    "simulation names must use lowercase letters, numbers, and underscores"
                )
            if len(set(modules)) != len(modules):
                raise configuration_error("enabled_modules contains duplicates")
            if self.profile != "custom" and modules != profile_modules[self.profile]:
                object.__setattr__(self, "profile", "custom")

        object.__setattr__(self, "enabled_modules", tuple(modules))

        self._validate_positive_int("file_max_size", self.file_max_size, 100_000_000)
        self._validate_positive_int("staging_chunk_size", self.staging_chunk_size, 1_048_576)
        self._validate_positive_int("beacon_count", self.beacon_count, 100)

        if not isinstance(self.detection_enabled, bool):
            raise configuration_error("detection_enabled must be a boolean")

    @staticmethod
    def _validate_positive_int(name: str, value: Any, maximum: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise configuration_error(f"{name} must be an integer")
        if value < 1 or value > maximum:
            raise configuration_error(f"{name} must be between 1 and {maximum}")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "rootrot_config":
        if not isinstance(values, Mapping):
            raise configuration_error("configuration must be a json object")
        if any(not isinstance(key, str) for key in values):
            raise configuration_error("configuration keys must be strings")

        allowed = {
            "version",
            "profile",
            "enabled_modules",
            "file_max_size",
            "staging_chunk_size",
            "beacon_count",
            "detection_enabled",
        }
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise configuration_error(
                f"unknown configuration keys: {', '.join(unknown)}"
            )

        version = values.get("version", config_version)
        if isinstance(version, bool) or not isinstance(version, int) or version != config_version:
            raise configuration_error(
                f"unsupported configuration version: {version!r}"
            )

        raw_modules = values.get("enabled_modules")
        if raw_modules is not None and not isinstance(raw_modules, (list, tuple)):
            raise configuration_error("enabled_modules must be a list of names")

        try:
            return cls(
                profile=values.get("profile", "multi_stage"),
                enabled_modules=(tuple(raw_modules) if raw_modules is not None else None),
                file_max_size=values.get("file_max_size", 5_000_000),
                staging_chunk_size=values.get("staging_chunk_size", 256),
                beacon_count=values.get("beacon_count", 3),
                detection_enabled=values.get("detection_enabled", True),
            )
        except TypeError as exc:
            raise configuration_error("configuration contains an invalid value") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> "rootrot_config":
        config_path = Path(path)
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise configuration_error(f"could not read config file: {config_path}") from exc
        except json.JSONDecodeError as exc:
            raise configuration_error(
                f"invalid json in config file at line {exc.lineno}, column {exc.colno}"
            ) from exc
        return cls.from_mapping(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": config_version,
            "profile": self.profile,
            "enabled_modules": list(self.enabled_modules or ()),
            "file_max_size": self.file_max_size,
            "staging_chunk_size": self.staging_chunk_size,
            "beacon_count": self.beacon_count,
            "detection_enabled": self.detection_enabled,
        }
