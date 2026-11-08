"""load and validate settings for a rootrot run."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping


_module_name = re.compile(r"^[a-z][a-z0-9_]*$")
_rule_name = re.compile(r"^[a-z0-9_.-]+$")
profile_modules = {
    "basic": ("file_intel", "persistence", "ransomware"),
    "file_analysis": ("file_intel",),
    "multi_stage": ("file_intel", "persistence", "c2", "ransomware", "staging"),
}
config_version = 1
_default_extensions = (".txt", ".csv", ".json", ".log", ".pdf")


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
    max_staging_bytes: int = 1_000_000
    persistence_platform: str = "cross_platform"
    c2_command_ttl_seconds: float = 60.0
    c2_queue_limit: int = 64
    ransomware_target_extensions: tuple[str, ...] = _default_extensions
    ransomware_excluded_paths: tuple[str, ...] = ()
    detection_min_severity: str = "low"
    detection_excluded_rules: tuple[str, ...] = ()
    detection_correlation_window_seconds: int = 120

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or self.profile not in (*profile_modules, "custom"):
            raise configuration_error(
                f"unknown profile {self.profile!r}. available profiles: "
                f"{', '.join((*profile_modules, 'custom'))}"
            )

        modules = self.enabled_modules
        if modules is None:
            if self.profile == "custom":
                raise configuration_error("a custom profile needs an enabled_modules list")
            modules = profile_modules[self.profile]
        else:
            if isinstance(modules, (str, bytes)):
                raise configuration_error("enabled_modules must be a list of names")
            try:
                modules = tuple(modules)
            except TypeError as exc:
                raise configuration_error("enabled_modules must be a list of names") from exc
            if any(not isinstance(name, str) or not _module_name.fullmatch(name) for name in modules):
                raise configuration_error("simulation names must use lowercase letters, numbers, and underscores")
            if len(set(modules)) != len(modules):
                raise configuration_error("enabled_modules contains duplicates")
            if self.profile != "custom" and modules != profile_modules[self.profile]:
                object.__setattr__(self, "profile", "custom")

        object.__setattr__(self, "enabled_modules", tuple(modules))
        self._validate_positive_int("file_max_size", self.file_max_size, 100_000_000)
        self._validate_positive_int("staging_chunk_size", self.staging_chunk_size, 1_048_576)
        self._validate_positive_int("beacon_count", self.beacon_count, 100)
        self._validate_positive_int("max_staging_bytes", self.max_staging_bytes, 10_000_000)
        self._validate_positive_int("c2_queue_limit", self.c2_queue_limit, 1024)
        self._validate_positive_int(
            "detection_correlation_window_seconds",
            self.detection_correlation_window_seconds,
            3600,
        )

        if (
            isinstance(self.c2_command_ttl_seconds, bool)
            or not isinstance(self.c2_command_ttl_seconds, (int, float))
            or not math.isfinite(self.c2_command_ttl_seconds)
            or not 1 <= self.c2_command_ttl_seconds <= 3600
        ):
            raise configuration_error("c2_command_ttl_seconds must be between 1 and 3600")
        if not isinstance(self.detection_enabled, bool):
            raise configuration_error("detection_enabled must be a boolean")
        if not isinstance(self.persistence_platform, str) or self.persistence_platform not in {
            "cross_platform", "windows", "linux", "macos"
        }:
            raise configuration_error("persistence_platform must be cross_platform, windows, linux, or macos")

        if not isinstance(self.detection_min_severity, str) or self.detection_min_severity not in {
            "info", "low", "medium", "high", "critical"
        }:
            raise configuration_error("detection_min_severity must be info, low, medium, high, or critical")

        raw_detection_exclusions = self.detection_excluded_rules
        if isinstance(raw_detection_exclusions, (str, bytes)):
            raise configuration_error("detection_excluded_rules must be a list")
        try:
            detection_exclusions = tuple(raw_detection_exclusions)
        except TypeError as exc:
            raise configuration_error("detection_excluded_rules must be a list") from exc
        if any(
            not isinstance(rule, str) or not _rule_name.fullmatch(rule)
            for rule in detection_exclusions
        ):
            raise configuration_error("detection_excluded_rules contains an invalid rule name or id")
        if len(set(detection_exclusions)) != len(detection_exclusions):
            raise configuration_error("detection_excluded_rules contains duplicates")
        object.__setattr__(self, "detection_excluded_rules", detection_exclusions)

        raw_extensions = self.ransomware_target_extensions
        if isinstance(raw_extensions, (str, bytes)):
            raise configuration_error("ransomware_target_extensions must be a list")
        try:
            extensions = tuple(raw_extensions)
        except TypeError as exc:
            raise configuration_error("ransomware_target_extensions must be a list") from exc
        if not extensions or any(
            not isinstance(ext, str)
            or not ext.startswith(".")
            or "/" in ext
            or "\\" in ext
            for ext in extensions
        ):
            raise configuration_error("ransomware_target_extensions must contain extensions such as '.txt'")
        extensions = tuple(ext.lower() for ext in extensions)
        if len(set(extensions)) != len(extensions):
            raise configuration_error("ransomware_target_extensions contains duplicates")
        object.__setattr__(self, "ransomware_target_extensions", extensions)

        raw_exclusions = self.ransomware_excluded_paths
        if isinstance(raw_exclusions, (str, bytes)):
            raise configuration_error("ransomware_excluded_paths must be a list")
        try:
            exclusions = tuple(raw_exclusions)
        except TypeError as exc:
            raise configuration_error("ransomware_excluded_paths must be a list") from exc
        for path in exclusions:
            if (
                not isinstance(path, str)
                or not path
                or "\x00" in path
                or "\\" in path
                or Path(path).is_absolute()
                or PureWindowsPath(path).is_absolute()
                or ".." in Path(path).parts
            ):
                raise configuration_error("ransomware_excluded_paths must contain safe relative paths")
        if len(set(exclusions)) != len(exclusions):
            raise configuration_error("ransomware_excluded_paths contains duplicates")
        object.__setattr__(self, "ransomware_excluded_paths", exclusions)

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
            "version", "profile", "enabled_modules", "file_max_size",
            "staging_chunk_size", "beacon_count", "detection_enabled",
            "max_staging_bytes", "persistence_platform", "c2_command_ttl_seconds",
            "c2_queue_limit", "ransomware_target_extensions", "ransomware_excluded_paths",
            "detection_min_severity", "detection_excluded_rules",
            "detection_correlation_window_seconds",
        }
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise configuration_error(f"unknown configuration keys: {', '.join(unknown)}")

        version = values.get("version", config_version)
        if isinstance(version, bool) or not isinstance(version, int) or version != config_version:
            raise configuration_error(f"unsupported configuration version: {version!r}")

        raw_modules = values.get("enabled_modules")
        if raw_modules is not None and not isinstance(raw_modules, (list, tuple)):
            raise configuration_error("enabled_modules must be a list of names")
        raw_extensions = values.get("ransomware_target_extensions", _default_extensions)
        raw_exclusions = values.get("ransomware_excluded_paths", ())
        raw_detection_exclusions = values.get("detection_excluded_rules", ())
        if not isinstance(raw_extensions, (list, tuple)):
            raise configuration_error("ransomware_target_extensions must be a list")
        if not isinstance(raw_exclusions, (list, tuple)):
            raise configuration_error("ransomware_excluded_paths must be a list")
        if not isinstance(raw_detection_exclusions, (list, tuple)):
            raise configuration_error("detection_excluded_rules must be a list")

        try:
            return cls(
                profile=values.get("profile", "multi_stage"),
                enabled_modules=(tuple(raw_modules) if raw_modules is not None else None),
                file_max_size=values.get("file_max_size", 5_000_000),
                staging_chunk_size=values.get("staging_chunk_size", 256),
                beacon_count=values.get("beacon_count", 3),
                detection_enabled=values.get("detection_enabled", True),
                max_staging_bytes=values.get("max_staging_bytes", 1_000_000),
                persistence_platform=values.get("persistence_platform", "cross_platform"),
                c2_command_ttl_seconds=values.get("c2_command_ttl_seconds", 60.0),
                c2_queue_limit=values.get("c2_queue_limit", 64),
                ransomware_target_extensions=tuple(raw_extensions),
                ransomware_excluded_paths=tuple(raw_exclusions),
                detection_min_severity=values.get("detection_min_severity", "low"),
                detection_excluded_rules=tuple(raw_detection_exclusions),
                detection_correlation_window_seconds=values.get(
                    "detection_correlation_window_seconds", 120
                ),
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
            "max_staging_bytes": self.max_staging_bytes,
            "persistence_platform": self.persistence_platform,
            "c2_command_ttl_seconds": self.c2_command_ttl_seconds,
            "c2_queue_limit": self.c2_queue_limit,
            "ransomware_target_extensions": list(self.ransomware_target_extensions),
            "ransomware_excluded_paths": list(self.ransomware_excluded_paths),
            "detection_min_severity": self.detection_min_severity,
            "detection_excluded_rules": list(self.detection_excluded_rules),
            "detection_correlation_window_seconds": self.detection_correlation_window_seconds,
        }
