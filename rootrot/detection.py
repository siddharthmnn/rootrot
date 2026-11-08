"""backwards-compatible import for the modular detection engine."""

from .detection_engine.engine import detection_engine, detection_error

__all__ = ["detection_engine", "detection_error"]
