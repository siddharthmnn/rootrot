"""modular behavioural analysis for rootrot events."""

from .engine import detection_engine
from .models import detection_finding

__all__ = ["detection_engine", "detection_finding"]
