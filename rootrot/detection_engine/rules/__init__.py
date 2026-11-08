"""built-in detection rules."""

from .correlation import multi_stage_correlation_rule
from .event_rules import build_event_rules


def build_default_rules(correlation_window_seconds: int = 120):
    return [
        *build_event_rules(),
        multi_stage_correlation_rule(window_seconds=correlation_window_seconds),
    ]


__all__ = ["build_default_rules", "multi_stage_correlation_rule"]
