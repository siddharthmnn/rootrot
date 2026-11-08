"""common interface for behavioural detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from ..models import detection_finding


class detection_rule(ABC):
    rule_id: str
    name: str
    description: str
    base_score: int

    @abstractmethod
    def evaluate(
        self,
        events: list[Mapping[str, Any]],
    ) -> list[detection_finding]:
        """return findings supported by the supplied event records."""
        raise NotImplementedError
