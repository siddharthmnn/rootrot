"""run the built-in detection rules against one event stream."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .models import detection_finding
from .rules import build_default_rules
from .rules.base import detection_rule
from .scoring import meets_minimum_severity


class detection_error(RuntimeError):
    """raised when a rule fails and the analysis would otherwise be incomplete."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"detection rule '{rule_id}' failed")
        self.rule_id = rule_id


class detection_engine:
    """evaluate independent rules, apply policy, and return ranked findings."""

    def __init__(
        self,
        logger: Any,
        rules: Iterable[detection_rule] | None = None,
        minimum_severity: str = "low",
        excluded_rules: Iterable[str] = (),
        correlation_window_seconds: int = 120,
    ) -> None:
        allowed_severities = {"info", "low", "medium", "high", "critical"}
        if not isinstance(minimum_severity, str) or minimum_severity not in allowed_severities:
            raise ValueError("minimum_severity must be info, low, medium, high, or critical")
        if (
            isinstance(correlation_window_seconds, bool)
            or not isinstance(correlation_window_seconds, int)
            or not 1 <= correlation_window_seconds <= 3600
        ):
            raise ValueError("correlation_window_seconds must be between 1 and 3600")
        if isinstance(excluded_rules, (str, bytes)):
            raise ValueError("excluded_rules must be an iterable of rule names or ids")
        try:
            exclusions = tuple(excluded_rules)
        except TypeError as exc:
            raise ValueError("excluded_rules must be an iterable of rule names or ids") from exc
        if any(not isinstance(item, str) or not item for item in exclusions):
            raise ValueError("excluded rule names and ids must be non-empty strings")
        if len(set(exclusions)) != len(exclusions):
            raise ValueError("excluded_rules contains duplicates")

        selected_rules = list(
            rules if rules is not None else build_default_rules(correlation_window_seconds)
        )
        ids = [getattr(rule, "rule_id", None) for rule in selected_rules]
        if any(not isinstance(rule_id, str) or not rule_id for rule_id in ids):
            raise ValueError("every detection rule must have a non-empty rule_id")
        if len(set(ids)) != len(ids):
            raise ValueError("detection rule ids must be unique")
        for rule in selected_rules:
            if not callable(getattr(rule, "evaluate", None)):
                raise TypeError("every detection rule must provide evaluate(events)")
            if not isinstance(getattr(rule, "name", None), str):
                raise TypeError("every detection rule must have a name")
            if not isinstance(getattr(rule, "description", None), str):
                raise TypeError("every detection rule must have a description")
            if (
                isinstance(getattr(rule, "base_score", None), bool)
                or not isinstance(getattr(rule, "base_score", None), int)
                or not 0 <= rule.base_score <= 100
            ):
                raise TypeError("every detection rule must have a base_score between 0 and 100")

        self.logger = logger
        self.rules = tuple(selected_rules)
        self.minimum_severity = minimum_severity
        self.excluded_rules = frozenset(exclusions)
        self.correlation_window_seconds = correlation_window_seconds

    def list_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "base_score": rule.base_score,
                "enabled": (
                    rule.rule_id not in self.excluded_rules
                    and rule.name not in self.excluded_rules
                ),
            }
            for rule in self.rules
        ]

    @staticmethod
    def _validate_events(events: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        if isinstance(events, (str, bytes, Mapping)):
            raise ValueError("events must be an iterable of event objects")
        try:
            records = list(events)
        except TypeError as exc:
            raise ValueError("events must be an iterable of event objects") from exc
        for index, event in enumerate(records, start=1):
            if not isinstance(event, Mapping):
                raise ValueError(f"event at position {index} is not an object")
            if not isinstance(event.get("action"), str) or not event["action"]:
                raise ValueError(f"event at position {index} has no valid action")
            if "details" in event and not isinstance(event["details"], Mapping):
                raise ValueError(f"event at position {index} has invalid details")
            if event.get("run_id") is not None and not isinstance(event["run_id"], str):
                raise ValueError(f"event at position {index} has an invalid run id")
        return records

    def analyze(
        self,
        events: Iterable[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        source_events = self.logger.events if events is None else events
        records = self._validate_events(source_events)
        findings: list[detection_finding] = []
        evaluated_rules = 0
        excluded_count = 0

        for rule in self.rules:
            if rule.rule_id in self.excluded_rules or rule.name in self.excluded_rules:
                excluded_count += 1
                continue
            evaluated_rules += 1
            try:
                rule_findings = rule.evaluate(records)
                if not isinstance(rule_findings, list) or any(
                    not isinstance(item, detection_finding) for item in rule_findings
                ):
                    raise TypeError("a detection rule must return a list of detection_finding objects")
            except Exception as exc:
                self.logger.emit(
                    "detection",
                    "detection.rule_failed",
                    "error",
                    rule_id=rule.rule_id,
                    error_type=type(exc).__name__,
                )
                raise detection_error(rule.rule_id) from exc

            for finding in rule_findings:
                if meets_minimum_severity(finding.severity, self.minimum_severity):
                    findings.append(finding)

        findings.sort(key=lambda item: (-item.score, item.rule_id))
        output = [finding.to_dict() for finding in findings]
        self.logger.emit(
            "detection",
            "analysis.completed",
            finding_count=len(output),
            evaluated_event_count=len(records),
            evaluated_rule_count=evaluated_rules,
            excluded_rule_count=excluded_count,
            minimum_severity=self.minimum_severity,
            correlation_window_seconds=self.correlation_window_seconds,
        )
        return output
