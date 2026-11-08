"""rules that look for individual event types or repeated signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .base import detection_rule
from ..models import detection_finding, event_reference
from ..scoring import score_finding, severity_for_score


evidence_builder = Callable[[list[Mapping[str, Any]]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class event_action_rule(detection_rule):
    rule_id: str
    name: str
    description: str
    actions: tuple[str, ...]
    base_score: int
    explanation: str
    make_evidence: evidence_builder
    minimum_events: int = 1

    def evaluate(
        self,
        events: list[Mapping[str, Any]],
    ) -> list[detection_finding]:
        grouped: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
        for index, event in enumerate(events, start=1):
            if event.get("action") not in self.actions:
                continue
            run_id = event.get("run_id")
            group_key = run_id if isinstance(run_id, str) and run_id else "unknown"
            grouped.setdefault(group_key, []).append((index, event))

        findings = []
        for run_id, indexed_matches in grouped.items():
            if len(indexed_matches) < self.minimum_events:
                continue
            matches = [event for _, event in indexed_matches]
            score = score_finding(self.base_score, len(matches))
            references = tuple(
                event_reference(event, index)
                for index, event in indexed_matches[-25:]
            )
            evidence = self.make_evidence(matches)
            evidence.setdefault("run_id", run_id)
            findings.append(
                detection_finding(
                    rule_id=self.rule_id,
                    rule=self.name,
                    severity=severity_for_score(score),
                    score=score,
                    explanation=self.explanation,
                    evidence=evidence,
                    events=references,
                )
            )
        return findings


def build_event_rules() -> list[detection_rule]:
    return [
        event_action_rule(
            rule_id="rr.persistence.001",
            name="persistence_indicator",
            description="records simulated attempts to describe common persistence locations",
            actions=("persistence.would_write",),
            base_score=70,
            explanation="one or more persistence locations were represented in the simulation; no host configuration was changed",
            make_evidence=lambda items: {
                "observed": len(items),
                "performed": False,
            },
        ),
        event_action_rule(
            rule_id="rr.staging.001",
            name="data_staging_indicator",
            description="records synthetic data chunking kept in memory",
            actions=("data.staged_in_memory",),
            base_score=45,
            explanation="synthetic data was split into in-memory chunks; nothing was transmitted",
            make_evidence=lambda items: {
                "events": len(items),
                "transmitted": False,
            },
        ),
        event_action_rule(
            rule_id="rr.ransomware.001",
            name="ransomware_like_file_selection",
            description="records a non-destructive preview of file selection",
            actions=("ransomware.dry_run",),
            base_score=72,
            explanation="the dry-run selector identified candidate files; no files were encrypted or modified",
            make_evidence=lambda items: {
                "dry_runs": len(items),
                "files_changed": 0,
            },
        ),
        event_action_rule(
            rule_id="rr.c2.001",
            name="repeated_beaconing",
            description="identifies repeated in-memory agent heartbeat events",
            actions=("c2.beacon",),
            base_score=45,
            explanation="the same run contains repeated simulated agent heartbeat events; no network transport was used",
            make_evidence=lambda items: {
                "beacon_count": len(items),
                "transport": "in_memory",
            },
            minimum_events=3,
        ),
        event_action_rule(
            rule_id="rr.c2.002",
            name="command_authentication_failure",
            description="identifies a task rejected because its authentication signature was invalid",
            actions=("c2.bad_signature",),
            base_score=75,
            explanation="the local agent rejected a task whose signature did not validate",
            make_evidence=lambda items: {"rejected": len(items)},
        ),
        event_action_rule(
            rule_id="rr.file.001",
            name="file_extension_mismatch",
            description="identifies a mismatch between a file signature and its name extension",
            actions=("file.extension_mismatch",),
            base_score=42,
            explanation="the detected file signature did not match the file extension; this can be useful for triage but is not proof of malware",
            make_evidence=lambda items: {
                "mismatches": len(items),
                "files": [
                    (
                        item.get("details", {}).get("file")
                        if isinstance(item.get("details"), Mapping)
                        else None
                    )
                    for item in items[:25]
                ],
            },
        ),
        event_action_rule(
            rule_id="rr.c2.003",
            name="command_replay_attempt",
            description="identifies a previously consumed local task presented again",
            actions=("c2.command_replayed",),
            base_score=75,
            explanation="the local controller rejected a command identifier that had already been consumed",
            make_evidence=lambda items: {"rejected": len(items)},
        ),
    ]
