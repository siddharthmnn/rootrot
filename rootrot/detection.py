"""look for a few suspicious patterns in the events from this lab run."""

from typing import Any


class detection_engine:
    def __init__(self, logger: Any) -> None:
        self.logger = logger

    def analyze(self) -> list[dict[str, Any]]:
        events = self.logger.events
        findings = []

        def add(rule: str, severity: str, evidence: dict[str, Any]) -> None:
            findings.append(
                {
                    "rule": rule,
                    "severity": severity,
                    "evidence": evidence,
                }
            )

        persistence = [
            event for event in events
            if event["action"] == "persistence.would_write"
        ]
        if persistence:
            add(
                "persistence_indicator",
                "high",
                {"observed": len(persistence), "performed": False},
            )

        staging = [
            event for event in events
            if event["action"] == "data.staged_in_memory"
        ]
        if staging:
            add(
                "data_staging_indicator",
                "medium",
                {"events": len(staging), "transmitted": False},
            )

        ransomware = [
            event for event in events
            if event["action"] == "ransomware.dry_run"
        ]
        if ransomware:
            add(
                "ransomware_like_file_selection",
                "high",
                {"dry_runs": len(ransomware), "files_changed": 0},
            )

        beacons = [
            event for event in events
            if event["action"] == "c2.beacon"
        ]
        if len(beacons) >= 3:
            add(
                "repeated_beaconing",
                "medium",
                {"beacon_count": len(beacons)},
            )

        bad_signatures = [
            event for event in events
            if event["action"] == "c2.bad_signature"
        ]
        if bad_signatures:
            add(
                "command_authentication_failure",
                "high",
                {"rejected": len(bad_signatures)},
            )

        self.logger.emit(
            "detection",
            "analysis.completed",
            finding_count=len(findings),
        )
        return findings
