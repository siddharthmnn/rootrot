#!/usr/bin/env python3
"""
MALSTRIKE
Advanced Malware Behaviour Simulation & Detection Framework
Python 3.10+
Standard library only.

All activity is restricted to synthetic files in an isolated,
automatically cleaned temporary workspace. No real persistence,
command execution, encryption, or external data transmission.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import queue
import secrets
import tempfile
import time

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ============================================================
# CONFIGURATION
# ============================================================

FRAMEWORK = "MALSTRIKE"
VERSION = "1.0.0"

MAX_FILE_SIZE = 5 * 1024 * 1024
CHUNK_SIZE = 256
ALLOWED_TASKS = {"inventory", "hash_file", "status"}


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode()


# ============================================================
# EVENT TELEMETRY AND HASH-CHAIN AUDITING
# ============================================================

@dataclass
class Event:
    timestamp: str
    source: str
    action: str
    severity: str
    details: dict[str, Any] = field(default_factory=dict)


class EventLogger:

    def __init__(self):
        self.events: list[dict] = []
        self.previous_hash = "0" * 64

    def emit(
        self,
        source: str,
        action: str,
        severity: str = "INFO",
        **details
    ):
        event = Event(
            timestamp=timestamp(),
            source=source,
            action=action,
            severity=severity,
            details=details
        )

        record = asdict(event)
        record["previous_hash"] = self.previous_hash

        current_hash = sha256(canonical(record))
        record["event_hash"] = current_hash

        self.events.append(record)
        self.previous_hash = current_hash

    def verify_integrity(self) -> bool:
        previous = "0" * 64

        for event in self.events:
            record = {
                key: value
                for key, value in event.items()
                if key != "event_hash"
            }

            if record["previous_hash"] != previous:
                return False

            expected = sha256(canonical(record))

            if not hmac.compare_digest(
                expected, event["event_hash"]
            ):
                return False

            previous = expected

        return True


# ============================================================
# FILE INTELLIGENCE
# ============================================================

class FileIntelligence:

    def __init__(self, root: Path, logger: EventLogger):
        self.root = root.resolve()
        self.logger = logger

    @staticmethod
    def entropy(data: bytes) -> float:
        if not data:
            return 0.0

        frequencies = Counter(data)
        length = len(data)

        return -sum(
            (count / length) * math.log2(count / length)
            for count in frequencies.values()
        )

    def safe_path(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()

        if not candidate.is_relative_to(self.root):
            raise ValueError("Path escapes isolated workspace")

        if candidate.is_symlink():
            raise ValueError("Symbolic links are prohibited")

        return candidate

    def fingerprint(self, path: Path) -> dict:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid file")

        if path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError("File exceeds size limit")

        data = path.read_bytes()

        return {
            "name": path.name,
            "size": len(data),
            "sha256": sha256(data),
            "entropy": round(self.entropy(data), 4),
            "extension": path.suffix.lower()
        }

    def inventory(self) -> list[dict]:
        results = []

        for path in self.root.rglob("*"):
            try:
                if path.is_symlink() or not path.is_file():
                    continue

                result = self.fingerprint(path)
                results.append(result)

                self.logger.emit(
                    "file_intelligence",
                    "file.inspected",
                    file=path.name,
                    sha256=result["sha256"],
                    entropy=result["entropy"]
                )

            except (OSError, ValueError):
                continue

        return results


# ============================================================
# SYNTHETIC MALWARE PERSISTENCE SIMULATOR
# ============================================================

class PersistenceSimulator:

    def __init__(self, logger: EventLogger):
        self.logger = logger

    def simulate(self):
        techniques = [
            "windows_run_key",
            "scheduled_task",
            "linux_autostart",
            "service_registration"
        ]

        results = []

        for technique in techniques:
            self.logger.emit(
                "persistence_simulator",
                "persistence.write_attempt",
                "WARNING",
                technique=technique,
                executed=False
            )

            results.append({
                "technique": technique,
                "simulated": True,
                "system_modified": False
            })

        return results


# ============================================================
# LOCAL IN-MEMORY COMMAND AND CONTROL SIMULATOR
# ============================================================

@dataclass
class Command:
    command_id: str
    action: str
    arguments: dict
    signature: str


class C2Controller:

    def __init__(self, secret: bytes, logger: EventLogger):
        self.secret = secret
        self.logger = logger
        self.commands = queue.Queue()

    def sign(self, payload: dict) -> str:
        return hmac.new(
            self.secret,
            canonical(payload),
            hashlib.sha256
        ).hexdigest()

    def beacon(self, agent_id: str):
        self.logger.emit(
            "c2_controller",
            "c2.beacon",
            agent=agent_id
        )

    def dispatch(self, action: str, arguments=None):
        if action not in ALLOWED_TASKS:
            raise ValueError("Unsupported command")

        payload = {
            "command_id": secrets.token_hex(8),
            "action": action,
            "arguments": arguments or {}
        }

        signature = self.sign(payload)

        command = Command(
            command_id=payload["command_id"],
            action=action,
            arguments=payload["arguments"],
            signature=signature
        )

        self.commands.put(command)

        self.logger.emit(
            "c2_controller",
            "c2.task_dispatched",
            command_id=command.command_id,
            action=action
        )

        return command


class C2Agent:

    def __init__(
        self,
        agent_id: str,
        root: Path,
        secret: bytes,
        controller: C2Controller,
        logger: EventLogger
    ):
        self.agent_id = agent_id
        self.root = root.resolve()
        self.secret = secret
        self.controller = controller
        self.logger = logger

    def validate(self, command: Command) -> bool:
        if command.action not in ALLOWED_TASKS:
            return False

        payload = {
            "command_id": command.command_id,
            "action": command.action,
            "arguments": command.arguments
        }

        expected = hmac.new(
            self.secret,
            canonical(payload),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(
            expected, command.signature
        )

    def execute_allowed_task(self, command: Command):
        action = command.action

        if action == "status":
            return {
                "agent_id": self.agent_id,
                "status": "simulated_online",
                "timestamp": timestamp()
            }

        if action == "inventory":
            scanner = FileIntelligence(
                self.root, self.logger
            )
            return scanner.inventory()

        if action == "hash_file":
            relative = command.arguments.get("path", "")

            scanner = FileIntelligence(
                self.root, self.logger
            )

            path = scanner.safe_path(relative)
            return scanner.fingerprint(path)

        raise ValueError("Task not implemented")

    def poll(self):
        while not self.controller.commands.empty():
            command = self.controller.commands.get()

            if not self.validate(command):
                self.logger.emit(
                    "c2_agent",
                    "c2.invalid_signature",
                    "ALERT",
                    command_id=command.command_id
                )
                continue

            result = self.execute_allowed_task(command)

            self.logger.emit(
                "c2_agent",
                "c2.task_completed",
                command_id=command.command_id,
                action=command.action
            )

            yield {
                "command_id": command.command_id,
                "result": result
            }


# ============================================================
# DATA STAGING AND EXFILTRATION SIMULATOR
# ============================================================

class ExfiltrationSimulator:

    def __init__(self, logger: EventLogger):
        self.logger = logger

    def simulate(self, synthetic_data: bytes) -> dict:
        chunks = [
            synthetic_data[i:i + CHUNK_SIZE]
            for i in range(0, len(synthetic_data), CHUNK_SIZE)
        ]

        manifest = []

        for index, chunk in enumerate(chunks):
            encoded = base64.b64encode(chunk)

            manifest.append({
                "index": index,
                "encoded_size": len(encoded),
                "sha256": sha256(chunk)
            })

        result = {
            "original_size": len(synthetic_data),
            "chunk_count": len(chunks),
            "chunks": manifest,
            "transmitted": False
        }

        self.logger.emit(
            "exfil_simulator",
            "data.staged",
            "WARNING",
            chunk_count=len(chunks),
            bytes=len(synthetic_data),
            transmitted=False
        )

        return result


# ============================================================
# NON-DESTRUCTIVE RANSOMWARE BEHAVIOUR SIMULATOR
# ============================================================

class RansomwareSimulator:

    TARGET_EXTENSIONS = {
        ".txt", ".csv", ".json", ".log", ".pdf"
    }

    def __init__(self, scanner: FileIntelligence,
                 logger: EventLogger):
        self.scanner = scanner
        self.logger = logger

    def dry_run(self):
        targets = []

        for path in self.scanner.root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue

            if path.suffix.lower() in self.TARGET_EXTENSIONS:
                targets.append({
                    "filename": path.name,
                    "size": path.stat().st_size,
                    "would_be_targeted": True,
                    "modified": False
                })

        self.logger.emit(
            "ransomware_simulator",
            "ransomware.dry_run",
            "WARNING",
            candidates=len(targets),
            files_modified=0
        )

        return {
            "mode": "NON_DESTRUCTIVE",
            "targets": targets,
            "files_encrypted": 0
        }


# ============================================================
# BEHAVIOURAL DETECTION ENGINE
# ============================================================

class DetectionEngine:

    def __init__(self, logger: EventLogger):
        self.logger = logger

    def analyze(self) -> list[dict]:
        events = self.logger.events
        findings = []

        def alert(rule, severity, evidence):
            findings.append({
                "rule": rule,
                "severity": severity,
                "evidence": evidence,
                "timestamp": timestamp()
            })

        persistence_events = [
            e for e in events
            if e["action"] == "persistence.write_attempt"
        ]

        if persistence_events:
            alert(
                "PERSISTENCE_BEHAVIOUR",
                "HIGH",
                {
                    "attempts": len(persistence_events),
                    "executed": False
                }
            )

        staging_events = [
            e for e in events
            if e["action"] == "data.staged"
        ]

        for event in staging_events:
            if event["details"].get("chunk_count", 0) > 1:
                alert(
                    "POTENTIAL_DATA_EXFILTRATION",
                    "HIGH",
                    event["details"]
                )

        dry_runs = [
            e for e in events
            if e["action"] == "ransomware.dry_run"
        ]

        if dry_runs:
            alert(
                "RANSOMWARE_LIKE_ACTIVITY",
                "HIGH",
                {
                    "simulation_count": len(dry_runs),
                    "destructive_activity": False
                }
            )

        beacons = [
            e for e in events
            if e["action"] == "c2.beacon"
        ]

        if len(beacons) >= 3:
            alert(
                "REPEATED_C2_BEACONING",
                "MEDIUM",
                {"beacon_count": len(beacons)}
            )

        invalid_signatures = [
            e for e in events
            if e["action"] == "c2.invalid_signature"
        ]

        if invalid_signatures:
            alert(
                "INVALID_COMMAND_AUTHENTICATION",
                "HIGH",
                {"rejected_commands": len(invalid_signatures)}
            )

        self.logger.emit(
            "detection_engine",
            "analysis.completed",
            findings=len(findings)
        )

        return findings


# ============================================================
# SYNTHETIC LAB INITIALIZATION
# ============================================================

def initialize_lab(root: Path):
    demo = root / "demo"
    demo.mkdir(parents=True)

    (demo / "notes.txt").write_text(
        "Synthetic malware research dataset.\n"
        "No real personal information.\n",
        encoding="utf-8"
    )

    (demo / "config.json").write_text(
        json.dumps({
            "environment": "isolated_lab",
            "agent": "test_agent",
            "debug": True
        }, indent=2),
        encoding="utf-8"
    )

    (demo / "sample.csv").write_text(
        "id,name,value\n"
        "001,TEST_USER,123\n"
        "002,DEMO_USER,456\n",
        encoding="utf-8"
    )

    (demo / "sample.log").write_text(
        "[INFO] Agent initialized\n"
        "[INFO] Synthetic telemetry generated\n"
        "[WARNING] Simulated behaviour detected\n",
        encoding="utf-8"
    )


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():

    report = {
        "framework": FRAMEWORK,
        "version": VERSION,
        "started": timestamp()
    }

    logger = EventLogger()

    with tempfile.TemporaryDirectory(
        prefix="malstrike_isolated_"
    ) as temporary_directory:

        root = Path(temporary_directory).resolve()

        initialize_lab(root)

        scanner = FileIntelligence(root, logger)

        # 1. File intelligence
        inventory = scanner.inventory()

        logger.emit(
            "framework",
            "inventory.completed",
            files=len(inventory)
        )

        # 2. Persistence simulation
        persistence = PersistenceSimulator(
            logger
        ).simulate()

        # 3. Simulated authenticated C2
        secret = secrets.token_bytes(32)

        controller = C2Controller(
            secret, logger
        )

        agent = C2Agent(
            agent_id="MALSTRIKE-AGENT-001",
            root=root,
            secret=secret,
            controller=controller,
            logger=logger
        )

        c2_results = []

        for _ in range(3):
            controller.beacon(agent.agent_id)

        controller.dispatch("status")
        controller.dispatch("inventory")
        controller.dispatch(
            "hash_file",
            {"path": "demo/notes.txt"}
        )

        c2_results.extend(agent.poll())

        # 4. Non-destructive ransomware simulation
        ransomware = RansomwareSimulator(
            scanner, logger
        ).dry_run()

        # 5. Synthetic data staging
        synthetic_data = (
            b"MALSTRIKE SYNTHETIC TELEMETRY " * 40
        )

        exfiltration = ExfiltrationSimulator(
            logger
        ).simulate(synthetic_data)

        # 6. Behavioural detection
        detections = DetectionEngine(
            logger
        ).analyze()

        # 7. Integrity verification
        integrity = logger.verify_integrity()

        report.update({
            "completed": timestamp(),
            "file_inventory": inventory,
            "persistence_simulation": persistence,
            "c2_results": c2_results,
            "ransomware_simulation": ransomware,
            "data_staging": exfiltration,
            "detections": detections,
            "event_count": len(logger.events),
            "event_log_integrity": integrity,
            "execution_environment": "ISOLATED_TEMPORARY_WORKSPACE",
            "external_network_access": False,
            "system_persistence": False,
            "real_file_modification": False,
            "real_data_exfiltration": False
        })

        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
