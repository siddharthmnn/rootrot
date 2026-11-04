"""show common persistence locations without changing the host system."""

from typing import Any


class persistence_simulator:
    examples = (
        "windows_run_key",
        "scheduled_task",
        "linux_autostart_entry",
        "service_registration",
    )

    def __init__(self, logger: Any) -> None:
        self.logger = logger

    def run(self) -> list[dict[str, Any]]:
        results = []

        for technique in self.examples:
            self.logger.emit(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                technique=technique,
                performed=False,
            )
            results.append(
                {
                    "technique": technique,
                    "simulated": True,
                    "system_modified": False,
                }
            )

        return results
