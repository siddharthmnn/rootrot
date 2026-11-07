"""show common persistence locations without changing the host system."""

from typing import Any


class persistence_simulator:
    """record platform-specific examples as events; never write to the host."""

    examples = (
        "windows_run_key",
        "scheduled_task",
        "linux_autostart_entry",
        "service_registration",
    )
    platform_examples = {
        "cross_platform": examples,
        "windows": ("windows_run_key", "startup_folder", "scheduled_task"),
        "linux": ("linux_autostart_entry", "systemd_user_service", "cron_user_entry"),
        "macos": ("launch_agent", "login_item"),
    }

    def __init__(self, logger: Any) -> None:
        self.logger = logger

    def run(self, platform: str = "cross_platform") -> list[dict[str, Any]]:
        if platform not in self.platform_examples:
            available = ", ".join(self.platform_examples)
            raise ValueError(f"unknown platform profile {platform!r}; choose from {available}")

        results = []
        for technique in self.platform_examples[platform]:
            self.logger.emit(
                "persistence_simulator",
                "persistence.would_write",
                "warning",
                platform=platform,
                technique=technique,
                performed=False,
            )
            results.append({
                "platform": platform,
                "technique": technique,
                "simulated": True,
                "system_modified": False,
            })
        return results
