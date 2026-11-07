"""tests for platform-specific persistence examples."""

import unittest

from rootrot.events import event_logger
from rootrot.persistence_simulator import persistence_simulator


class test_persistence_profiles(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger()
        self.simulator = persistence_simulator(self.logger)

    def test_default_profile_preserves_cross_platform_examples(self):
        results = self.simulator.run()
        self.assertEqual(len(results), 4)
        self.assertTrue(all(item["simulated"] for item in results))
        self.assertTrue(all(not item["system_modified"] for item in results))

    def test_platform_profiles_return_only_their_examples(self):
        windows = self.simulator.run("windows")
        linux = self.simulator.run("linux")
        macos = self.simulator.run("macos")
        self.assertEqual({item["platform"] for item in windows}, {"windows"})
        self.assertIn("systemd_user_service", {item["technique"] for item in linux})
        self.assertIn("launch_agent", {item["technique"] for item in macos})

    def test_unknown_platform_is_rejected(self):
        with self.assertRaises(ValueError):
            self.simulator.run("freebsd")

    def test_every_example_is_recorded_as_not_performed(self):
        results = self.simulator.run("windows")
        events = [
            event for event in self.logger.events
            if event["action"] == "persistence.would_write"
        ]
        self.assertEqual(len(results), len(events))
        self.assertTrue(all(event["details"]["performed"] is False for event in events))


if __name__ == "__main__":
    unittest.main()
