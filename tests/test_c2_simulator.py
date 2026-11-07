"""tests for the in-memory command queue and its local agent."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rootrot.c2_simulator import c2_agent, c2_controller
from rootrot.events import event_logger


class test_c2_simulator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        (self.workspace / "notes.txt").write_text(
            "synthetic test data",
            encoding="utf-8",
        )
        self.logger = event_logger()
        self.controller = c2_controller(b"unit-test-secret", self.logger)
        self.agent = c2_agent(
            "test-agent",
            self.workspace,
            self.controller,
            self.logger,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            c2_controller(b"", self.logger)

    def test_unknown_action_is_rejected(self):
        with self.assertRaises(ValueError):
            self.controller.dispatch("run_shell")

    def test_dispatched_command_has_a_valid_signature(self):
        item = self.controller.dispatch("status")
        self.assertTrue(self.controller.verify(item))

    def test_changed_command_arguments_fail_signature_check(self):
        item = self.controller.dispatch("status")
        changed_item = replace(item, arguments={"unexpected": True})
        self.assertFalse(self.controller.verify(changed_item))

    def test_agent_handles_status_task(self):
        self.controller.dispatch("status")
        results = list(self.agent.poll())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["action"], "status")
        self.assertEqual(results[0]["result"]["agent_id"], "test-agent")
        self.assertEqual(results[0]["result"]["state"], "simulated_online")

    def test_agent_hashes_only_a_file_in_the_workspace(self):
        self.controller.dispatch("hash_file", {"path": "notes.txt"})
        results = list(self.agent.poll())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["action"], "hash_file")
        self.assertEqual(results[0]["result"]["name"], "notes.txt")

    def test_agent_rejects_a_path_outside_the_workspace(self):
        with self.assertRaises(ValueError):
            self.controller.dispatch("hash_file", {"path": "../outside.txt"})


if __name__ == "__main__":
    unittest.main()
