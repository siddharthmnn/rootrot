"""tests for command expiry, replay rejection, and queue lifecycle."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rootrot.c2_simulator import c2_agent, c2_controller
from rootrot.events import event_logger


class test_c2_lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        (self.workspace / "notes.txt").write_text("synthetic data", encoding="utf-8")
        self.logger = event_logger()
        self.now = [100.0]
        self.controller = c2_controller(
            b"test-secret",
            self.logger,
            command_ttl_seconds=5,
            max_queue_size=2,
            clock=lambda: self.now[0],
        )
        self.agent = c2_agent("test-agent", self.workspace, self.controller, self.logger)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_command_moves_through_queued_running_and_completed(self):
        item = self.controller.dispatch("status")
        self.assertEqual(self.controller.command_status(item.command_id), "queued")
        results = list(self.agent.poll())
        self.assertEqual(len(results), 1)
        self.assertEqual(self.controller.command_status(item.command_id), "completed")

    def test_expired_command_is_not_executed(self):
        item = self.controller.dispatch("status")
        self.now[0] += 6
        self.assertEqual(list(self.agent.poll()), [])
        self.assertEqual(self.controller.command_status(item.command_id), "expired")

    def test_replayed_command_is_rejected(self):
        item = self.controller.dispatch("status")
        self.assertEqual(len(list(self.agent.poll())), 1)
        self.controller._queue.put_nowait(item)
        self.assertEqual(list(self.agent.poll()), [])
        self.assertEqual(self.controller.command_status(item.command_id), "rejected")
        self.assertIn(
            "c2.command_replayed",
            {event["action"] for event in self.logger.events},
        )

    def test_tampered_command_is_rejected(self):
        item = self.controller.dispatch("status")
        changed = replace(item, arguments={"unexpected": True})
        self.controller._queue.get_nowait()
        self.controller._queue.put_nowait(changed)
        self.assertEqual(list(self.agent.poll()), [])
        self.assertEqual(self.controller.command_status(item.command_id), "rejected")

    def test_queue_is_bounded(self):
        controller = c2_controller(b"test-secret", self.logger, max_queue_size=1)
        controller.dispatch("status")
        with self.assertRaises(RuntimeError):
            controller.dispatch("inventory")

    def test_invalid_command_arguments_are_rejected_before_queueing(self):
        for arguments in (
            {"path": "../outside.txt"},
            {"path": "C:\\Windows\\win.ini"},
            {"extra": True},
        ):
            with self.assertRaises(ValueError):
                self.controller.dispatch("hash_file", arguments)
        with self.assertRaises(ValueError):
            self.controller.dispatch("status", {"unexpected": True})
        self.assertEqual(self.controller._queue.qsize(), 0)

    def test_valid_hash_file_command_stays_inside_workspace(self):
        self.controller.dispatch("hash_file", {"path": "notes.txt"})
        results = list(self.agent.poll())
        self.assertEqual(results[0]["result"]["name"], "notes.txt")

    def test_invalid_ttl_and_queue_limits_are_rejected(self):
        with self.assertRaises(ValueError):
            c2_controller(b"secret", self.logger, command_ttl_seconds=0)
        with self.assertRaises(ValueError):
            c2_controller(b"secret", self.logger, max_queue_size=0)


if __name__ == "__main__":
    unittest.main()
