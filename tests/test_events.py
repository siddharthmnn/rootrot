"""tests for the event log and its hash chain."""

import unittest

from rootrot.events import event_logger


class test_event_logger(unittest.TestCase):
    def setUp(self):
        self.logger = event_logger()

    def test_emit_stores_the_event_details(self):
        event = self.logger.emit("test", "test.started", "info", item_count=3)
        self.assertEqual(event["source"], "test")
        self.assertEqual(event["action"], "test.started")
        self.assertEqual(event["severity"], "info")
        self.assertEqual(event["details"]["item_count"], 3)
        self.assertEqual(len(event["event_hash"]), 64)

    def test_hash_chain_is_valid_after_multiple_events(self):
        self.logger.emit("test", "first")
        self.logger.emit("test", "second")
        self.logger.emit("test", "third")
        self.assertTrue(self.logger.verify_integrity())

    def test_changed_event_is_detected(self):
        self.logger.emit("test", "file.inspected", filename="notes.txt")
        self.logger.events[0]["details"]["filename"] = "changed.txt"
        self.assertFalse(self.logger.verify_integrity())

    def test_empty_log_is_valid(self):
        self.assertTrue(self.logger.verify_integrity())

    def test_events_have_run_id_and_contiguous_sequence(self):
        first = self.logger.emit("test", "first")
        second = self.logger.emit("test", "second")
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual([first["sequence"], second["sequence"]], [1, 2])

    def test_sequence_tampering_is_detected(self):
        self.logger.emit("test", "first")
        self.logger.events[0]["sequence"] = 5
        self.assertFalse(self.logger.verify_integrity())


if __name__ == "__main__":
    unittest.main()
