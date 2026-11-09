"""tests for injectable clocks used by deterministic validation scenarios."""

import unittest

from rootrot.events import event_logger


class test_event_logger_clock(unittest.TestCase):
    def test_custom_clock_is_used_for_each_event(self):
        values = iter(
            (
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:01+00:00",
            )
        )
        logger = event_logger(run_id="clock-test", clock=lambda: next(values))
        first = logger.emit("test", "event.one")
        second = logger.emit("test", "event.two")
        self.assertEqual(first["timestamp"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(second["timestamp"], "2026-01-01T00:00:01+00:00")
        self.assertTrue(logger.verify_integrity())

    def test_non_callable_clock_is_rejected(self):
        with self.assertRaises(TypeError):
            event_logger(run_id="clock-test", clock="not-callable")

    def test_bad_clock_output_is_rejected_before_event_is_stored(self):
        logger = event_logger(run_id="clock-test", clock=lambda: "not-a-timestamp")
        with self.assertRaises(ValueError):
            logger.emit("test", "event.one")
        self.assertEqual(logger.events, [])


if __name__ == "__main__":
    unittest.main()
