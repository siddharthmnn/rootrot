"""tests for shared run context, simulator registration, and orchestration."""

import tempfile
import unittest
from pathlib import Path

from rootrot.core.config import rootrot_config
from rootrot.core.context import run_context
from rootrot.core.orchestrator import simulation_error, simulation_orchestrator
from rootrot.core.registry import simulation_registry
from rootrot.events import event_logger


class test_run_context(unittest.TestCase):
    def test_context_shares_the_logger_run_id_and_resolves_workspace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = event_logger(run_id="test-run")
            context = run_context.create(temp_dir, rootrot_config(), logger)
        self.assertEqual(context.run_id, "test-run")
        self.assertEqual(context.logger, logger)
        self.assertTrue(context.workspace.is_absolute())

    def test_context_rejects_a_file_as_workspace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.txt"
            path.write_text("demo", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_context.create(path)


class test_simulation_registry(unittest.TestCase):
    def test_register_and_describe_handler(self):
        registry = simulation_registry()
        registry.register("sample", lambda context: {"ok": True}, "sample handler")
        self.assertEqual(registry.names(), ("sample",))
        self.assertEqual(registry.describe()[0]["description"], "sample handler")

    def test_duplicate_names_are_rejected(self):
        registry = simulation_registry()
        registry.register("sample", lambda context: None)
        with self.assertRaises(ValueError):
            registry.register("sample", lambda context: None)

    def test_invalid_names_and_handlers_are_rejected(self):
        registry = simulation_registry()
        with self.assertRaises(ValueError):
            registry.register("Bad-Name", lambda context: None)
        with self.assertRaises(TypeError):
            registry.register("sample", None)


class test_simulation_orchestrator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.context = run_context.create(
            self.temp_dir.name,
            rootrot_config(enabled_modules=("first", "second")),
            event_logger(run_id="orchestrator-test"),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_handlers_run_in_configured_order(self):
        seen = []
        registry = simulation_registry()
        registry.register("first", lambda context: seen.append("first") or 1)
        registry.register("second", lambda context: seen.append("second") or 2)
        outcomes = simulation_orchestrator(self.context, registry).run()
        self.assertEqual(seen, ["first", "second"])
        self.assertEqual(outcomes["first"].output, 1)
        self.assertEqual(outcomes["second"].output, 2)
        self.assertGreaterEqual(outcomes["first"].duration_ms, 0)

    def test_missing_registered_module_is_rejected_before_execution(self):
        registry = simulation_registry()
        with self.assertRaises(ValueError):
            simulation_orchestrator(self.context, registry).run()
        self.assertEqual(self.context.logger.events, [])

    def test_handler_failure_is_logged_and_preserves_cause(self):
        def fail(context):
            raise RuntimeError("expected test failure")

        registry = simulation_registry()
        registry.register("first", fail)
        registry.register("second", lambda context: 2)
        with self.assertRaises(simulation_error) as caught:
            simulation_orchestrator(self.context, registry).run()
        self.assertEqual(caught.exception.module, "first")
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertEqual(self.context.logger.events[-1]["action"], "simulation.failed")
        self.assertFalse(
            any(
                event["action"] == "simulation.started"
                and event["details"].get("module") == "second"
                for event in self.context.logger.events
            )
        )


if __name__ == "__main__":
    unittest.main()
