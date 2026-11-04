"""simulate a tiny command queue without sockets or remote execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Iterator

from .file_intel import file_intel


@dataclass(frozen=True)
class command:
    command_id: str
    action: str
    arguments: dict[str, Any]
    signature: str


class c2_controller:
    """queue a small set of signed demo tasks for the local agent."""

    allowed_actions = {"status", "inventory", "hash_file"}

    def __init__(self, secret: bytes, logger: Any) -> None:
        if not secret:
            raise ValueError("the signing secret cannot be empty")

        self._secret = secret
        self.logger = logger
        self._queue: Queue[command] = Queue()

    def _sign(self, payload: dict[str, Any]) -> str:
        message = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def beacon(self, agent_id: str) -> None:
        # this is just an event in the local log, not a network heartbeat
        self.logger.emit(
            "c2",
            "c2.beacon",
            agent_id=agent_id,
            transport="in_memory",
        )

    def dispatch(
        self,
        action: str,
        arguments: dict[str, Any] | None = None,
    ) -> command:
        if action not in self.allowed_actions:
            raise ValueError("that demo command is not allowed")

        payload = {
            "command_id": secrets.token_hex(8),
            "action": action,
            "arguments": arguments or {},
        }
        item = command(**payload, signature=self._sign(payload))
        self._queue.put(item)
        self.logger.emit(
            "c2",
            "c2.command_queued",
            command_action=action,
            command_id=item.command_id,
        )
        return item

    def next_command(self) -> command | None:
        try:
            return self._queue.get_nowait()
        except Empty:
            return None

    def verify(self, item: command) -> bool:
        payload = {
            "command_id": item.command_id,
            "action": item.action,
            "arguments": item.arguments,
        }
        expected = self._sign(payload)
        return hmac.compare_digest(expected, item.signature)


class c2_agent:
    """handle the controller's allowlisted tasks against the demo workspace."""

    def __init__(
        self,
        agent_id: str,
        workspace: Path,
        controller: c2_controller,
        logger: Any,
    ) -> None:
        self.agent_id = agent_id
        self.workspace = workspace.resolve()
        self.controller = controller
        self.logger = logger

    def poll(self) -> Iterator[dict[str, Any]]:
        while (item := self.controller.next_command()) is not None:
            if not self.controller.verify(item):
                self.logger.emit(
                    "c2",
                    "c2.bad_signature",
                    "alert",
                    command_id=item.command_id,
                )
                continue

            scanner = file_intel(self.workspace, self.logger)

            if item.action == "status":
                result = {
                    "agent_id": self.agent_id,
                    "state": "simulated_online",
                }
            elif item.action == "inventory":
                result = scanner.inventory()
            elif item.action == "hash_file":
                relative_path = str(item.arguments.get("path", ""))
                result = scanner.fingerprint(scanner.safe_path(relative_path))
            else:
                # keep this check too in case a command is changed after validation
                self.logger.emit(
                    "c2",
                    "c2.blocked_action",
                    "alert",
                    blocked_action=item.action,
                )
                continue

            self.logger.emit(
                "c2",
                "c2.command_completed",
                command_action=item.action,
                command_id=item.command_id,
            )
            yield {
                "command_id": item.command_id,
                "action": item.action,
                "result": result,
            }
