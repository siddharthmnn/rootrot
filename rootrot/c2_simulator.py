"""simulate a small authenticated task queue without sockets or remote execution."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from math import isfinite as time_finite
from pathlib import Path, PureWindowsPath
from queue import Empty, Full, Queue
from threading import Lock
from typing import Any, Callable, Iterator

from .file_intel import file_intel


@dataclass(frozen=True)
class command:
    command_id: str
    action: str
    arguments: dict[str, Any]
    issued_at: float
    expires_at: float
    signature: str


class c2_controller:
    """queue a bounded set of signed demo tasks for the local agent."""

    allowed_actions = {"status", "inventory", "hash_file"}
    max_argument_bytes = 4096
    max_path_length = 512
    max_commands_per_run = 4096

    def __init__(
        self,
        secret: bytes,
        logger: Any,
        command_ttl_seconds: float = 60.0,
        max_queue_size: int = 64,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("the signing secret cannot be empty")
        if (
            isinstance(command_ttl_seconds, bool)
            or not isinstance(command_ttl_seconds, (int, float))
            or not 1 <= command_ttl_seconds <= 3600
        ):
            raise ValueError("command_ttl_seconds must be between 1 and 3600")
        if (
            isinstance(max_queue_size, bool)
            or not isinstance(max_queue_size, int)
            or not 1 <= max_queue_size <= 1024
        ):
            raise ValueError("max_queue_size must be between 1 and 1024")
        if not callable(clock):
            raise TypeError("clock must be callable")

        self._secret = secret
        self.logger = logger
        self.command_ttl_seconds = float(command_ttl_seconds)
        self._clock = clock
        self._queue: Queue[command] = Queue(maxsize=max_queue_size)
        self._statuses: dict[str, str] = {}
        self._claimed_ids: set[str] = set()
        self._dispatched_count = 0
        self._state_lock = Lock()

    @staticmethod
    def _payload(item: command) -> dict[str, Any]:
        return {
            "command_id": item.command_id,
            "action": item.action,
            "arguments": item.arguments,
            "issued_at": item.issued_at,
            "expires_at": item.expires_at,
        }

    def _sign(self, payload: dict[str, Any]) -> str:
        message = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def _validate_arguments(self, action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(arguments, dict):
            raise ValueError("command arguments must be an object")
        expected = {
            "hash_file": {"path"},
            "status": set(),
            "inventory": set(),
        }[action]
        if set(arguments) != expected:
            raise ValueError(f"invalid arguments for command '{action}'")

        clean = dict(arguments)
        if action == "hash_file":
            path = clean["path"]
            if (
                not isinstance(path, str)
                or not path
                or len(path) > self.max_path_length
                or "\x00" in path
                or "\\" in path
            ):
                raise ValueError("hash_file requires a valid relative path")
            path_obj = Path(path)
            if (
                path_obj.is_absolute()
                or PureWindowsPath(path).is_absolute()
                or ".." in path_obj.parts
                or ".." in PureWindowsPath(path).parts
            ):
                raise ValueError("hash_file path must stay inside the demo workspace")

        try:
            encoded = json.dumps(
                clean,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("command arguments must contain valid json values") from exc
        if len(encoded) > self.max_argument_bytes:
            raise ValueError("command arguments exceed the configured size limit")
        return clean

    def _set_status(self, item: command, status: str, **details: Any) -> None:
        with self._state_lock:
            self._statuses[item.command_id] = status
        severity = {
            "failed": "error",
            "rejected": "warning",
            "expired": "warning",
        }.get(status, "info")
        self.logger.emit(
            "c2",
            "c2.command_status",
            severity,
            command_id=item.command_id,
            command_action=item.action,
            status=status,
            **details,
        )

    def command_status(self, command_id: str) -> str | None:
        with self._state_lock:
            return self._statuses.get(command_id)

    def claim(self, item: command) -> bool:
        with self._state_lock:
            if item.command_id in self._claimed_ids:
                return False
            self._claimed_ids.add(item.command_id)
            return True

    def beacon(self, agent_id: str) -> None:
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
        clean_arguments = self._validate_arguments(
            action,
            arguments if arguments is not None else {},
        )
        issued_at = self._clock()
        if (
            not isinstance(issued_at, (int, float))
            or isinstance(issued_at, bool)
            or not time_finite(issued_at)
        ):
            raise ValueError("the configured clock returned an invalid timestamp")

        with self._state_lock:
            if self._dispatched_count >= self.max_commands_per_run:
                raise RuntimeError("the local command limit has been reached")
            self._dispatched_count += 1

        expires_at = issued_at + self.command_ttl_seconds
        payload = {
            "command_id": secrets.token_hex(8),
            "action": action,
            "arguments": clean_arguments,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        item = command(**payload, signature=self._sign(payload))
        try:
            self._queue.put_nowait(item)
        except Full as exc:
            self.logger.emit(
                "c2",
                "c2.queue_full",
                "warning",
                queue_limit=self._queue.maxsize,
            )
            raise RuntimeError("the local command queue is full") from exc

        self._set_status(item, "queued")
        self.logger.emit(
            "c2",
            "c2.command_queued",
            command_action=action,
            command_id=item.command_id,
            expires_at=expires_at,
        )
        return item

    def next_command(self) -> command | None:
        try:
            item = self._queue.get_nowait()
        except Empty:
            return None
        if self.command_status(item.command_id) == "queued":
            self._set_status(item, "running")
        return item

    def verify(self, item: command) -> bool:
        if item.action not in self.allowed_actions or item.expires_at <= item.issued_at:
            return False
        try:
            expected = self._sign(self._payload(item))
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(expected, item.signature)


class c2_agent:
    """handle allowlisted tasks against the local demo workspace."""

    def __init__(
        self,
        agent_id: str,
        workspace: Path,
        controller: c2_controller,
        logger: Any,
    ) -> None:
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id must be a non-empty string")
        self.agent_id = agent_id
        self.workspace = Path(workspace).resolve()
        self.controller = controller
        self.logger = logger

    def poll(self) -> Iterator[dict[str, Any]]:
        while (item := self.controller.next_command()) is not None:
            if not self.controller.verify(item):
                self.controller._set_status(item, "rejected", reason="invalid_signature")
                self.logger.emit(
                    "c2",
                    "c2.bad_signature",
                    "alert",
                    command_id=item.command_id,
                )
                continue
            if self.controller._clock() > item.expires_at:
                self.controller._set_status(item, "expired", reason="command_ttl_elapsed")
                self.logger.emit(
                    "c2",
                    "c2.command_expired",
                    "warning",
                    command_id=item.command_id,
                )
                continue
            if not self.controller.claim(item):
                self.controller._set_status(item, "rejected", reason="replayed_command")
                self.logger.emit(
                    "c2",
                    "c2.command_replayed",
                    "alert",
                    command_id=item.command_id,
                )
                continue

            scanner = file_intel(self.workspace, self.logger)
            try:
                if item.action == "status":
                    result = {
                        "agent_id": self.agent_id,
                        "state": "simulated_online",
                    }
                elif item.action == "inventory":
                    result = scanner.inventory()
                elif item.action == "hash_file":
                    relative_path = item.arguments["path"]
                    result = scanner.fingerprint(scanner.safe_path(relative_path))
                else:
                    raise ValueError("blocked command action")
            except Exception as exc:
                self.controller._set_status(
                    item,
                    "failed",
                    error_type=type(exc).__name__,
                )
                self.logger.emit(
                    "c2",
                    "c2.command_failed",
                    "error",
                    command_id=item.command_id,
                    error_type=type(exc).__name__,
                )
                raise

            self.controller._set_status(item, "completed")
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
