"""Authenticated, per-worker message framing; not a source of task authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
from collections.abc import Mapping
from typing import Any

_MAX_FRAME = 65536
_BINDING_KEYS = frozenset(
    {
        "worker_id",
        "supervisor_id",
        "task_id",
        "agent_id",
        "principal_id",
        "attempt",
        "owner_hash",
        "epoch",
        "checkpoint_version",
        "lease_expires_at",
    }
)
_BODY_KEYS = frozenset(
    {
        "version",
        "binding",
        "sender",
        "sequence",
        "kind",
        "message_id",
        "request_id",
        "tool_call_id",
        "deadline",
        "cancellation",
        "payload",
    }
)
_KINDS = {
    "host": frozenset({"START", "AUTHENTICATE", "EXECUTE_TOOL", "CANCEL", "SHUTDOWN"}),
    "worker": frozenset(
        {"AUTHENTICATE", "TOOL_RESULT", "CHECKPOINT", "HEARTBEAT", "EXIT"}
    ),
}


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=True,
    ).encode("ascii")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate IPC field")
        result[key] = value
    return result


def _identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and bool(value.strip())
        and value.isprintable()
    )


def _timestamp(value: Any) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


class TaskWorkerChannel:
    """Bind one fresh shared key and one live worker to both IPC directions.

    The host must independently verify authority and sessions before dispatch.
    A new random key and worker identity are required after every restart.
    Both peers know the key, so a valid MAC does not make a worker trustworthy.
    """

    def __init__(self, key: bytes, binding: Mapping[str, Any], *, role: str):
        if not isinstance(key, bytes) or len(key) < 32 or role not in _KINDS:
            raise ValueError("invalid IPC channel configuration")
        if not isinstance(binding, Mapping) or set(binding) != _BINDING_KEYS:
            raise ValueError("invalid IPC worker binding")
        binding = dict(binding)
        for name in (
            "worker_id",
            "supervisor_id",
            "task_id",
            "agent_id",
            "principal_id",
            "attempt",
        ):
            if not _identifier(binding[name]):
                raise ValueError("invalid IPC worker binding")
        owner_hash = binding["owner_hash"]
        if (
            not isinstance(owner_hash, str)
            or len(owner_hash) != 64
            or any(c not in "0123456789abcdef" for c in owner_hash)
            or type(binding["epoch"]) is not int
            or binding["epoch"] < 1
            or type(binding["checkpoint_version"]) is not int
            or binding["checkpoint_version"] < 0
            or not _timestamp(binding["lease_expires_at"])
            or binding["lease_expires_at"] <= 0
        ):
            raise ValueError("invalid IPC worker binding")
        self._key = key
        self._binding = binding
        self._role = role
        self._sent = 0
        self._received = 0
        # shortcut: replay state is process-local, add durable state before recovery.
        self._seen: set[str] = set()
        self._requests: set[str] = set()
        self._calls: set[str] = set()
        self._pending: dict[str, tuple[str, int | float]] = {}
        self._failed = False
        self._lock = threading.Lock()

    def seal(
        self,
        kind: str,
        *,
        message_id: str,
        request_id: str,
        tool_call_id: str,
        deadline: int | float,
        cancellation: str,
        payload: Mapping[str, Any],
    ) -> bytes:
        with self._lock:
            if self._failed:
                raise PermissionError("IPC channel is closed")
            body = {
                "version": 1,
                "binding": self._binding,
                "sender": self._role,
                "sequence": self._sent + 1,
                "kind": kind,
                "message_id": message_id,
                "request_id": request_id,
                "tool_call_id": tool_call_id,
                "deadline": deadline,
                "cancellation": cancellation,
                "payload": dict(payload),
            }
            self._validate(body, self._role)
            self._check_flow(body)
            raw = _canonical(body)
            mac = hmac.new(self._key, b"atlas-task-ipc-v1\0" + raw, hashlib.sha256)
            frame = _canonical({"body": body, "mac": mac.hexdigest()})
            if len(frame) > _MAX_FRAME:
                raise ValueError("IPC frame exceeds limit")
            self._sent += 1
            self._record_flow(body)
            return frame

    def open(self, frame: bytes) -> dict[str, Any]:
        with self._lock:
            if self._failed:
                raise PermissionError("IPC channel is closed")
            try:
                if not isinstance(frame, bytes) or not 0 < len(frame) <= _MAX_FRAME:
                    raise ValueError("invalid IPC frame")
                envelope = json.loads(
                    frame,
                    object_pairs_hook=_object,
                    parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
                )
                if not isinstance(envelope, dict) or set(envelope) != {"body", "mac"}:
                    raise ValueError("invalid IPC envelope")
                body, received = envelope["body"], envelope["mac"]
                sender = "worker" if self._role == "host" else "host"
                self._validate(body, sender)
                expected = hmac.new(
                    self._key, b"atlas-task-ipc-v1\0" + _canonical(body), hashlib.sha256
                ).hexdigest()
                if not isinstance(received, str) or not hmac.compare_digest(
                    expected, received
                ):
                    raise ValueError("invalid IPC authentication")
                if (
                    body["sequence"] != self._received + 1
                    or body["message_id"] in self._seen
                ):
                    raise ValueError("IPC replay or ordering mismatch")
                self._check_flow(body)
                self._received += 1
                self._seen.add(body["message_id"])
                self._record_flow(body)
                return body
            except (
                ValueError,
                TypeError,
                KeyError,
                UnicodeError,
                RecursionError,
            ) as exc:
                self._failed = True
                raise PermissionError("IPC frame rejected") from exc

    def _check_flow(self, body: dict[str, Any]) -> None:
        request, call = body["request_id"], body["tool_call_id"]
        if body["kind"] == "EXECUTE_TOOL":
            if request in self._requests or call in self._calls:
                raise ValueError("IPC tool call replay")
        elif body["kind"] == "TOOL_RESULT":
            pending = self._pending.get(request)
            if pending is None or pending[0] != call or body["deadline"] > pending[1]:
                raise ValueError("IPC result does not match a request")

    def _record_flow(self, body: dict[str, Any]) -> None:
        request, call = body["request_id"], body["tool_call_id"]
        if body["kind"] == "EXECUTE_TOOL":
            self._requests.add(request)
            self._calls.add(call)
            self._pending[request] = (call, body["deadline"])
        elif body["kind"] == "TOOL_RESULT":
            del self._pending[request]

    def _validate(self, body: Any, sender: str) -> None:
        if (
            not isinstance(body, dict)
            or set(body) != _BODY_KEYS
            or type(body["version"]) is not int
            or body["version"] != 1
            or _canonical(body["binding"]) != _canonical(self._binding)
            or body["sender"] != sender
            or type(body["sequence"]) is not int
            or body["sequence"] < 1
            or body["kind"] not in _KINDS[sender]
            or not all(
                _identifier(body[k])
                for k in ("message_id", "request_id", "tool_call_id")
            )
            or not _timestamp(body["deadline"])
            or body["deadline"] > self._binding["lease_expires_at"]
            or body["deadline"] <= time.time()
            or body["cancellation"] not in {"ACTIVE", "CANCELLED"}
            or (body["kind"] == "EXECUTE_TOOL" and body["cancellation"] != "ACTIVE")
            or not isinstance(body["payload"], dict)
        ):
            raise ValueError("invalid IPC message")
