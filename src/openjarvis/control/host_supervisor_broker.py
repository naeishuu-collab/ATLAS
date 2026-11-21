"""Host-owned, loopback-only authenticated broker for one synthetic task.

The embedding host issues each one-use session over a separate confidential
channel and independently authorizes the bound principal and task. A socket
session proves possession of its key, not the caller's OS process identity.
"""

from __future__ import annotations

import base64
import json
import math
import os
import secrets
import select
import socket
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from openjarvis.agents.manager import AgentManager
from openjarvis.control.host_task_supervisor import (
    HostTaskSupervisorProcess,
    verify_signed_exit_record,
)
from openjarvis.control.task_worker import TaskWorkerExecutionError
from openjarvis.control.task_worker_ipc import TaskWorkerChannel
from openjarvis.control.windows_peer import process_identity, tcp_peer_process_identity
from openjarvis.core.types import ToolCall, ToolResult

_LIMIT = 131072


def _send(stream: Any, obj: Mapping[str, Any]) -> None:
    raw = json.dumps(obj, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > _LIMIT:
        raise PermissionError("supervisor message too large")
    remaining = memoryview(raw + b"\n")
    while remaining:
        written = stream.write(remaining)
        if not isinstance(written, int) or written <= 0:
            raise OSError("supervisor connection write failed")
        remaining = remaining[written:]


def _read(stream: Any) -> dict[str, Any]:
    line = stream.readline(_LIMIT + 1)
    if not line or len(line) > _LIMIT or not line.endswith(b"\n"):
        raise EOFError("supervisor connection closed")
    result = json.loads(line)
    if not isinstance(result, dict):
        raise PermissionError("supervisor message invalid")
    return result


def _seal(
    channel: TaskWorkerChannel,
    kind: str,
    request: str,
    call: str,
    deadline: float,
    payload: Mapping[str, Any],
) -> bytes:
    return channel.seal(
        kind,
        message_id=uuid.uuid4().hex,
        request_id=request,
        tool_call_id=call,
        deadline=deadline,
        cancellation="ACTIVE",
        payload=payload,
    )


class HostSupervisorBroker:
    """Own one supervisor; host callbacks must independently enforce authority."""

    def __init__(
        self,
        authorize: Callable[[Mapping[str, Any], Mapping[str, Any]], bool],
        manager: AgentManager,
        principal: Any,
        authority: Any,
        *,
        integrity_key: bytes,
    ) -> None:
        if (
            not callable(authorize)
            or not isinstance(manager, AgentManager)
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
        ):
            raise ValueError("host authorization callbacks required")
        self._authorize = authorize
        self._manager = manager
        self._principal = principal
        self._authority = authority
        self._integrity_key = integrity_key
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(4)
        self._socket.settimeout(0.2)
        self.address = self._socket.getsockname()
        self._lock = threading.Lock()
        self._active_conn: socket.socket | None = None
        self._grants: dict[str, dict[str, Any]] = {}
        self._closed = threading.Event()
        self.disconnected = threading.Event()
        self.supervisor_lost = threading.Event()
        self.supervisor: HostTaskSupervisorProcess | None = None
        self.binding: dict[str, Any] | None = None
        self.unknown_outcome = False
        self._close_complete = False
        self._cleanup_unconfirmed = False
        self._cleanup_error: Exception | None = None
        self.tool_dispatch_count = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def issue(
        self,
        *,
        role: str,
        task_id: str,
        agent_id: str,
        principal_id: str,
        expires_at: float,
        client_pid: int | None = None,
    ) -> dict[str, Any]:
        """Trusted host only; return the key through a confidential host channel."""
        if client_pid is not None and (type(client_pid) is not int or client_pid <= 0):
            raise ValueError("host supervisor client process invalid")
        if (
            role not in {"controller", "observer"}
            or not task_id
            or not agent_id
            or not principal_id
            or type(expires_at) not in (int, float)
            or not math.isfinite(expires_at)
            or expires_at <= time.time()
        ):
            raise ValueError("host supervisor grant invalid")
        if role == "observer" and not self.disconnected.is_set():
            raise PermissionError("old controller has not disconnected")
        session_id, key = uuid.uuid4().hex, secrets.token_bytes(32)
        client_identity = process_identity(
            os.getpid() if client_pid is None else client_pid
        )
        grant = {
            "session_id": session_id,
            "key": key,
            "role": role,
            "task_id": task_id,
            "agent_id": agent_id,
            "principal_id": principal_id,
            "expires_at": expires_at,
            "client_identity": client_identity,
            "used": False,
        }
        with self._lock:
            self._grants[session_id] = grant
        return {**grant, "address": self.address}

    def _validate(self, grant: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
        if (
            time.time() >= grant["expires_at"]
            or any(
                grant[name] != binding.get(name)
                for name in ("task_id", "agent_id", "principal_id")
            )
            or binding.get("principal_id") != self._principal.principal_id
            or self._authorize(grant, binding) is not True
        ):
            raise PermissionError("host supervisor grant denied")
        self._manager.validate_host_task_binding(
            self._principal, self._authority, dict(binding)
        )

    def _validate_live_controller(
        self, conn: socket.socket, grant: Mapping[str, Any], binding: Mapping[str, Any]
    ) -> None:
        self._validate_peer(conn, grant)
        readable, _, exceptional = select.select([conn], [], [conn], 0)
        # No pipelining is allowed while a worker operation is in flight.
        if readable or exceptional:
            raise PermissionError("controller disconnected or sent an unexpected frame")
        self._validate(grant, binding)

    @staticmethod
    def _validate_peer(conn: socket.socket, grant: Mapping[str, Any]) -> None:
        try:
            actual = tcp_peer_process_identity(conn)
        except Exception:
            raise PermissionError("host OS peer identity unavailable") from None
        if actual != grant.get("client_identity"):
            raise PermissionError("host OS peer identity mismatch")

    def _read_live(
        self,
        conn: socket.socket,
        stream: Any,
        grant: Mapping[str, Any],
        binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        while not self._closed.is_set() and not self.supervisor_lost.is_set():
            # shortcut: polling is per session; use host revocation events at scale.
            self._validate(grant, binding)
            readable, _, _ = select.select([conn], [], [], 0.2)
            if readable:
                return _read(stream)
        raise EOFError("supervisor is unavailable")

    def _watch_supervisor(self, supervisor: HostTaskSupervisorProcess) -> None:
        exit_code = supervisor._process.wait()
        if not supervisor._shutdown_requested or exit_code != 0:
            self.unknown_outcome = True
            self.supervisor_lost.set()
            with self._lock:
                if self._active_conn is not None:
                    try:
                        self._active_conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    def _run(self) -> None:
        while not self._closed.is_set():
            try:
                conn, peer = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if peer[0] != "127.0.0.1":
                conn.close()
                continue
            with self._lock:
                self._active_conn = conn
            self._serve(conn)
            with self._lock:
                self._active_conn = None

    def _serve(self, conn: socket.socket) -> None:
        grant = None
        controller_authenticated = False
        try:
            conn.settimeout(5)
            with conn, conn.makefile("rwb", buffering=0) as stream:
                outer = _read(stream)
                if set(outer) != {"session_id", "binding", "frame"}:
                    raise PermissionError("supervisor handshake invalid")
                with self._lock:
                    grant = self._grants.get(outer["session_id"])
                    if grant is None or grant["used"]:
                        raise PermissionError("supervisor session unavailable")
                    grant["used"] = True
                self._validate_peer(conn, grant)
                binding = outer["binding"]
                if not isinstance(binding, dict):
                    raise PermissionError("supervisor binding invalid")
                channel = TaskWorkerChannel(grant["key"], binding, role="worker")
                body = channel.open(base64.b64decode(outer["frame"], validate=True))
                if body["kind"] != "AUTHENTICATE":
                    raise PermissionError("supervisor authentication required")
                self._validate(grant, binding)
                if grant["role"] == "observer" and (
                    self.binding != binding or not self.disconnected.is_set()
                ):
                    raise PermissionError("supervisor observer binding invalid")
                if grant["role"] == "controller" and self.supervisor is not None:
                    raise PermissionError("supervisor already has an owner")
                controller_authenticated = grant["role"] == "controller"
                _send(
                    stream,
                    {
                        "frame": base64.b64encode(
                            _seal(
                                channel,
                                "AUTHENTICATE",
                                body["request_id"],
                                body["tool_call_id"],
                                body["deadline"],
                                {"authenticated": True},
                            )
                        ).decode("ascii")
                    },
                )
                while not self._closed.is_set():
                    packet = self._read_live(conn, stream, grant, binding)
                    if set(packet) != {"frame"}:
                        raise PermissionError("supervisor frame invalid")
                    body = channel.open(
                        base64.b64decode(packet["frame"], validate=True)
                    )
                    self._validate(grant, binding)
                    kind, data = body["kind"], body["payload"]
                    if kind == "START" and data == {"op": "start"}:
                        if grant["role"] != "controller" or self.supervisor is not None:
                            raise PermissionError("supervisor start denied")
                        self.binding = dict(binding)
                        self.supervisor = HostTaskSupervisorProcess(
                            binding,
                            validate_authority=lambda: self._validate_live_controller(
                                conn, grant, binding
                            ),
                        )
                        self.supervisor.start()
                        threading.Thread(
                            target=self._watch_supervisor,
                            args=(self.supervisor,),
                            daemon=True,
                        ).start()
                        reply, payload = (
                            "AUTHENTICATE",
                            {
                                "supervisor_pid": self.supervisor.pid,
                                "evidence": self.supervisor.evidence,
                            },
                        )
                    elif kind == "EXECUTE_TOOL" and grant["role"] == "controller":
                        if self.supervisor is None:
                            raise PermissionError("supervisor unavailable")
                        call = ToolCall(body["tool_call_id"], data["name"], "{}")
                        self._manager.claim_task_tool_dispatch(
                            self._principal,
                            self._authority,
                            binding,
                            body,
                            integrity_key=self._integrity_key,
                        )
                        self._validate_live_controller(conn, grant, binding)
                        self.tool_dispatch_count += 1
                        result = self.supervisor.execute_tool(
                            call,
                            data["params"],
                            timeout=body["deadline"] - time.time(),
                            request_id=body["request_id"],
                            deadline=body["deadline"],
                            checkpoint_version=data["checkpoint_version"],
                        )
                        reply, payload = (
                            "TOOL_RESULT",
                            {
                                "name": result.tool_name,
                                "content": result.content,
                                "success": result.success,
                                "evidence": self.supervisor.evidence,
                            },
                        )
                    elif kind == "SHUTDOWN" and grant["role"] == "controller":
                        if self.supervisor is None:
                            raise PermissionError("supervisor unavailable")
                        self.supervisor.close()
                        reply, payload = "EXIT", {"evidence": self.supervisor.evidence}
                    elif kind == "START" and data == {"op": "verify_exit"}:
                        if self.supervisor is None or grant["role"] != "controller":
                            raise PermissionError("supervisor verification denied")
                        reply, payload = (
                            "AUTHENTICATE",
                            {
                                "verified": self.supervisor.verify_exit_evidence(
                                    self.supervisor.evidence
                                ),
                                "evidence": self.supervisor.evidence,
                            },
                        )
                    elif kind == "START" and data == {"op": "evidence"}:
                        if (
                            grant["role"] != "observer"
                            or self.supervisor is None
                            or not self.supervisor.verify_exit_evidence(
                                self.supervisor.evidence
                            )
                        ):
                            raise PermissionError("supervisor exit is unverified")
                        durable = self._manager.read_host_worker_exit(
                            self._principal,
                            self._authority,
                            binding,
                            self.supervisor.evidence_verification_key,
                            integrity_key=self._integrity_key,
                        )
                        if durable != self.supervisor.exit_record:
                            raise PermissionError("supervisor durable exit mismatch")
                        reply, payload = (
                            "AUTHENTICATE",
                            {
                                "record": self.supervisor.exit_record,
                                "os_verified": True,
                                "supervisor_pid": self.supervisor.pid,
                            },
                        )
                    else:
                        raise PermissionError("supervisor operation denied")
                    _send(
                        stream,
                        {
                            "frame": base64.b64encode(
                                _seal(
                                    channel,
                                    reply,
                                    body["request_id"],
                                    body["tool_call_id"],
                                    body["deadline"],
                                    payload,
                                )
                            ).decode("ascii")
                        },
                    )
        except TaskWorkerExecutionError as exc:
            if exc.unknown_outcome:
                self.unknown_outcome = True
        except Exception:
            pass
        finally:
            if controller_authenticated and self.supervisor is not None:
                if not self.supervisor._closed and not self.supervisor._worker_stopped:
                    try:
                        self.supervisor.stop_worker()
                    except Exception:
                        self.unknown_outcome = True
                        try:
                            self.supervisor._abort()
                        except Exception:
                            self.unknown_outcome = True
                if (
                    not self.supervisor._closed
                    and self.supervisor._worker_stopped
                    and self.binding is not None
                ):
                    try:
                        self._manager.record_host_worker_exit(
                            self._principal,
                            self._authority,
                            self.binding,
                            self.supervisor.exit_record,
                            self.supervisor.evidence_verification_key,
                            integrity_key=self._integrity_key,
                            verify_os_exit=self.supervisor.verify_exit_evidence,
                        )
                    except Exception:
                        self.unknown_outcome = True
                self.disconnected.set()

    def close(self) -> None:
        if self._close_complete:
            return
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_BROKER_CLEANUP_UNCONFIRMED",
                unknown_outcome=True,
            ) from self._cleanup_error
        self._closed.set()
        try:
            self._socket.close()
            with self._lock:
                active_conn = self._active_conn
            if active_conn is not None:
                try:
                    active_conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise TimeoutError("Host Supervisor broker thread did not stop")
            if self.supervisor is not None:
                self.supervisor.close()
                if not self.supervisor._closed:
                    raise RuntimeError("Host Supervisor process cleanup is unconfirmed")
            self._close_complete = True
        except Exception as exc:
            self.unknown_outcome = True
            self._cleanup_unconfirmed = True
            self._cleanup_error = exc
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_BROKER_CLEANUP_UNCONFIRMED",
                unknown_outcome=True,
            ) from exc


class HostSupervisorClient:
    """Controller endpoint for one host-issued session, with no unsafe fallback."""

    def __init__(
        self,
        grant: Mapping[str, Any],
        binding: Mapping[str, Any],
        *,
        validate_authority: Callable[[], Any],
    ) -> None:
        self.binding = dict(binding)
        self._validate_authority = validate_authority
        self._channel = TaskWorkerChannel(grant["key"], self.binding, role="host")
        self._session_id = grant["session_id"]
        self._socket = socket.create_connection(tuple(grant["address"]), timeout=5)
        self._socket.settimeout(60)
        self._stream = self._socket.makefile("rwb", buffering=0)
        self._lock = threading.Lock()
        self._evidence: dict[str, Any] = {}
        self._closed = False
        request, deadline = (
            uuid.uuid4().hex,
            min(time.time() + 5, binding["lease_expires_at"]),
        )
        try:
            frame = _seal(self._channel, "AUTHENTICATE", request, "auth", deadline, {})
            _send(
                self._stream,
                {
                    "session_id": self._session_id,
                    "binding": self.binding,
                    "frame": base64.b64encode(frame).decode("ascii"),
                },
            )
            response = self._open(_read(self._stream), request, "auth")
            if response["kind"] != "AUTHENTICATE" or response["payload"] != {
                "authenticated": True
            }:
                raise PermissionError("host supervisor authentication failed")
        except Exception:
            self.release_exit_evidence()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_AUTH_FAILED") from None

    def _open(
        self, packet: Mapping[str, Any], request: str, call: str
    ) -> dict[str, Any]:
        if set(packet) != {"frame"}:
            raise PermissionError("host supervisor response invalid")
        body = self._channel.open(base64.b64decode(packet["frame"], validate=True))
        if body["request_id"] != request or body["tool_call_id"] != call:
            raise PermissionError("host supervisor response mismatch")
        return body

    def _request(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        timeout: float,
        request: str | None = None,
        call: str = "control",
        deadline: float | None = None,
        check_local_authority: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            if self._closed:
                raise TaskWorkerExecutionError("HOST_SUPERVISOR_UNAVAILABLE")
            request = request or uuid.uuid4().hex
            deadline = min(
                deadline or time.time() + timeout,
                time.time() + timeout,
                self.binding["lease_expires_at"],
            )
            try:
                if check_local_authority:
                    self._validate_authority()
                self._socket.settimeout(max(0.01, deadline - time.time()))
                frame = _seal(self._channel, kind, request, call, deadline, payload)
                _send(self._stream, {"frame": base64.b64encode(frame).decode("ascii")})
                response = self._open(_read(self._stream), request, call)
                if check_local_authority:
                    self._validate_authority()
                return response
            except Exception:
                self.release_exit_evidence()
                raise TaskWorkerExecutionError(
                    "HOST_SUPERVISOR_OUTCOME_UNKNOWN"
                    if kind == "EXECUTE_TOOL"
                    else "HOST_SUPERVISOR_REQUEST_FAILED",
                    unknown_outcome=kind == "EXECUTE_TOOL",
                ) from None

    @property
    def evidence(self) -> dict[str, Any]:
        return dict(self._evidence)

    def start(self) -> None:
        response = self._request("START", {"op": "start"}, timeout=15)
        if response["kind"] != "AUTHENTICATE":
            raise PermissionError("host supervisor start rejected")
        self._evidence = dict(response["payload"]["evidence"])

    def execute_tool(
        self,
        tool_call: ToolCall,
        params: Mapping[str, Any],
        *,
        timeout: float,
        request_id: str,
        deadline: float,
        checkpoint_version: int,
    ) -> ToolResult:
        if tool_call.name != "synthetic_echo":
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_TOOL_NOT_ALLOWED")
        response = self._request(
            "EXECUTE_TOOL",
            {
                "name": tool_call.name,
                "params": dict(params),
                "checkpoint_version": checkpoint_version,
            },
            timeout=timeout,
            request=request_id,
            call=tool_call.id,
            deadline=deadline,
        )
        payload = response["payload"]
        if (
            response["kind"] != "TOOL_RESULT"
            or payload.get("name") != tool_call.name
            or type(payload.get("success")) is not bool
            or not isinstance(payload.get("content"), str)
        ):
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_RESULT_INVALID", unknown_outcome=True
            )
        self._evidence = dict(payload["evidence"])
        return ToolResult(
            tool_name=tool_call.name,
            content=payload["content"],
            success=payload["success"],
            metadata={"worker_execution": self.evidence},
        )

    def close(self) -> None:
        response = self._request("SHUTDOWN", {}, timeout=10)
        if response["kind"] != "EXIT":
            raise PermissionError("host supervisor shutdown rejected")
        self._evidence = dict(response["payload"]["evidence"])

    def verify_exit_evidence(self, evidence: Mapping[str, Any]) -> bool:
        try:
            # Completion already stopped its heartbeat; the host and manager
            # independently validate authority around this read-only query.
            response = self._request(
                "START", {"op": "verify_exit"}, timeout=5, check_local_authority=False
            )
            return (
                response["kind"] == "AUTHENTICATE"
                and response["payload"].get("verified") is True
                and response["payload"].get("evidence") == dict(evidence)
            )
        except Exception:
            return False

    def read_exit_evidence(self, verification_key: bytes) -> dict[str, Any]:
        response = self._request("START", {"op": "evidence"}, timeout=5)
        payload = response["payload"]
        if (
            response["kind"] != "AUTHENTICATE"
            or payload.get("os_verified") is not True
            or not verify_signed_exit_record(
                payload.get("record", {}), verification_key, self.binding
            )
            or payload["record"]["record"]["supervisor_pid"]
            != payload.get("supervisor_pid")
        ):
            raise PermissionError("host supervisor exit evidence invalid")
        return payload["record"]

    def release_exit_evidence(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._stream.close()
            finally:
                self._socket.close()
