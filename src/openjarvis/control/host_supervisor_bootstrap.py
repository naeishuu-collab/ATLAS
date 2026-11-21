"""Windows Host-owned Broker bootstrap and authenticated Controller grants."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Mapping

from openjarvis.control.windows_named_pipe import (
    NamedPipeServer,
    connect_named_pipe,
)
from openjarvis.control.windows_peer import is_process_descendant, process_identity
from openjarvis.security.host_principal import (
    HostPrincipalAuthority,
    HostPrincipalCredential,
)

_HOST_SESSION_TTL = 12 * 60 * 60
_MAX_CONTROL_LINE = 4096


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _mac(key: bytes, purpose: bytes, value: Mapping[str, Any]) -> str:
    return hmac.new(
        key, purpose + b"\0" + _json_bytes(value), hashlib.sha256
    ).hexdigest()


@dataclass
class _ControllerSession:
    session_id: str
    identity: dict[str, int | str]
    credential: HostPrincipalCredential
    principal: Any
    api_key: bytes
    used_requests: set[str] = field(default_factory=set)
    active: bool = True


@dataclass
class _BrokerRecord:
    task_id: str
    agent_id: str
    session_id: str
    principal: Any
    authority: HostPrincipalAuthority
    binding: dict[str, Any]
    broker: Any
    observer_session_id: str | None = None


class HostSupervisorBootstrapClient:
    """Controller-side client; Host and pipe server identity are pinned at boot."""

    def __init__(
        self,
        pipe_name: str,
        *,
        supervisor_pid: int,
        supervisor_created_filetime: int,
    ) -> None:
        self.pipe_name = pipe_name
        self.supervisor_pid = supervisor_pid
        self.supervisor_created_filetime = supervisor_created_filetime
        self.authority: HostPrincipalAuthority | None = None
        self.principal: Any = None
        self.session_id = ""
        self.integrity_key = b""
        self._api_key = b""
        self._lock = threading.Lock()

    @property
    def principal_context(self) -> Any:
        if self.principal is None or not self.session_id:
            raise PermissionError("Host Controller is not bootstrapped")
        return SimpleNamespace(principal=self.principal, session_id=self.session_id)

    def bootstrap(self, *, timeout: float = 20.0) -> HostSupervisorBootstrapClient:
        if os.name != "nt":
            raise PermissionError("Windows Host bootstrap is unavailable")
        deadline = time.monotonic() + timeout
        while True:
            try:
                with self._connect() as pipe:
                    pipe.send({"operation": "BOOTSTRAP"})
                    response = pipe.receive()
                if response.get("ok") is not True:
                    if response.get("detail") != "HOST_CONTROLLER_NOT_REGISTERED":
                        raise PermissionError("Host bootstrap rejected")
                else:
                    bundle = response.get("bundle")
                    if not isinstance(bundle, dict):
                        raise PermissionError("Host bootstrap response invalid")
                    self._accept_bundle(bundle)
                    return self
            except PermissionError as exc:
                if str(exc) != "Windows named-pipe host unavailable":
                    raise
            if time.monotonic() >= deadline:
                raise PermissionError("Host bootstrap unavailable") from None
            time.sleep(0.1)

    def _connect(self):
        return connect_named_pipe(
            self.pipe_name,
            expected_server_pid=self.supervisor_pid,
            expected_server_created_filetime=self.supervisor_created_filetime,
            timeout=2.0,
        )

    def _accept_bundle(self, bundle: Mapping[str, Any]) -> None:
        try:
            authority_key = base64.b64decode(bundle["authority_key"], validate=True)
            integrity_key = base64.b64decode(bundle["integrity_key"], validate=True)
            api_key = base64.b64decode(bundle["api_key"], validate=True)
            credential_data = bundle["credential"]
            credential = HostPrincipalCredential(**credential_data)
            authority = HostPrincipalAuthority(authority_key, ttl=_HOST_SESSION_TTL)
            principal = authority.verify(credential)
            session_id = bundle["session_id"]
            if (
                not isinstance(session_id, str)
                or session_id != credential.session_id
                or not authority.accepts(principal, session_id=session_id)
                or len(integrity_key) < 32
                or len(api_key) < 32
            ):
                raise ValueError("invalid Host bootstrap bundle")
        except Exception:
            raise PermissionError("Host bootstrap response invalid") from None
        self.authority = authority
        self.principal = principal
        self.session_id = session_id
        self.integrity_key = integrity_key
        self._api_key = api_key

    def _request(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            if (
                self.authority is None
                or self.principal is None
                or not self.authority.accepts(
                    self.principal, session_id=self.session_id
                )
            ):
                raise PermissionError("Host Controller session expired")
            body = {
                "operation": operation,
                "session_id": self.session_id,
                "request_id": uuid.uuid4().hex,
                "payload": dict(payload),
            }
            envelope = {
                "body": body,
                "mac": _mac(self._api_key, b"atlas-host-ipc-request-v1", body),
            }
            with self._connect() as pipe:
                pipe.send(envelope)
                response = pipe.receive()
            signed = response.get("body")
            signature = response.get("mac")
            if (
                not isinstance(signed, dict)
                or not isinstance(signature, str)
                or not hmac.compare_digest(
                    signature,
                    _mac(self._api_key, b"atlas-host-ipc-response-v1", signed),
                )
            ):
                raise PermissionError("Host IPC response authentication failed")
            if signed.get("ok") is not True:
                raise PermissionError("Host IPC request rejected")
            value = signed.get("value")
            if not isinstance(value, dict):
                raise PermissionError("Host IPC response invalid")
            return value

    def issue(
        self,
        binding: Mapping[str, Any],
        *,
        validate_authority: Any,
    ) -> dict[str, Any]:
        if not callable(validate_authority) or not isinstance(binding, Mapping):
            raise PermissionError("Host task binding invalid")
        validate_authority()
        if (
            binding.get("principal_id") != getattr(self.principal, "principal_id", None)
            or not binding.get("task_id")
            or not binding.get("agent_id")
        ):
            raise PermissionError("Host task binding invalid")
        value = self._request("ISSUE_CONTROLLER", {"binding": dict(binding)})
        validate_authority()
        return _decode_grant(value.get("grant"))

    def observer(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        manager: Any,
    ) -> dict[str, Any]:
        if (
            self.authority is None
            or not self.authority.accepts(principal, session_id=self.session_id)
            or principal != self.principal
        ):
            raise PermissionError("Host observer session invalid")
        value = self._request(
            "ISSUE_OBSERVER", {"task_id": task_id, "agent_id": agent_id}
        )
        binding = value.get("binding")
        verification_key = base64.b64decode(
            value.get("verification_key", ""), validate=True
        )
        grant = _decode_grant(value.get("grant"))
        if not isinstance(binding, dict) or len(verification_key) < 32:
            raise PermissionError("Host observer response invalid")

        def validate_authority() -> None:
            if self.authority is None or not self.authority.accepts(
                principal, session_id=self.session_id
            ):
                raise PermissionError("Host observer authority expired")
            manager.validate_host_task_binding(principal, self.authority, binding)

        from openjarvis.control.host_supervisor_broker import HostSupervisorClient

        client = HostSupervisorClient(
            grant, binding, validate_authority=validate_authority
        )
        try:
            record = client.read_exit_evidence(verification_key)
        finally:
            client.release_exit_evidence()
        return {
            "binding": binding,
            "verification_key": verification_key,
            "fetch": lambda: record,
        }


def _decode_grant(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermissionError("Host Supervisor grant invalid")
    try:
        grant = dict(value)
        grant["key"] = base64.b64decode(grant["key"], validate=True)
        address = grant["address"]
        if (
            len(grant["key"]) < 32
            or not isinstance(address, list)
            or len(address) != 2
            or address[0] != "127.0.0.1"
            or type(address[1]) is not int
            or not 0 < address[1] <= 65535
        ):
            raise ValueError
        grant["address"] = tuple(address)
        return grant
    except Exception:
        raise PermissionError("Host Supervisor grant invalid") from None


class HostSupervisorBootstrapService:
    """Long-lived Host child that alone launches task Supervisors and Workers."""

    def __init__(self, pipe_name: str, manager: Any) -> None:
        if os.name != "nt":
            raise PermissionError("Windows Host bootstrap is unavailable")
        if not callable(getattr(manager, "validate_host_task_binding", None)):
            raise ValueError("Host AgentManager is required")
        self.pipe_name = pipe_name
        self.manager = manager
        self._service_identity = process_identity(os.getpid())
        self._authority_key = secrets.token_bytes(32)
        self._authority = HostPrincipalAuthority(
            self._authority_key, ttl=_HOST_SESSION_TTL
        )
        self._integrity_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._close_lock = threading.Lock()
        self._closed = threading.Event()
        self._close_complete = False
        self._cleanup_unconfirmed = False
        self._cleanup_error: Exception | None = None
        self._serve_error: Exception | None = None
        self._cleanup_thread: threading.Thread | None = None
        self._server: NamedPipeServer | None = None
        self._active_connection: Any = None
        self._thread: threading.Thread | None = None
        self._launcher_identity: dict[str, int | str] | None = None
        self._sessions: dict[str, _ControllerSession] = {}
        self._current_session_id: str | None = None
        self._brokers: dict[str, _BrokerRecord] = {}

    def start(self) -> None:
        with self._lock:
            if self._thread is not None or self._closed.is_set():
                raise RuntimeError("Host bootstrap cannot start")
            self._server = NamedPipeServer(self.pipe_name)
            self._thread = threading.Thread(target=self._serve_entry, daemon=True)
            self._thread.start()

    def _serve_entry(self) -> None:
        try:
            self._serve()
        except Exception as exc:
            self._serve_error = exc
            self._closed.set()
        finally:
            if self._serve_error is not None:
                with self._lock:
                    if self._cleanup_thread is None:
                        self._cleanup_thread = threading.Thread(
                            target=self._cleanup_after_serve,
                            daemon=True,
                        )
                        cleanup_thread = self._cleanup_thread
                    else:
                        cleanup_thread = None
                if cleanup_thread is not None:
                    cleanup_thread.start()

    def _cleanup_after_serve(self) -> None:
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=10)
        try:
            self.close()
        except Exception:
            # The owner retains broker/server refs and the cleanup error.
            pass

    def register_controller(self, launcher_pid: int) -> None:
        identity = process_identity(launcher_pid)
        if (
            identity["user_sid"] != self._service_identity["user_sid"]
            or identity["integrity_rid"] != self._service_identity["integrity_rid"]
        ):
            raise PermissionError("Host Controller token mismatch")
        with self._lock:
            old = self._launcher_identity
            if old is not None:
                try:
                    current_old = process_identity(int(old["pid"]))
                except PermissionError:
                    current_old = None
                if current_old == old:
                    raise PermissionError("previous Controller process is still live")
            if self._current_session_id is not None:
                old_session = self._sessions[self._current_session_id]
                try:
                    current_controller = process_identity(
                        int(old_session.identity["pid"])
                    )
                except PermissionError:
                    current_controller = None
                if current_controller == old_session.identity:
                    raise PermissionError("previous Controller is still live")
                old_session.active = False
            self._launcher_identity = identity
            self._current_session_id = None

    def _serve(self) -> None:
        while True:
            try:
                with self._lock:
                    if self._closed.is_set():
                        break
                    if self._server is None:
                        self._server = NamedPipeServer(self.pipe_name)
                    server = self._server
            except Exception:
                self._closed.set()
                raise
            try:
                connection = server.accept()
            except Exception:
                try:
                    server.close()
                except Exception:
                    self._closed.set()
                    raise
                with self._lock:
                    if self._server is server:
                        self._server = None
                if self._closed.is_set():
                    break
                continue
            with self._lock:
                self._active_connection = connection
                shutdown_requested = self._closed.is_set()
            if shutdown_requested:
                try:
                    connection.close()
                except Exception:
                    self._closed.set()
                    raise
                with self._lock:
                    if self._active_connection is connection:
                        self._active_connection = None
                break
            try:
                # accept() consumes the instance handle; close confirms that
                # no listener resource remains before the next instance opens.
                server.close()
            except Exception:
                self._closed.set()
                raise
            else:
                with self._lock:
                    if self._server is server:
                        self._server = None
            try:
                try:
                    identity = connection.client_identity()
                    self._validate_client(identity)
                    request = connection.receive()
                    if request == {"operation": "BOOTSTRAP"}:
                        response = self._bootstrap(identity)
                        connection.send(response)
                    else:
                        response = self._authenticated_request(identity, request)
                        connection.send(response)
                except Exception as exc:
                    try:
                        detail = (
                            "HOST_CONTROLLER_NOT_REGISTERED"
                            if str(exc) == "Host Controller is not registered"
                            else "HOST_IPC_REJECTED"
                        )
                        connection.send({"ok": False, "detail": detail})
                    except Exception:
                        pass
            finally:
                try:
                    connection.close()
                except Exception:
                    self._closed.set()
                    raise
                else:
                    with self._lock:
                        if self._active_connection is connection:
                            self._active_connection = None

    def _validate_client(self, identity: Mapping[str, Any]) -> None:
        with self._lock:
            launcher = self._launcher_identity
        pid = identity.get("pid")
        if launcher is None:
            raise PermissionError("Host Controller is not registered")
        if (
            type(pid) is not int
            or pid <= 0
            or identity.get("user_sid") != self._service_identity["user_sid"]
            or identity.get("integrity_rid") != self._service_identity["integrity_rid"]
            or not is_process_descendant(pid, launcher)
            # Re-read after ancestry checks so PID reuse cannot pass on stale identity.
            or process_identity(pid) != dict(identity)
        ):
            raise PermissionError("Host Controller OS identity rejected")

    def _bootstrap(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = (
                self._sessions.get(self._current_session_id)
                if self._current_session_id is not None
                else None
            )
            if current is not None and current.identity != dict(identity):
                try:
                    alive = process_identity(int(current.identity["pid"]))
                except PermissionError:
                    alive = None
                if alive == current.identity:
                    raise PermissionError("another Controller is already active")
                current.active = False
                current = None
            if current is None:
                session_id = uuid.uuid4().hex
                credential = self._authority.issue(
                    f"windows:{self._service_identity['user_sid']}", session_id
                )
                principal = self._authority.verify(credential)
                current = _ControllerSession(
                    session_id=session_id,
                    identity=dict(identity),
                    credential=credential,
                    principal=principal,
                    api_key=secrets.token_bytes(32),
                )
                self._sessions[session_id] = current
                self._current_session_id = session_id
            bundle = {
                "session_id": current.session_id,
                "credential": {
                    "principal_id": current.credential.principal_id,
                    "token_id": current.credential.token_id,
                    "session_id": current.credential.session_id,
                    "issued_at": current.credential.issued_at,
                    "expires_at": current.credential.expires_at,
                    "signature": current.credential.signature,
                },
                "authority_key": base64.b64encode(self._authority_key).decode("ascii"),
                "integrity_key": base64.b64encode(self._integrity_key).decode("ascii"),
                "api_key": base64.b64encode(current.api_key).decode("ascii"),
            }
            return {"ok": True, "bundle": bundle}

    def _authenticated_request(
        self, identity: Mapping[str, Any], request: Mapping[str, Any]
    ) -> dict[str, Any]:
        if set(request) != {"body", "mac"} or not isinstance(request.get("body"), dict):
            raise PermissionError("Host IPC request invalid")
        body = request["body"]
        if set(body) != {"operation", "session_id", "request_id", "payload"}:
            raise PermissionError("Host IPC request invalid")
        with self._lock:
            session = self._sessions.get(body["session_id"])
            if (
                session is None
                or not session.active
                or session.identity != dict(identity)
                or body["session_id"] != self._current_session_id
                or not self._authority.accepts(
                    session.principal, session_id=session.session_id
                )
                or not isinstance(body["request_id"], str)
                or len(body["request_id"]) != 32
                or body["request_id"] in session.used_requests
                or len(session.used_requests) >= 10000
                or not isinstance(body["payload"], dict)
                or not isinstance(request["mac"], str)
                or not hmac.compare_digest(
                    request["mac"],
                    _mac(session.api_key, b"atlas-host-ipc-request-v1", body),
                )
            ):
                raise PermissionError("Host IPC authentication rejected")
            session.used_requests.add(body["request_id"])
            operation = body["operation"]
            payload = body["payload"]
        if operation == "ISSUE_CONTROLLER":
            value = self._issue_controller(session, identity, payload)
        elif operation == "ISSUE_OBSERVER":
            value = self._issue_observer(session, identity, payload)
        else:
            raise PermissionError("Host IPC operation rejected")
        signed = {"ok": True, "value": value}
        return {
            "body": signed,
            "mac": _mac(session.api_key, b"atlas-host-ipc-response-v1", signed),
        }

    def _issue_controller(
        self,
        session: _ControllerSession,
        identity: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        binding = payload.get("binding")
        if not isinstance(binding, dict):
            raise PermissionError("Host task binding invalid")
        if (
            binding.get("principal_id") != session.principal.principal_id
            or not isinstance(binding.get("task_id"), str)
            or not isinstance(binding.get("agent_id"), str)
        ):
            raise PermissionError("Host task binding invalid")
        self.manager.validate_host_task_binding(
            session.principal, self._authority, binding
        )
        task = self.manager._get_task(binding["task_id"], agent_id=binding["agent_id"])
        if (
            task is None
            or task["principal_id"] != session.principal.principal_id
            or task["host_session_id"] != session.session_id
            or task["status"] != "running"
        ):
            raise PermissionError("Host task session binding invalid")
        with self._lock:
            if self._closed.is_set():
                raise PermissionError("Host bootstrap is closed")
            existing = self._brokers.get(binding["task_id"])
            if existing is not None:
                if existing.binding == binding:
                    raise PermissionError("Host Supervisor session already exists")
                if (
                    existing.agent_id != binding["agent_id"]
                    or existing.principal.principal_id != binding["principal_id"]
                    or type(binding.get("epoch")) is not int
                    or type(existing.binding.get("epoch")) is not int
                    or binding["epoch"] <= existing.binding["epoch"]
                    or not self._verified_stopped(existing)
                ):
                    raise PermissionError("previous Host worker stop is unverified")
                existing.broker.close()
                del self._brokers[binding["task_id"]]
            record = self._new_broker(session, binding)
            self._brokers[binding["task_id"]] = record
        grant = record.broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=session.principal.principal_id,
            expires_at=float(binding["lease_expires_at"]),
            client_pid=int(identity["pid"]),
        )
        return {"grant": _encode_grant(grant)}

    def _new_broker(
        self, session: _ControllerSession, binding: dict[str, Any]
    ) -> _BrokerRecord:
        from openjarvis.control.host_supervisor_broker import HostSupervisorBroker

        record: _BrokerRecord

        def authorize(grant: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
            if (
                not self._authority.accepts(
                    session.principal, session_id=session.session_id
                )
                or dict(candidate) != record.binding
                or grant.get("principal_id") != session.principal.principal_id
            ):
                return False
            task = self.manager._get_task(record.task_id, agent_id=record.agent_id)
            if (
                task is None
                or task["status"] != "running"
                or task["principal_id"] != session.principal.principal_id
                or task["host_session_id"] != record.session_id
            ):
                return False
            if grant.get("role") == "controller":
                return session.active
            if grant.get("role") == "observer":
                with self._lock:
                    observer = self._sessions.get(record.observer_session_id or "")
                    return bool(
                        observer is not None
                        and observer.active
                        and observer.session_id == self._current_session_id
                        and observer.principal.principal_id
                        == session.principal.principal_id
                    )
            return False

        record = _BrokerRecord(
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            session_id=session.session_id,
            principal=session.principal,
            authority=self._authority,
            binding=dict(binding),
            broker=HostSupervisorBroker(
                authorize,
                self.manager,
                session.principal,
                self._authority,
                integrity_key=self._integrity_key,
            ),
        )
        return record

    def _verified_stopped(self, record: _BrokerRecord) -> bool:
        broker = record.broker
        supervisor = broker.supervisor
        if (
            supervisor is None
            or not broker.disconnected.is_set()
            or not supervisor._worker_stopped
            or not supervisor.verify_exit_evidence(supervisor.evidence)
        ):
            return False
        try:
            durable = self.manager.read_host_worker_exit(
                record.principal,
                record.authority,
                record.binding,
                supervisor.evidence_verification_key,
                integrity_key=self._integrity_key,
            )
            return durable == supervisor.exit_record
        except Exception:
            return False

    def _issue_observer(
        self,
        session: _ControllerSession,
        identity: Mapping[str, Any],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        task_id, agent_id = payload.get("task_id"), payload.get("agent_id")
        if not isinstance(task_id, str) or not isinstance(agent_id, str):
            raise PermissionError("Host observer binding invalid")
        with self._lock:
            record = self._brokers.get(task_id)
            if (
                record is None
                or record.agent_id != agent_id
                or record.principal.principal_id != session.principal.principal_id
                or record.session_id == session.session_id
                or not record.broker.disconnected.is_set()
                or not self._verified_stopped(record)
            ):
                raise PermissionError("Host worker exit is not verified")
            task = self.manager._get_task(task_id, agent_id=agent_id)
            if (
                task is None
                or task["principal_id"] != session.principal.principal_id
                or task["execution_attempt"] != record.binding["attempt"]
            ):
                raise PermissionError("Host observer task mismatch")
            record.observer_session_id = session.session_id
        grant = record.broker.issue(
            role="observer",
            task_id=task_id,
            agent_id=agent_id,
            principal_id=session.principal.principal_id,
            expires_at=min(float(record.binding["lease_expires_at"]), time.time() + 30),
            client_pid=int(identity["pid"]),
        )
        supervisor = record.broker.supervisor
        if supervisor is None:
            raise PermissionError("Host Supervisor unavailable")
        return {
            "grant": _encode_grant(grant),
            "binding": dict(record.binding),
            "verification_key": base64.b64encode(
                supervisor.evidence_verification_key
            ).decode("ascii"),
        }

    def _handle_control(self, value: Mapping[str, Any]) -> bool:
        if value.get("operation") == "REGISTER_CONTROLLER":
            pid = value.get("pid")
            if type(pid) is not int:
                raise PermissionError("Host Controller registration invalid")
            self.register_controller(pid)
            return True
        if value.get("operation") == "SHUTDOWN":
            self.close()
            return False
        raise PermissionError("Host control operation invalid")

    def run(self, control_stream: Any) -> None:
        try:
            self.start()
            print(
                "ATLAS_HOST_READY:{}:{}".format(
                    self._service_identity["pid"],
                    self._service_identity["created_filetime"],
                ),
                flush=True,
            )
            while not self._closed.is_set():
                line = control_stream.readline(_MAX_CONTROL_LINE + 1)
                if not line:
                    break
                if len(line) > _MAX_CONTROL_LINE or not line.endswith(b"\n"):
                    raise PermissionError("Host control message invalid")
                try:
                    value = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise PermissionError("Host control message invalid") from exc
                if not isinstance(value, dict) or not self._handle_control(value):
                    break
        finally:
            self.close()

    def close(self) -> None:
        with self._close_lock:
            self._close()

    def _close(self) -> None:
        with self._lock:
            if self._close_complete:
                return
            if self._cleanup_unconfirmed:
                raise RuntimeError(
                    "Host bootstrap cleanup is unconfirmed"
                ) from self._cleanup_error
            self._closed.set()
            server = self._server
            connection = self._active_connection
            thread = self._thread
        try:
            if server is not None:
                server.close()
            if connection is not None:
                connection.close()
            if thread is threading.current_thread():
                raise RuntimeError("Host bootstrap owner thread must finish cleanup")
            if thread is not None:
                thread.join(timeout=10)
                if thread.is_alive():
                    raise TimeoutError("Host bootstrap IPC thread did not stop")
            while True:
                with self._lock:
                    item = next(iter(self._brokers.items()), None)
                if item is None:
                    break
                task_id, record = item
                record.broker.close()
                if getattr(record.broker, "_close_complete", False) is not True:
                    raise RuntimeError("Host Supervisor broker drain is unconfirmed")
                with self._lock:
                    if self._brokers.get(task_id) is record:
                        del self._brokers[task_id]
            self.manager.close()
            with self._lock:
                self._server = None
                self._active_connection = None
                self._thread = None
                self._close_complete = True
        except Exception as exc:
            with self._lock:
                self._cleanup_unconfirmed = True
                self._cleanup_error = exc
            raise RuntimeError("Host bootstrap cleanup is unconfirmed") from exc


def _encode_grant(grant: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(grant)
    result["key"] = base64.b64encode(result["key"]).decode("ascii")
    result["address"] = list(result["address"])
    return result


__all__ = [
    "HostSupervisorBootstrapClient",
    "HostSupervisorBootstrapService",
]
