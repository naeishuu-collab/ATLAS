"""Terminable owner-process transport for Windows application observations."""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import threading
import time
import weakref

from openjarvis.windows.identity import IdentityError, IdentitySession

_MAX_MESSAGE = 2 * 1024 * 1024


def _worker(connection, max_controls):
    # comtypes' import-time COM initialization must use this windowless MTA.
    sys.coinit_flags = 0
    backend = None
    session = None
    try:
        from openjarvis.windows.native import NativeBackend

        backend = NativeBackend()
        session = IdentitySession(backend, max_controls=max_controls)
        connection.send_bytes(b'{"ready":true}')
        while True:
            backend.pump()
            if not connection.poll(0.02):
                continue
            request = json.loads(connection.recv_bytes(_MAX_MESSAGE))
            operation = request["operation"]
            args = request["arguments"]
            try:
                if operation == "close":
                    break
                if operation == "observe":
                    result = session.observe(**args).to_dict()
                elif operation == "select":
                    result = session.select(**args)
                elif operation == "validate":
                    result = session.validate(**args)
                elif operation == "read_value":
                    result = session.read_value(**args)
                else:
                    raise IdentityError("Unsupported observation operation")
                payload = json.dumps({"ok": True, "result": result}).encode("utf-8")
                if len(payload) > _MAX_MESSAGE:
                    raise IdentityError("Observation transport limit exceeded")
                connection.send_bytes(payload)
            except Exception as error:
                session.invalidate()
                connection.send_bytes(
                    json.dumps(
                        {
                            "ok": False,
                            "error": f"{type(error).__name__}: {error}",
                        }
                    ).encode("utf-8")
                )
    except (EOFError, BrokenPipeError):
        pass
    except Exception as error:
        try:
            connection.send_bytes(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"{type(error).__name__}: {error}",
                    }
                ).encode("utf-8")
            )
        except (OSError, EOFError):
            pass
    finally:
        if session:
            session.invalidate()
        if backend:
            backend.close()
        connection.close()


def _stop(state):
    process = state.get("process")
    if process is not None and process.pid is not None:
        if process.is_alive():
            process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        if process.is_alive():
            raise IdentityError("Observation worker did not stop")
    connection = state.get("connection")
    if connection is not None:
        connection.close()
    state.clear()


class WindowsObserver:
    """Observe explicit HWNDs and validate retained identities; never act.

    Timeouts/crashes discard all observations and terminate the owned worker.
    A fresh explicit observe may create a new worker. Select/validate never
    restart a worker or recover a target by semantic text.
    """

    def __init__(self, *, timeout: float = 10, max_controls: int = 128):
        if not 0 < timeout <= 60 or not 1 <= max_controls <= 1024:
            raise ValueError("Invalid observation timeout/control limit")
        self.timeout = timeout
        self.max_controls = max_controls
        self._state: dict = {}
        self._lock = threading.RLock()
        self._closed = False
        self._finalizer = weakref.finalize(self, _stop, self._state)

    def _request(self, operation: str, arguments: dict):
        with self._lock:
            if self._closed:
                raise IdentityError("Observer is closed")
            if os.name != "nt":
                raise IdentityError(
                    "Windows observation is unavailable on this platform"
                )
            deadline = time.perf_counter() + self.timeout
            try:
                if not self._state:
                    if operation != "observe":
                        raise IdentityError("No retained observation worker")
                    context = multiprocessing.get_context("spawn")
                    host, child = context.Pipe()
                    process = context.Process(
                        target=_worker,
                        args=(child, self.max_controls),
                        daemon=True,
                    )
                    self._state.update(process=process, connection=host)
                    try:
                        process.start()
                    finally:
                        child.close()
                    if not host.poll(max(0, deadline - time.perf_counter())):
                        raise TimeoutError("Windows observer startup timed out")
                    ready = json.loads(host.recv_bytes(_MAX_MESSAGE))
                    if ready != {"ready": True}:
                        raise IdentityError(
                            ready.get("error", "Invalid observer readiness")
                        )
                connection = self._state["connection"]
                payload = json.dumps(
                    {"operation": operation, "arguments": arguments}
                ).encode("utf-8")
                if len(payload) > _MAX_MESSAGE:
                    raise IdentityError("Observation request limit exceeded")
                connection.send_bytes(payload)
                if not connection.poll(max(0, deadline - time.perf_counter())):
                    raise TimeoutError("Windows observer request timed out")
                response = json.loads(connection.recv_bytes(_MAX_MESSAGE))
                if response.get("ok") is not True:
                    raise IdentityError(
                        response.get("error", "Invalid observer response")
                    )
                return response["result"]
            except Exception:
                _stop(self._state)
                raise

    def observe(self, hwnd: int) -> dict:
        if type(hwnd) is not int or not 0 < hwnd <= 0xFFFFFFFFFFFFFFFF:
            raise IdentityError("An explicit positive HWND is required")
        return self._request("observe", {"hwnd": hwnd})

    def select(self, observation_id: str, **hints) -> str:
        return self._request("select", {"observation_id": observation_id, **hints})

    def validate(
        self,
        observation_id: str,
        target_id: str,
        *,
        require_foreground: bool = True,
        require_value_verifiable: bool = False,
    ) -> dict:
        if type(require_foreground) is not bool:
            raise IdentityError("Foreground precondition must be boolean")
        if type(require_value_verifiable) is not bool:
            raise IdentityError("Value capability precondition must be boolean")
        return self._request(
            "validate",
            {
                "observation_id": observation_id,
                "target_id": target_id,
                "require_foreground": require_foreground,
                "require_value_verifiable": require_value_verifiable,
            },
        )

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._state:
                try:
                    self._state["connection"].send_bytes(
                        b'{"operation":"close","arguments":{}}',
                    )
                    self._state["process"].join(1)
                finally:
                    _stop(self._state)
            self._closed = True
            self._finalizer.detach()

    def read_value(self, observation_id: str, target_id: str) -> str:
        return self._request(
            "read_value", {"observation_id": observation_id, "target_id": target_id}
        )

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
