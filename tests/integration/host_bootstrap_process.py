"""Child process for Windows Host bootstrap IPC integration tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys

from openjarvis.control.host_supervisor_bootstrap import HostSupervisorBootstrapClient
from openjarvis.control.windows_named_pipe import connect_named_pipe


def _json_bytes(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _bootstrap(pipe_name: str, server_pid: int, server_created: int) -> None:
    if sys.stdin.readline().strip() != "BOOTSTRAP":
        return
    client = HostSupervisorBootstrapClient(
        pipe_name,
        supervisor_pid=server_pid,
        supervisor_created_filetime=server_created,
    ).bootstrap()
    print(
        json.dumps(
            {
                "event": "bootstrapped",
                "pid": os.getpid(),
                "principal_id": client.principal.principal_id,
                "session_id": client.session_id,
            }
        ),
        flush=True,
    )
    command = sys.stdin.readline().strip()
    if command == "FORGED_HMAC":
        body = {
            "operation": "ISSUE_CONTROLLER",
            "session_id": client.session_id,
            "request_id": "f" * 32,
            "payload": {},
        }
        signature = hmac.new(
            b"invalid-test-key" * 2,
            b"atlas-host-ipc-request-v1\0" + _json_bytes(body),
            hashlib.sha256,
        ).hexdigest()
        with connect_named_pipe(
            pipe_name,
            expected_server_pid=server_pid,
            expected_server_created_filetime=server_created,
        ) as connection:
            connection.send({"body": body, "mac": signature})
            response = connection.receive()
        print(
            json.dumps(
                {
                    "event": "forged_hmac_attempt",
                    "pid": os.getpid(),
                    "detail": response.get("detail"),
                    "accepted": response.get("ok") is True,
                }
            ),
            flush=True,
        )


def _stolen_key(pipe_name: str, server_pid: int, server_created: int) -> None:
    value = json.loads(sys.stdin.readline())
    key = base64.b64decode(value["key"], validate=True)
    body = {
        "operation": "ISSUE_CONTROLLER",
        "session_id": value["session_id"],
        "request_id": "a" * 32,
        "payload": {},
    }
    signature = hmac.new(
        key,
        b"atlas-host-ipc-request-v1\0" + _json_bytes(body),
        hashlib.sha256,
    ).hexdigest()
    with connect_named_pipe(
        pipe_name,
        expected_server_pid=server_pid,
        expected_server_created_filetime=server_created,
    ) as connection:
        connection.send({"body": body, "mac": signature})
        response = connection.receive()
    print(
        json.dumps(
            {
                "event": "stolen_key_attempt",
                "pid": os.getpid(),
                "detail": response.get("detail"),
                "accepted": response.get("ok") is True,
            }
        ),
        flush=True,
    )


def main() -> None:
    mode, pipe_name, raw_pid, raw_created = sys.argv[1:5]
    server_pid, server_created = int(raw_pid), int(raw_created)
    if mode == "bootstrap":
        _bootstrap(pipe_name, server_pid, server_created)
    elif mode == "stolen-key":
        _stolen_key(pipe_name, server_pid, server_created)


if __name__ == "__main__":
    main()
