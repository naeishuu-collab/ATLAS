"""Strict JSON-only codec for a future Python 3.10 UFO proposal worker.

This is a message boundary, not an OS isolation claim.  It never opens a
socket, starts a process, evaluates code, reads files, or permits network data.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

RPC_VERSION = 1
MAX_RPC_BYTES = 16384
WORKER_READY_KIND = "atlas_worker_ready"
WORKER_ERROR_KIND = "atlas_worker_error"
_REQUEST_KEYS = frozenset(
    {"version", "kind", "request_id", "session_id", "nonce", "observation_id", "action"}
)
_RESPONSE_KEYS = frozenset(
    {
        "version",
        "kind",
        "request_id",
        "session_id",
        "nonce",
        "status",
        "proposal",
        "error",
    }
)


class UfoRpcError(ValueError):
    """A worker message violates the bounded RPC contract."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _encode(payload: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise UfoRpcError("RPC_JSON_INVALID") from exc
    if len(encoded) > MAX_RPC_BYTES:
        raise UfoRpcError("RPC_MESSAGE_TOO_LARGE")
    return encoded


def _decode(raw: bytes | bytearray | str) -> dict[str, Any]:
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8")
    elif isinstance(raw, (bytes, bytearray)):
        raw_bytes = bytes(raw)
    else:
        raise UfoRpcError("RPC_BYTES_REQUIRED")
    if len(raw_bytes) > MAX_RPC_BYTES:
        raise UfoRpcError("RPC_MESSAGE_TOO_LARGE")
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UfoRpcError("RPC_JSON_INVALID") from exc
    if not isinstance(payload, dict):
        raise UfoRpcError("RPC_OBJECT_REQUIRED")
    return payload


def encode_request(
    *,
    request_id: str,
    session_id: str,
    nonce: str,
    observation_id: str,
    action: Mapping[str, Any],
) -> bytes:
    payload = {
        "version": RPC_VERSION,
        "kind": "ufo_proposal_request",
        "request_id": request_id,
        "session_id": session_id,
        "nonce": nonce,
        "observation_id": observation_id,
        "action": dict(action),
    }
    _validate_request(payload)
    return _encode(payload)


def decode_request(raw: bytes | bytearray | str) -> dict[str, Any]:
    payload = _decode(raw)
    _validate_request(payload)
    return payload


def encode_response(
    *,
    request_id: str,
    session_id: str,
    nonce: str,
    status: str,
    proposal: Mapping[str, Any] | None = None,
    error: str = "",
) -> bytes:
    payload = {
        "version": RPC_VERSION,
        "kind": "ufo_proposal_response",
        "request_id": request_id,
        "session_id": session_id,
        "nonce": nonce,
        "status": status,
        "proposal": dict(proposal) if proposal is not None else None,
        "error": error,
    }
    _validate_response(payload)
    return _encode(payload)


def decode_response(
    raw: bytes | bytearray | str,
    *,
    request_id: str,
    session_id: str,
    nonce: str,
) -> dict[str, Any]:
    payload = _decode(raw)
    _validate_response(payload)
    if payload["request_id"] != request_id:
        raise UfoRpcError("RPC_REQUEST_ID_MISMATCH")
    if payload["session_id"] != session_id:
        raise UfoRpcError("RPC_SESSION_MISMATCH")
    if payload["nonce"] != nonce:
        raise UfoRpcError("RPC_NONCE_MISMATCH")
    return payload


def encode_ready(
    *,
    worker_kind: str,
    pid: int,
    python: str,
    capabilities: Mapping[str, Any],
    version: int = RPC_VERSION,
) -> bytes:
    payload = {
        "version": version,
        "kind": WORKER_READY_KIND,
        "worker_kind": worker_kind,
        "pid": pid,
        "python": python,
        "capabilities": dict(capabilities),
    }
    _validate_ready(payload)
    return _encode(payload)


def decode_ready(
    raw: bytes | bytearray | str,
    *,
    worker_kind: str,
) -> dict[str, Any]:
    payload = _decode(raw)
    _validate_ready(payload)
    if payload["version"] != RPC_VERSION:
        raise UfoRpcError("RPC_VERSION_UNSUPPORTED")
    if payload["worker_kind"] != worker_kind:
        raise UfoRpcError("RPC_WORKER_KIND_MISMATCH")
    return payload


def encode_worker_error(
    reason: str,
    *,
    request_id: str = "",
    session_id: str = "",
    nonce: str = "",
) -> bytes:
    payload = {
        "version": RPC_VERSION,
        "kind": WORKER_ERROR_KIND,
        "error": reason,
        "request_id": request_id,
        "session_id": session_id,
        "nonce": nonce,
    }
    _validate_worker_error(payload)
    return _encode(payload)


def decode_worker_error(raw: bytes | bytearray | str) -> dict[str, Any]:
    payload = _decode(raw)
    _validate_worker_error(payload)
    return payload


def _validate_request(payload: Mapping[str, Any]) -> None:
    if set(payload) != _REQUEST_KEYS:
        raise UfoRpcError("RPC_REQUEST_KEYS_INVALID")
    if payload["version"] != RPC_VERSION:
        raise UfoRpcError("RPC_VERSION_UNSUPPORTED")
    if payload["kind"] != "ufo_proposal_request":
        raise UfoRpcError("RPC_KIND_INVALID")
    for field in ("request_id", "session_id", "nonce", "observation_id"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise UfoRpcError("RPC_ID_REQUIRED")
    if not isinstance(payload["action"], Mapping):
        raise UfoRpcError("RPC_ACTION_OBJECT_REQUIRED")


def _validate_response(payload: Mapping[str, Any]) -> None:
    if set(payload) != _RESPONSE_KEYS:
        raise UfoRpcError("RPC_RESPONSE_KEYS_INVALID")
    if payload["version"] != RPC_VERSION:
        raise UfoRpcError("RPC_VERSION_UNSUPPORTED")
    if payload["kind"] != "ufo_proposal_response":
        raise UfoRpcError("RPC_KIND_INVALID")
    for field in ("request_id", "session_id", "nonce"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise UfoRpcError("RPC_ID_REQUIRED")
    if payload["status"] not in {"PROPOSAL", "DENIED", "ERROR"}:
        raise UfoRpcError("RPC_STATUS_INVALID")
    if payload["proposal"] is not None and not isinstance(
        payload["proposal"], Mapping
    ):
        raise UfoRpcError("RPC_PROPOSAL_OBJECT_REQUIRED")
    if not isinstance(payload["error"], str):
        raise UfoRpcError("RPC_ERROR_INVALID")
    if payload["status"] == "PROPOSAL" and payload["proposal"] is None:
        raise UfoRpcError("RPC_PROPOSAL_REQUIRED")
    if payload["status"] != "PROPOSAL" and payload["proposal"] is not None:
        raise UfoRpcError("RPC_PROPOSAL_FORBIDDEN")
    if payload["status"] == "ERROR" and not payload["error"].strip():
        raise UfoRpcError("RPC_ERROR_REQUIRED")


def _validate_ready(payload: Mapping[str, Any]) -> None:
    if set(payload) != {
        "version",
        "kind",
        "worker_kind",
        "pid",
        "python",
        "capabilities",
    }:
        raise UfoRpcError("RPC_READY_KEYS_INVALID")
    if not isinstance(payload["version"], int) or payload["version"] <= 0:
        raise UfoRpcError("RPC_VERSION_INVALID")
    if payload["kind"] != WORKER_READY_KIND:
        raise UfoRpcError("RPC_READY_KIND_INVALID")
    if not isinstance(payload["worker_kind"], str) or not payload[
        "worker_kind"
    ].strip():
        raise UfoRpcError("RPC_WORKER_KIND_REQUIRED")
    if not isinstance(payload["pid"], int) or payload["pid"] <= 0:
        raise UfoRpcError("RPC_PID_INVALID")
    if not isinstance(payload["python"], str) or not payload["python"].strip():
        raise UfoRpcError("RPC_PYTHON_REQUIRED")
    if not isinstance(payload["capabilities"], Mapping):
        raise UfoRpcError("RPC_CAPABILITIES_REQUIRED")


def _validate_worker_error(payload: Mapping[str, Any]) -> None:
    if set(payload) != {
        "version",
        "kind",
        "error",
        "request_id",
        "session_id",
        "nonce",
    }:
        raise UfoRpcError("RPC_ERROR_KEYS_INVALID")
    if payload["version"] != RPC_VERSION:
        raise UfoRpcError("RPC_VERSION_UNSUPPORTED")
    if payload["kind"] != WORKER_ERROR_KIND:
        raise UfoRpcError("RPC_ERROR_KIND_INVALID")
    if not isinstance(payload["error"], str) or not payload["error"].strip():
        raise UfoRpcError("RPC_ERROR_REQUIRED")
    for field in ("request_id", "session_id", "nonce"):
        if not isinstance(payload[field], str):
            raise UfoRpcError("RPC_ERROR_BINDING_INVALID")


__all__ = [
    "MAX_RPC_BYTES",
    "RPC_VERSION",
    "WORKER_ERROR_KIND",
    "WORKER_READY_KIND",
    "UfoRpcError",
    "decode_request",
    "decode_response",
    "decode_ready",
    "decode_worker_error",
    "encode_request",
    "encode_response",
    "encode_ready",
    "encode_worker_error",
]
