"""Proposal-only worker entry point for UFO and browser-use inspection."""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import os
import sys
import time
from collections.abc import Mapping
from typing import Any

from openjarvis.control.ufo_worker_rpc import (
    MAX_RPC_BYTES,
    UfoRpcError,
    decode_request,
    encode_ready,
    encode_response,
    encode_worker_error,
)

_UFO_MODULES = (
    "ufo",
    "ufo.automator.ui_control.controller",
    "ufo.automator.puppeteer",
    "ufo.automator.basic",
    "ufo.automator.action_execution",
    "ufo.client.websocket",
    "aip.transport.websocket",
)
_UFO_PROPOSALS = frozenset(
    {"click_input", "set_edit_text", "keyboard_input", "key_press", "scroll", "type"}
)
_DIRECT_MUTATION_NAMES = frozenset(
    {
        "Agent.run",
        "Agent.step",
        "BrowserSession.start",
        "BrowserSession.connect",
        "BrowserSession.navigate_to",
        "BrowserSession.close",
        "BrowserSession.take_screenshot",
        "Tools.click",
        "Tools.input",
        "Tools.scroll",
        "Tools.send_keys",
        "Tools.switch",
        "Tools.screenshot",
        "Tools.write_file",
        "Tools.replace_file",
        "Tools.evaluate",
        "Playwright/CDP",
        "ControlReceiver.atomic_execution",
        "ControlReceiver.click_input",
        "ControlReceiver.set_edit_text",
        "ControlReceiver.keyboard_input",
        "ControlReceiver.key_press",
        "ControlReceiver.scroll",
        "ControlReceiver.type",
        "ControlReceiver.click_on_coordinates",
        "ControlReceiver.drag_on_coordinates",
        "ControlReceiver.wheel_mouse_input",
        "ControlReceiver.mouse_move",
        "ActionExecutor.execute",
        "AppPuppeteer.execute_command",
        "AppPuppeteer.execute_all_commands",
        "AppPuppeteer.save",
        "UFOWebSocketClient.handle_commands",
        "UFOWebSocketClient._maybe_retry",
        "WebSocketTransport.connect",
        "WebSocketTransport.send",
        "WebSocketTransport.receive",
        "subprocess",
        "network",
        "filesystem",
        "gui",
    }
)


def _ufo_capabilities() -> dict[str, Any]:
    imported = []
    for name in _UFO_MODULES:
        importlib.import_module(name)
        imported.append(name)
    from ufo.agents.processors.schemas.actions import ActionCommandInfo
    from ufo.agents.processors.schemas.target import TargetInfo

    return {
        "sdk_import": "PASS",
        "sdk_modules": imported,
        "action_model": {
            "name": "ActionCommandInfo",
            "fields": sorted(ActionCommandInfo.model_fields),
        },
        "target_model": {
            "name": "TargetInfo",
            "fields": sorted(TargetInfo.model_fields),
        },
        "proposal_only": True,
        "mutation": "NOT_DISPATCHED",
        "gui": "NOT_CALLED",
        "browser": "NOT_CALLED",
        "network": "NOT_CALLED",
        "filesystem": "NOT_CALLED",
        "subprocess": "NOT_CALLED",
    }


def _browser_capabilities() -> dict[str, Any]:
    import browser_use
    from browser_use.tools.service import Tools

    tree = ast.parse(inspect.getsource(Tools).expandtabs(4))
    names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "action"
            for decorator in node.decorator_list
        )
    }
    return {
        "sdk_import": "PASS",
        "sdk_modules": ["browser_use", "browser_use.tools.service"],
        "sdk_file": str(browser_use.__file__),
        "schema_count": len(names),
        "schema_actions": sorted(names),
        "proposal_only": True,
        "agent_run": "NOT_CALLED",
        "browser_launch": "NOT_CALLED",
        "llm": "NOT_CALLED",
        "mutation": "NOT_DISPATCHED",
        "gui": "NOT_CALLED",
        "network": "NOT_CALLED",
        "filesystem": "NOT_CALLED",
        "subprocess": "NOT_CALLED",
    }


def _capabilities(kind: str, inspect_sdk: bool) -> dict[str, Any]:
    if not inspect_sdk:
        return {
            "sdk_import": "NOT_REQUESTED",
            "proposal_only": True,
            "mutation": "NOT_DISPATCHED",
        }
    try:
        if kind == "ufo":
            return _ufo_capabilities()
        if kind == "browser":
            return _browser_capabilities()
        return {
            "sdk_import": "NOT_APPLICABLE",
            "proposal_only": True,
            "mutation": "NOT_DISPATCHED",
        }
    except Exception as exc:
        return {
            "sdk_import": "BLOCKED",
            "inspection_error": type(exc).__name__,
            "inspection_detail": str(exc)[:512],
            "proposal_only": True,
            "mutation": "NOT_DISPATCHED",
        }


def _write(frame: bytes) -> None:
    sys.stdout.buffer.write(frame + b"\n")
    sys.stdout.buffer.flush()


def _deny(request: Mapping[str, Any], reason: str) -> None:
    _write(
        encode_response(
            request_id=request["request_id"],
            session_id=request["session_id"],
            nonce=request["nonce"],
            status="DENIED",
            error=reason,
        )
    )


def _handle(
    request: Mapping[str, Any],
    *,
    kind: str,
    session_id: str,
    capabilities: Mapping[str, Any],
    seen_requests: set[str],
    seen_nonces: set[str],
) -> None:
    request_id = request["request_id"]
    nonce = request["nonce"]
    if request["session_id"] != session_id:
        _deny(request, "RPC_SESSION_MISMATCH")
        return
    if request_id in seen_requests:
        _deny(request, "RPC_DUPLICATE_REQUEST")
        return
    if nonce in seen_nonces:
        _deny(request, "RPC_NONCE_REPLAY")
        return
    seen_requests.add(request_id)
    seen_nonces.add(nonce)
    action = request["action"]
    function = action.get("function") if isinstance(action, Mapping) else None
    if not isinstance(function, str) or not function.strip():
        _deny(request, "WORKER_ACTION_INVALID")
        return
    if function == "__crash__":
        os._exit(41)
    if function == "__sleep__":
        params = action.get("arguments", {}).get("params", {})
        seconds = params.get("seconds") if isinstance(params, Mapping) else None
        if not isinstance(seconds, (int, float)) or not 0 <= seconds <= 5:
            _deny(request, "WORKER_SLEEP_INVALID")
            return
        time.sleep(seconds)
        _deny(request, "WORKER_SLEEP_COMPLETED")
        return
    if function == "__stale__":
        _write(
            encode_response(
                request_id=f"stale-{request_id}",
                session_id=request["session_id"],
                nonce=nonce,
                status="DENIED",
                error="STALE_RESPONSE",
            )
        )
        return
    if function == "__capabilities__":
        _write(
            encode_response(
                request_id=request_id,
                session_id=request["session_id"],
                nonce=nonce,
                status="PROPOSAL",
                proposal={"worker_kind": kind, "capabilities": dict(capabilities)},
            )
        )
        return
    if function in _DIRECT_MUTATION_NAMES:
        _deny(request, "DIRECT_SDK_DISPATCH_DENIED")
        return
    allowed = {
        "ufo": _UFO_PROPOSALS,
        "browser": frozenset({"browser_proposal", "schema_inspection"}),
        "stub": frozenset({"proposal"}),
    }[kind]
    if function not in allowed:
        _deny(request, "UNSUPPORTED_ACTION")
        return
    _write(
        encode_response(
            request_id=request_id,
            session_id=request["session_id"],
            nonce=nonce,
            status="PROPOSAL",
            proposal=dict(action),
        )
    )


def run_worker(
    *,
    kind: str,
    session_id: str,
    inspect_sdk: bool,
    protocol_version: int,
) -> int:
    capabilities = _capabilities(kind, inspect_sdk)
    _write(
        encode_ready(
            worker_kind=kind,
            pid=os.getpid(),
            python=sys.version.split()[0],
            capabilities=capabilities,
            version=protocol_version,
        )
    )
    seen_requests: set[str] = set()
    seen_nonces: set[str] = set()
    while True:
        raw = sys.stdin.buffer.readline(MAX_RPC_BYTES + 2)
        if not raw:
            return 0
        if len(raw) > MAX_RPC_BYTES + 1:
            _write(encode_worker_error("RPC_MESSAGE_TOO_LARGE"))
            return 2
        raw = raw.rstrip(b"\r\n")
        try:
            request = decode_request(raw)
        except UfoRpcError as exc:
            _write(encode_worker_error(str(exc)))
            continue
        _handle(
            request,
            kind=kind,
            session_id=session_id,
            capabilities=capabilities,
            seen_requests=seen_requests,
            seen_nonces=seen_nonces,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=("ufo", "browser", "stub"), required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--protocol-version", type=int, default=1)
    args = parser.parse_args()
    try:
        return run_worker(
            kind=args.kind,
            session_id=args.session_id,
            inspect_sdk=args.inspect,
            protocol_version=args.protocol_version,
        )
    except Exception as exc:
        _write(encode_worker_error(f"WORKER_STARTUP_ERROR:{type(exc).__name__}"))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_worker"]
