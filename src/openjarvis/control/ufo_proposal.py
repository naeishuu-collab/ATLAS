"""Proposal-only contract adapter for the inspected Microsoft UFO API.

This module deliberately does not import UFO, pywinauto, UIA, WebSocket, or
any Windows automation package.  It converts a bounded UFO-shaped action into
an ATLAS proposal; dispatch remains owned by SafeEngineAdapter.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from openjarvis.control.mutation_boundary import (
    DirectMutationBoundary,
    DirectMutationDecision,
)
from openjarvis.control.oss_adapter import (
    ActionProposal,
    ControlSurface,
    ObservationSnapshot,
)


class UfoProposalError(ValueError):
    """A UFO contract payload cannot be safely converted."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class UfoActionSpec:
    function: str
    source_entrypoint: str
    parameter_keys: frozenset[str]
    required_parameter_keys: frozenset[str]
    target_kind: str = "control"
    verification: str = "independent_postcondition"
    direct_dispatch: str = "DENIED"

    @property
    def atlas_action(self) -> str:
        return f"ufo_sdk_{self.function}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ufo_function": self.function,
            "atlas_action": self.atlas_action,
            "source_entrypoint": self.source_entrypoint,
            "parameter_keys": sorted(self.parameter_keys),
            "required_parameter_keys": sorted(self.required_parameter_keys),
            "target_kind": self.target_kind,
            "mutation": True,
            "verification": self.verification,
            "direct_dispatch": self.direct_dispatch,
            "retry": "ATLAS_ONLY",
            "failure": "FAIL_CLOSED",
        }


_SPECS = (
    UfoActionSpec(
        "click_input",
        "ufo.automator.ui_control.controller.ControlReceiver.click_input",
        frozenset({"button", "double"}),
        frozenset(),
    ),
    UfoActionSpec(
        "set_edit_text",
        "ufo.automator.ui_control.controller.ControlReceiver.set_edit_text",
        frozenset({"text", "clear_current_text"}),
        frozenset({"text"}),
    ),
    UfoActionSpec(
        "keyboard_input",
        "ufo.automator.ui_control.controller.ControlReceiver.keyboard_input",
        frozenset({"keys", "control_focus"}),
        frozenset({"keys"}),
    ),
    UfoActionSpec(
        "key_press",
        "ufo.automator.ui_control.controller.ControlReceiver.key_press",
        frozenset({"keys"}),
        frozenset({"keys"}),
    ),
    UfoActionSpec(
        "scroll",
        "ufo.automator.ui_control.controller.ControlReceiver.scroll",
        frozenset({"x", "y", "scroll_x", "scroll_y"}),
        frozenset(),
    ),
    UfoActionSpec(
        "type",
        "ufo.automator.ui_control.controller.ControlReceiver.type",
        frozenset({"text"}),
        frozenset({"text"}),
    ),
)

_IDENTITY_FIELDS = (
    "session_id",
    "process_id",
    "process_created",
    "hwnd",
    "window_cookie",
    "runtime_id",
    "foreground_hwnd",
)
_TARGET_KEYS = frozenset({"kind", "name", "id", "type", "rect"})
_ACTION_KEYS = frozenset(
    {
        "function",
        "arguments",
        "target",
        "status",
        "result",
        "action_string",
        "action_representation",
    }
)
_UFO_DIRECT_ENTRYPOINTS = (
    "ControlReceiver.atomic_execution",
    "ControlReceiver.click_input",
    "ControlReceiver.set_edit_text",
    "ControlReceiver.keyboard_input",
    "ControlReceiver.key_press",
    "ControlReceiver.scroll",
    "ControlReceiver.type",
    "ActionExecutor.execute",
    "AppPuppeteer.execute_command",
    "AppPuppeteer.execute_all_commands",
    "AppPuppeteer.save",
    "UFOWebSocketClient.handle_commands",
    "UFOWebSocketClient._maybe_retry",
    "WebSocketTransport.connect",
    "WebSocketTransport.send",
    "WebSocketTransport.receive",
)


class UfoProposalAdapter:
    """Convert one inspected UFO ActionCommandInfo-shaped mapping to a proposal."""

    def __init__(self, *, session_id: str) -> None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id is required")
        self.session_id = session_id
        self._specs = {spec.function: spec for spec in _SPECS}
        self._direct_boundary = DirectMutationBoundary(
            ControlSurface.WINDOWS_APP,
            _UFO_DIRECT_ENTRYPOINTS,
        )

    @property
    def contract(self) -> tuple[UfoActionSpec, ...]:
        return _SPECS

    def contract_matrix(self) -> list[dict[str, Any]]:
        return [spec.to_dict() for spec in _SPECS]

    def deny_direct_sdk(self, entrypoint: str) -> DirectMutationDecision:
        return self._direct_boundary.deny(entrypoint)

    def invoke_direct_sdk(
        self,
        entrypoint: str,
        callback: Any = None,
        *_args: Any,
        **_kwargs: Any,
    ) -> DirectMutationDecision:
        return self._direct_boundary.invoke(entrypoint, callback, *_args, **_kwargs)

    def propose(
        self,
        action: Mapping[str, Any],
        snapshot: ObservationSnapshot,
        *,
        action_id: str,
    ) -> ActionProposal:
        if snapshot.surface is not ControlSurface.WINDOWS_APP:
            raise UfoProposalError("SURFACE_MISMATCH")
        if not isinstance(action_id, str) or not action_id.strip():
            raise UfoProposalError("ACTION_ID_REQUIRED")
        function, arguments, target = self._decode(action)
        spec = self._specs.get(function)
        if spec is None:
            raise UfoProposalError("UNSUPPORTED_ACTION")
        params = self._validate_arguments(spec, arguments)
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id.strip():
            raise UfoProposalError("TARGET_ID_REQUIRED")
        if target.get("kind") != spec.target_kind:
            raise UfoProposalError("TARGET_KIND_UNSUPPORTED")
        try:
            public = snapshot.public_payload()
        except (TypeError, ValueError) as exc:
            raise UfoProposalError(str(exc)) from exc
        matches = [
            item for item in public["targets"] if item.get("target_id") == target_id
        ]
        if len(matches) != 1:
            raise UfoProposalError(
                "AMBIGUOUS_TARGET" if len(matches) > 1 else "STALE_TARGET"
            )
        identity = matches[0].get("identity")
        if not isinstance(identity, Mapping):
            raise UfoProposalError("TARGET_IDENTITY_REQUIRED")
        if any(
            field not in identity or identity[field] in (None, "")
            for field in _IDENTITY_FIELDS
        ):
            raise UfoProposalError("TARGET_IDENTITY_INCOMPLETE")
        if identity.get("session_id") != self.session_id:
            raise UfoProposalError("SESSION_MISMATCH")
        if (
            snapshot.process_id is not None
            and identity.get("process_id") != snapshot.process_id
        ):
            raise UfoProposalError("CROSS_PROCESS")
        if identity.get("foreground_hwnd") != identity.get("hwnd"):
            raise UfoProposalError("WRONG_FOREGROUND")
        try:
            return ActionProposal(
                action_id=action_id,
                observation_id=public["observation_id"],
                target_id=target_id,
                target_identity=identity,
                action=spec.atlas_action,
                arguments={"params": params},
                mutation=True,
            )
        except (TypeError, ValueError) as exc:
            raise UfoProposalError("INVALID_ACTION_ARGUMENTS") from exc

    @staticmethod
    def _decode(
        action: Mapping[str, Any],
    ) -> tuple[str, Mapping[str, Any], Mapping[str, Any]]:
        required = {"function", "arguments", "target"}
        if (
            not isinstance(action, Mapping)
            or not required.issubset(action)
            or not set(action).issubset(_ACTION_KEYS)
        ):
            raise UfoProposalError("ACTION_INVALID")
        function = action.get("function")
        arguments = action.get("arguments")
        target = action.get("target")
        if (
            not isinstance(function, str)
            or not isinstance(arguments, Mapping)
            or not isinstance(target, Mapping)
            or not set(target).issubset(_TARGET_KEYS)
        ):
            raise UfoProposalError("ACTION_INVALID")
        for field in ("status", "action_string", "action_representation"):
            if field in action and not isinstance(action[field], str):
                raise UfoProposalError("ACTION_INVALID")
        if "result" in action and not isinstance(action["result"], Mapping):
            raise UfoProposalError("ACTION_INVALID")
        try:
            encoded = json.dumps(action, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise UfoProposalError("ACTION_INVALID") from exc
        if len(encoded.encode("utf-8")) > 16384:
            raise UfoProposalError("ACTION_TOO_LARGE")
        return function, arguments, target

    @staticmethod
    def _validate_arguments(
        spec: UfoActionSpec,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        if set(arguments) != {"params"} or not isinstance(arguments["params"], Mapping):
            raise UfoProposalError("ARGUMENTS_INVALID")
        params = dict(arguments["params"])
        if not set(params).issubset(spec.parameter_keys):
            raise UfoProposalError("ARGUMENTS_UNKNOWN")
        if not spec.required_parameter_keys.issubset(params):
            raise UfoProposalError("ARGUMENTS_MISSING")
        if "text" in params and (
            not isinstance(params["text"], str)
            or len(params["text"]) > 4096
            or "\x00" in params["text"]
        ):
            raise UfoProposalError("INVALID_TEXT_VALUE")
        if "keys" in params:
            keys = params["keys"]
            if not isinstance(keys, (str, list, tuple)):
                raise UfoProposalError("INVALID_KEYS_VALUE")
            if isinstance(keys, (list, tuple)) and any(
                not isinstance(item, str) for item in keys
            ):
                raise UfoProposalError("INVALID_KEYS_VALUE")
        try:
            json.dumps(params, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise UfoProposalError("INVALID_ARGUMENT_VALUE") from exc
        return params


__all__ = ["UfoActionSpec", "UfoProposalAdapter", "UfoProposalError"]
