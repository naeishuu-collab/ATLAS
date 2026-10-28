"""browser-use 0.13.13 action schemas converted to ATLAS proposals.

This module only reads action metadata and creates an untrusted proposal.  It
never imports browser-use, starts a browser, calls an LLM, or dispatches an
SDK action.  Dispatch remains owned by ``SafeEngineAdapter``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from openjarvis.control.oss_adapter import (
    ActionProposal,
    ControlSurface,
    ObservationSnapshot,
)

BROWSER_USE_VERSION = "0.13.13"


class BrowserUseSchemaError(ValueError):
    """A schema or action cannot be safely converted."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class BrowserUseActionSpec:
    sdk_name: str
    argument_names: frozenset[str]
    required_arguments: frozenset[str]
    sdk_schema: Mapping[str, Any]
    mutation: bool
    target_kind: str
    required_authorization: tuple[str, ...]
    verification: str
    retry: str = "ATLAS_ONLY"
    failure: str = "FAIL_CLOSED"

    @property
    def atlas_action(self) -> str:
        return f"browser_sdk_{self.sdk_name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sdk_action": self.sdk_name,
            "atlas_action": self.atlas_action,
            "arguments": sorted(self.argument_names),
            "required_arguments": sorted(self.required_arguments),
            "sdk_schema": _json_copy(self.sdk_schema),
            "mutation": self.mutation,
            "target_kind": self.target_kind,
            "required_authorization": list(self.required_authorization),
            "verification": self.verification,
            "retry": self.retry,
            "failure": self.failure,
        }


_POLICIES: dict[str, tuple[bool, str]] = {
    "click": (True, "element"),
    "close": (True, "tab"),
    "done": (False, "page"),
    "dropdown_options": (False, "element"),
    "evaluate": (True, "page"),
    "extract": (False, "page"),
    "find_elements": (False, "page"),
    "find_text": (False, "page"),
    "go_back": (True, "page"),
    "input": (True, "element"),
    "navigate": (True, "page"),
    "read_file": (False, "page"),
    "replace_file": (True, "page"),
    "save_as_pdf": (True, "page"),
    # file_name is optional, but when present the SDK writes a local file.
    "screenshot": (True, "page"),
    "scroll": (True, "element_or_page"),
    "search": (True, "page"),
    "search_page": (False, "page"),
    "select_dropdown": (True, "element"),
    "send_keys": (True, "page"),
    "switch": (True, "tab"),
    "upload_file": (True, "element"),
    "wait": (False, "page"),
    "write_file": (True, "page"),
}


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=True))
    except (TypeError, ValueError) as exc:
        raise BrowserUseSchemaError("SCHEMA_NOT_JSON") from exc


def _schema_from_action(action: Any) -> Mapping[str, Any]:
    if isinstance(action, Mapping):
        schema = action.get("schema")
    else:
        model = getattr(action, "param_model", None)
        method = getattr(model, "model_json_schema", None)
        schema = method() if callable(method) else None
    if not isinstance(schema, Mapping):
        raise BrowserUseSchemaError("ACTION_SCHEMA_UNAVAILABLE")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, Mapping) or not isinstance(required, list):
        raise BrowserUseSchemaError("ACTION_SCHEMA_INVALID")
    if any(not isinstance(name, str) for name in properties):
        raise BrowserUseSchemaError("ACTION_SCHEMA_INVALID")
    if any(not isinstance(name, str) for name in required):
        raise BrowserUseSchemaError("ACTION_SCHEMA_INVALID")
    if not set(required).issubset(properties):
        raise BrowserUseSchemaError("ACTION_SCHEMA_INVALID")
    return _json_copy(schema)


def extract_browser_use_action_schema(
    actions: Mapping[str, Any],
    *,
    version: str,
) -> tuple[BrowserUseActionSpec, ...]:
    """Read the real SDK registry without importing or executing an action."""

    if version != BROWSER_USE_VERSION:
        raise BrowserUseSchemaError("SDK_VERSION_MISMATCH")
    if not isinstance(actions, Mapping):
        raise BrowserUseSchemaError("ACTION_REGISTRY_INVALID")
    expected = frozenset(_POLICIES)
    if frozenset(actions) != expected:
        raise BrowserUseSchemaError("ACTION_SCHEMA_SET_MISMATCH")

    result: list[BrowserUseActionSpec] = []
    for name in sorted(expected):
        schema = _schema_from_action(actions[name])
        properties = schema["properties"]
        required = frozenset(schema.get("required", []))
        mutation, target_kind = _POLICIES[name]
        authorization = (
            (
                "session_binding",
                "target_identity",
                "authorized_payload",
                "nonce_replay_protection",
                "independent_verification",
            )
            if mutation
            else ("session_binding", "privacy_filter")
        )
        result.append(
            BrowserUseActionSpec(
                sdk_name=name,
                argument_names=frozenset(properties),
                required_arguments=required,
                sdk_schema=schema,
                mutation=mutation,
                target_kind=target_kind,
                required_authorization=authorization,
                verification=(
                    "independent_postcondition" if mutation else "observation_integrity"
                ),
            )
        )
    return tuple(result)


def action_schema_rows(
    schema: Iterable[BrowserUseActionSpec],
) -> list[dict[str, Any]]:
    """Return JSON-ready evidence rows for a previously inspected registry."""

    return [item.to_dict() for item in schema]


class BrowserUseSchemaAdapter:
    """Convert one browser-use action into one ATLAS proposal."""

    def __init__(
        self,
        schema: Iterable[BrowserUseActionSpec],
        *,
        session_id: str,
    ) -> None:
        if not session_id:
            raise ValueError("session_id is required")
        self._schema = {item.sdk_name: item for item in schema}
        if set(self._schema) != set(_POLICIES):
            raise BrowserUseSchemaError("ACTION_SCHEMA_SET_MISMATCH")
        self.session_id = session_id

    @property
    def schema(self) -> tuple[BrowserUseActionSpec, ...]:
        return tuple(self._schema[name] for name in sorted(self._schema))

    def to_proposal(
        self,
        action: Mapping[str, Any],
        snapshot: ObservationSnapshot,
        *,
        action_id: str,
    ) -> ActionProposal:
        if snapshot.surface is not ControlSurface.BROWSER:
            raise BrowserUseSchemaError("SURFACE_MISMATCH")
        if not isinstance(action_id, str) or not action_id.strip():
            raise BrowserUseSchemaError("ACTION_ID_REQUIRED")
        name, arguments = self._decode_action(action)
        spec = self._schema.get(name)
        if spec is None:
            raise BrowserUseSchemaError("UNSUPPORTED_ACTION")
        self._validate_arguments(spec, arguments)
        try:
            public = snapshot.public_payload()
        except (TypeError, ValueError) as exc:
            raise BrowserUseSchemaError(str(exc)) from exc
        target_id, identity = self._select_target(spec, arguments, public["targets"])
        if identity.get("session_id") != self.session_id:
            raise BrowserUseSchemaError("SESSION_MISMATCH")
        self._validate_navigation(name, arguments, identity)
        try:
            return ActionProposal(
                action_id=action_id,
                observation_id=public["observation_id"],
                target_id=target_id,
                target_identity=identity,
                action=spec.atlas_action,
                arguments=arguments,
                mutation=spec.mutation,
            )
        except (TypeError, ValueError) as exc:
            raise BrowserUseSchemaError("INVALID_ACTION_ARGUMENTS") from exc

    @staticmethod
    def _decode_action(action: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
        if not isinstance(action, Mapping):
            raise BrowserUseSchemaError("ACTION_INVALID")
        if "name" in action or "arguments" in action:
            if set(action) != {"name", "arguments"}:
                raise BrowserUseSchemaError("ACTION_INVALID")
            name = action.get("name")
            arguments = action.get("arguments")
        elif len(action) == 1:
            name, arguments = next(iter(action.items()))
        else:
            raise BrowserUseSchemaError("MULTI_ACTION")
        if not isinstance(name, str) or not isinstance(arguments, Mapping):
            raise BrowserUseSchemaError("ACTION_INVALID")
        try:
            encoded = json.dumps(action, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise BrowserUseSchemaError("ACTION_INVALID") from exc
        if len(encoded) > 16384:
            raise BrowserUseSchemaError("ACTION_TOO_LARGE")
        return name, dict(arguments)

    @staticmethod
    def _validate_arguments(
        spec: BrowserUseActionSpec,
        arguments: Mapping[str, Any],
    ) -> None:
        keys = set(arguments)
        if not keys.issubset(spec.argument_names):
            raise BrowserUseSchemaError("ARGUMENTS_UNKNOWN")
        if not spec.required_arguments.issubset(keys):
            raise BrowserUseSchemaError("ARGUMENTS_MISSING")
        for value in arguments.values():
            if isinstance(value, str) and (len(value) > 4096 or "\x00" in value):
                raise BrowserUseSchemaError("INVALID_ARGUMENT_VALUE")
        try:
            json.dumps(arguments, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise BrowserUseSchemaError("INVALID_ARGUMENT_VALUE") from exc

    @staticmethod
    def _select_target(
        spec: BrowserUseActionSpec,
        arguments: Mapping[str, Any],
        targets: list[Mapping[str, Any]],
    ) -> tuple[str, Mapping[str, Any]]:
        target_kind = spec.target_kind
        if target_kind == "element_or_page":
            target_kind = "element" if arguments.get("index") is not None else "page"
        if target_kind == "page":
            if len(targets) != 1:
                raise BrowserUseSchemaError(
                    "AMBIGUOUS_TARGET" if len(targets) > 1 else "STALE_TARGET"
                )
            target = targets[0]
        elif target_kind == "tab":
            tab_id = arguments.get("tab_id")
            matches = [
                target
                for target in targets
                if target.get("identity", {}).get("tab_id") == tab_id
            ]
            if len(matches) != 1:
                raise BrowserUseSchemaError(
                    "AMBIGUOUS_TARGET" if len(matches) > 1 else "STALE_TARGET"
                )
            target = matches[0]
        else:
            index = arguments.get("index")
            matches = []
            for candidate in targets:
                identity = candidate.get("identity", {})
                if identity.get("element_index", identity.get("index")) == index:
                    matches.append(candidate)
            if len(matches) != 1:
                raise BrowserUseSchemaError(
                    "AMBIGUOUS_TARGET" if len(matches) > 1 else "STALE_TARGET"
                )
            target = matches[0]
        target_id = target.get("target_id")
        identity = target.get("identity")
        if not isinstance(target_id, str) or not isinstance(identity, Mapping):
            raise BrowserUseSchemaError("TARGET_IDENTITY_REQUIRED")
        return target_id, identity

    @staticmethod
    def _validate_navigation(
        name: str,
        arguments: Mapping[str, Any],
        identity: Mapping[str, Any],
    ) -> None:
        if name == "search":
            raise BrowserUseSchemaError("NAVIGATION_TARGET_UNVERIFIED")
        if name != "navigate":
            return
        url = arguments.get("url")
        origin = identity.get("origin")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
        ):
            raise BrowserUseSchemaError("NAVIGATION_TARGET_UNVERIFIED")
        actual_origin = f"{parsed.scheme}://{parsed.netloc}"
        if not isinstance(origin, str) or actual_origin.rstrip("/") != origin.rstrip(
            "/"
        ):
            raise BrowserUseSchemaError("CROSS_ORIGIN")


__all__ = [
    "BROWSER_USE_VERSION",
    "BrowserUseActionSpec",
    "BrowserUseSchemaAdapter",
    "BrowserUseSchemaError",
    "action_schema_rows",
    "extract_browser_use_action_schema",
]
