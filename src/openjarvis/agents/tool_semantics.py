"""Trusted host-side validation for managed tool proposals.

The model may propose tool names and JSON values, but it never supplies the
schema, effect, capability requirements, or resource binding used here.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

TOOL_SCHEMA_VERSION = 1
_SUPPORTED_SCHEMA_KEYS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "items",
        "anyOf",
        "title",
        "description",
        "default",
        "examples",
    }
)


class ToolSemanticError(ValueError):
    """Structured fail-closed validation error."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str = "$",
        expected: Any = None,
        actual: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.expected = expected
        self.actual = actual

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }


@dataclass(frozen=True, slots=True)
class ToolSemanticBinding:
    """Canonical identity bound to one trusted tool schema."""

    tool_name: str
    schema_version: int
    effect: str
    arguments_sha256: str
    resource_identity: dict[str, Any]


def _reject_constant(value: str) -> None:
    raise ToolSemanticError(
        "TOOL_ARGUMENT_INVALID_JSON",
        f"non-standard JSON constant: {value}",
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_INVALID_JSON",
                f"duplicate JSON field: {key}",
                path=f"$.{key}",
            )
        result[key] = value
    return result


def _ensure_json_value(value: Any, path: str = "$") -> None:
    if value is None or type(value) in {str, bool, int}:
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ToolSemanticError(
                    "TOOL_ARGUMENT_INVALID_JSON",
                    "JSON object keys must be strings",
                    path=path,
                    actual=type(key).__name__,
                )
            _ensure_json_value(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _ensure_json_value(child, f"{path}[{index}]")
        return
    raise ToolSemanticError(
        "TOOL_ARGUMENT_INVALID_JSON",
        "tool arguments contain a non-JSON value",
        path=path,
        actual=type(value).__name__,
    )


def canonical_arguments(arguments: str | dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Parse one object and return its deterministic JSON representation."""
    if isinstance(arguments, str):
        try:
            parsed = json.loads(
                arguments,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except ToolSemanticError:
            raise
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_INVALID_JSON",
                "tool arguments are not valid JSON",
            ) from exc
    elif isinstance(arguments, dict):
        parsed = arguments
    else:
        raise ToolSemanticError(
            "TOOL_ARGUMENT_NOT_OBJECT",
            "tool arguments must be a JSON object",
            actual=type(arguments).__name__,
        )
    if not isinstance(parsed, dict):
        raise ToolSemanticError(
            "TOOL_ARGUMENT_NOT_OBJECT",
            "tool arguments must be a JSON object",
            actual=type(parsed).__name__,
        )
    _ensure_json_value(parsed)
    try:
        canonical = json.dumps(
            parsed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ToolSemanticError(
            "TOOL_ARGUMENT_INVALID_JSON",
            "tool arguments contain a non-JSON value",
        ) from exc
    return canonical, parsed


def arguments_sha256(arguments: str | dict[str, Any]) -> str:
    canonical, _ = canonical_arguments(arguments)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _schema_version(spec: Any) -> int:
    metadata = getattr(spec, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID", "trusted tool metadata must be an object"
        )
    version = metadata.get("schema_version", TOOL_SCHEMA_VERSION)
    if type(version) is not int or version <= 0:
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID",
            "trusted tool schema version must be a positive integer",
            expected="positive integer",
            actual=version,
        )
    return version


def _effect(spec: Any) -> str:
    value = getattr(getattr(spec, "effect", None), "value", getattr(spec, "effect", ""))
    if not isinstance(value, str) or value not in {"READ_ONLY", "MUTATING"}:
        raise ToolSemanticError(
            "TOOL_EFFECT_UNCLASSIFIED",
            "trusted tool effect is not classified",
            expected=["READ_ONLY", "MUTATING"],
            actual=value,
        )
    return value


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return (type(value) in {int, float}) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _validate_value(
    value: Any,
    schema: dict[str, Any],
    path: str,
    *,
    depth: int = 0,
    default_additional_properties: bool = False,
) -> None:
    if depth > 32:
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID", "trusted schema nesting is too deep", path=path
        )
    unsupported = set(schema) - _SUPPORTED_SCHEMA_KEYS
    if unsupported:
        raise ToolSemanticError(
            "TOOL_SCHEMA_UNSUPPORTED",
            f"trusted schema uses unsupported keywords at {path}",
            path=path,
            actual=sorted(unsupported),
        )
    expected_type = schema.get("type")
    valid_types = {"object", "array", "string", "boolean", "integer", "number", "null"}
    if isinstance(expected_type, list):
        if not expected_type or any(
            not isinstance(item, str) or item not in valid_types
            for item in expected_type
        ):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"invalid type declaration at {path}",
                path=path,
            )
        if not any(_type_matches(value, item) for item in expected_type):
            raise ToolSemanticError(
                "TOOL_ARGUMENT_TYPE",
                f"value at {path} has the wrong type",
                path=path,
                expected=expected_type,
                actual=type(value).__name__,
            )
    elif isinstance(expected_type, str):
        if expected_type not in valid_types:
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"invalid type declaration at {path}",
                path=path,
            )
        if not _type_matches(value, expected_type):
            raise ToolSemanticError(
                "TOOL_ARGUMENT_TYPE",
                f"value at {path} has the wrong type",
                path=path,
                expected=expected_type,
                actual=type(value).__name__,
            )
    elif expected_type is not None:
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID",
            f"invalid type declaration at {path}",
            path=path,
        )

    if "enum" in schema:
        if not isinstance(schema["enum"], list):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID", f"enum at {path} must be a list", path=path
            )
        if value not in schema["enum"]:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_ENUM",
                f"value at {path} is outside the trusted enum",
                path=path,
                expected=schema["enum"],
                actual=value,
            )
    if "const" in schema and value != schema["const"]:
        raise ToolSemanticError(
            "TOOL_ARGUMENT_ENUM",
            f"value at {path} does not match the trusted constant",
            path=path,
            expected=schema["const"],
            actual=value,
        )

    for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        bound = schema.get(key)
        if key in schema and (
            type(bound) not in {int, float} or not math.isfinite(float(bound))
        ):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"{key} at {path} must be a finite number",
                path=path,
            )
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ToolSemanticError(
                "TOOL_ARGUMENT_RANGE",
                f"non-finite number at {path}",
                path=path,
            )
        for key, comparator in (
            ("minimum", lambda a, b: a < b),
            ("exclusiveMinimum", lambda a, b: a <= b),
        ):
            if key in schema and comparator(value, schema[key]):
                raise ToolSemanticError(
                    "TOOL_ARGUMENT_RANGE",
                    f"value at {path} is below the trusted minimum",
                    path=path,
                    expected={key: schema[key]},
                    actual=value,
                )
        for key, comparator in (
            ("maximum", lambda a, b: a > b),
            ("exclusiveMaximum", lambda a, b: a >= b),
        ):
            if key in schema and comparator(value, schema[key]):
                raise ToolSemanticError(
                    "TOOL_ARGUMENT_RANGE",
                    f"value at {path} exceeds the trusted maximum",
                    path=path,
                    expected={key: schema[key]},
                    actual=value,
                )

    if isinstance(value, str):
        for key in ("minLength", "maxLength"):
            if key in schema and (type(schema[key]) is not int or schema[key] < 0):
                raise ToolSemanticError(
                    "TOOL_SCHEMA_INVALID",
                    f"{key} at {path} must be a nonnegative integer",
                    path=path,
                )
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_RANGE", f"string at {path} is too short", path=path
            )
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_RANGE", f"string at {path} is too long", path=path
            )
        if "pattern" in schema:
            try:
                matches = re.search(schema["pattern"], value) is not None
            except (TypeError, re.error) as exc:
                raise ToolSemanticError(
                    "TOOL_SCHEMA_INVALID", f"invalid pattern at {path}", path=path
                ) from exc
            if not matches:
                raise ToolSemanticError(
                    "TOOL_ARGUMENT_PATTERN",
                    f"string at {path} does not match the trusted pattern",
                    path=path,
                )

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"properties at {path} must be an object",
                path=path,
            )
        if any(not isinstance(name, str) for name in properties):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"property names at {path} must be strings",
                path=path,
            )
        required = schema.get("required", [])
        if not isinstance(required, list) or any(
            not isinstance(item, str) for item in required
        ):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"required at {path} must be a list of strings",
                path=path,
            )
        if len(set(required)) != len(required):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"required at {path} contains duplicates",
                path=path,
            )
        for name in required:
            if name not in value:
                raise ToolSemanticError(
                    "TOOL_ARGUMENT_MISSING",
                    f"required field {name!r} is missing",
                    path=f"{path}.{name}",
                )
        additional = schema.get("additionalProperties", default_additional_properties)
        if not isinstance(additional, bool) and not isinstance(additional, dict):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"additionalProperties at {path} is invalid",
                path=path,
            )
        for name, child in value.items():
            child_path = f"{path}.{name}"
            if name not in properties:
                if additional is False:
                    raise ToolSemanticError(
                        "TOOL_ARGUMENT_UNKNOWN_FIELD",
                        f"unknown field {name!r} is not accepted",
                        path=child_path,
                    )
                if isinstance(additional, dict):
                    _validate_value(
                        child,
                        additional,
                        child_path,
                        depth=depth + 1,
                        default_additional_properties=default_additional_properties,
                    )
                continue
            if not isinstance(properties[name], dict):
                raise ToolSemanticError(
                    "TOOL_SCHEMA_INVALID",
                    f"schema for {child_path} is invalid",
                    path=child_path,
                )
            _validate_value(
                child,
                properties[name],
                child_path,
                depth=depth + 1,
                default_additional_properties=default_additional_properties,
            )

    if isinstance(value, list):
        for key in ("minItems", "maxItems"):
            if key in schema and (type(schema[key]) is not int or schema[key] < 0):
                raise ToolSemanticError(
                    "TOOL_SCHEMA_INVALID",
                    f"{key} at {path} must be a nonnegative integer",
                    path=path,
                )
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_RANGE", f"array at {path} is too short", path=path
            )
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_RANGE", f"array at {path} is too long", path=path
            )
        if "items" in schema:
            items = schema["items"]
            if not isinstance(items, dict):
                raise ToolSemanticError(
                    "TOOL_SCHEMA_INVALID", f"items at {path} is invalid", path=path
                )
            for index, item in enumerate(value):
                _validate_value(
                    item,
                    items,
                    f"{path}[{index}]",
                    depth=depth + 1,
                    default_additional_properties=default_additional_properties,
                )

    if "anyOf" in schema:
        choices = schema["anyOf"]
        if (
            not isinstance(choices, list)
            or not choices
            or any(not isinstance(choice, dict) for choice in choices)
        ):
            raise ToolSemanticError(
                "TOOL_SCHEMA_INVALID",
                f"anyOf at {path} must contain schemas",
                path=path,
            )
        for choice in choices:
            try:
                _validate_value(
                    value,
                    choice,
                    path,
                    depth=depth + 1,
                    default_additional_properties=True,
                )
                break
            except ToolSemanticError:
                continue
        else:
            raise ToolSemanticError(
                "TOOL_ARGUMENT_ANY_OF",
                f"value at {path} does not match any accepted schema",
                path=path,
            )


def validate_tool_arguments(
    spec: Any,
    arguments: str | dict[str, Any],
    *,
    expected_effect: str | None = None,
    expected_schema_version: int | None = None,
    expected_resource_identity: dict[str, Any] | None = None,
    authorization_scope: set[str] | None = None,
    authorization_check: Callable[[str, str], bool] | None = None,
    required_capabilities: Iterable[str] = (),
) -> ToolSemanticBinding:
    """Validate one call against a trusted ``ToolSpec`` and bind its identity."""
    tool_name = getattr(spec, "name", None)
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ToolSemanticError("TOOL_SCHEMA_INVALID", "trusted tool name is missing")
    version = _schema_version(spec)
    if expected_schema_version is not None and expected_schema_version != version:
        raise ToolSemanticError(
            "TOOL_SCHEMA_VERSION_MISMATCH",
            "proposal schema version does not match the trusted host schema",
            expected=version,
            actual=expected_schema_version,
        )
    effect = _effect(spec)
    if expected_effect is not None and expected_effect != effect:
        raise ToolSemanticError(
            "PLAN_EFFECT_MISMATCH",
            "proposed effect does not match the trusted tool effect",
            expected=effect,
            actual=expected_effect,
        )
    canonical, parsed = canonical_arguments(arguments)
    schema = getattr(spec, "parameters", {}) or {}
    if not isinstance(schema, dict):
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID", "trusted tool parameters must be an object"
        )
    schema = dict(schema)
    schema.setdefault("type", "object")
    _validate_value(parsed, schema, "$")

    capabilities = {
        str(cap) for cap in (getattr(spec, "required_capabilities", []) or [])
    }
    capabilities.update(str(cap) for cap in required_capabilities)
    if authorization_scope is not None and not capabilities.issubset(
        authorization_scope
    ):
        missing = sorted(capabilities - authorization_scope)
        raise ToolSemanticError(
            "AUTHORIZATION_SCOPE_MISMATCH",
            "authorization scope does not cover the trusted tool capabilities",
            expected=missing,
        )
    if authorization_check is not None:
        for capability in sorted(capabilities):
            if not authorization_check(capability, tool_name):
                raise ToolSemanticError(
                    "AUTHORIZATION_SCOPE_MISMATCH",
                    f"authorization denied capability {capability!r}",
                    expected=capability,
                )

    metadata = getattr(spec, "metadata", {}) or {}
    fields = metadata.get("resource_identity_fields", [])
    if not isinstance(fields, list) or any(
        not isinstance(field, str) for field in fields
    ):
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID", "resource_identity_fields must be a list of strings"
        )
    if len(set(fields)) != len(fields):
        raise ToolSemanticError(
            "TOOL_SCHEMA_INVALID", "resource_identity_fields must be unique"
        )
    missing_identity = [field for field in fields if field not in parsed]
    if missing_identity:
        raise ToolSemanticError(
            "TOOL_RESOURCE_MISSING",
            "required resource identity is missing",
            expected=missing_identity,
        )
    identity = {field: parsed[field] for field in fields}
    if (
        expected_resource_identity is not None
        and identity != expected_resource_identity
    ):
        raise ToolSemanticError(
            "TOOL_RESOURCE_MISMATCH",
            "tool resource identity does not match the controller binding",
            expected=expected_resource_identity,
            actual=identity,
        )
    return ToolSemanticBinding(
        tool_name=tool_name,
        schema_version=version,
        effect=effect,
        arguments_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        resource_identity=identity,
    )


__all__ = [
    "TOOL_SCHEMA_VERSION",
    "ToolSemanticBinding",
    "ToolSemanticError",
    "arguments_sha256",
    "canonical_arguments",
    "validate_tool_arguments",
]
