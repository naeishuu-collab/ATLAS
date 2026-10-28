"""Validation helpers for structured tool-produced artifact references."""

from __future__ import annotations

from typing import Any

_MAX_ARTIFACTS_PER_STEP = 64
_SHA256_HEX = frozenset("0123456789abcdef")


def is_artifact_reference(value: Any) -> bool:
    """Accept only the bounded file-reference shape emitted by file tools."""
    return (
        isinstance(value, dict)
        and set(value) == {"type", "path", "size_bytes", "sha256"}
        and value.get("type") == "file"
        and isinstance(value.get("path"), str)
        and 0 < len(value["path"]) <= 4096
        and type(value.get("size_bytes")) is int
        and value["size_bytes"] >= 0
        and isinstance(value.get("sha256"), str)
        and len(value["sha256"]) == 64
        and all(char in _SHA256_HEX for char in value["sha256"].lower())
    )


def valid_artifact_references(value: Any) -> bool:
    """Validate artifact arrays restored from a durable checkpoint."""
    return (
        isinstance(value, list)
        and len(value) <= _MAX_ARTIFACTS_PER_STEP
        and all(is_artifact_reference(item) for item in value)
    )


def clean_artifact_references(value: Any) -> list[dict[str, Any]]:
    """Keep only recognized fields from a tool's optional artifact metadata."""
    if not isinstance(value, list):
        return []
    cleaned = [
        {
            "type": item["type"],
            "path": item["path"],
            "size_bytes": item["size_bytes"],
            "sha256": item["sha256"].lower(),
        }
        for item in value[:_MAX_ARTIFACTS_PER_STEP]
        if is_artifact_reference(item)
    ]
    return cleaned
