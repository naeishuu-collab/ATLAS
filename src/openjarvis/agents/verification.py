"""Independent observation for managed file artifacts and goal acceptance."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from openjarvis.core.artifacts import is_artifact_reference


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    path: str
    status: str
    expected_size_bytes: int | None = None
    actual_size_bytes: int | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "expected_size_bytes": self.expected_size_bytes,
            "actual_size_bytes": self.actual_size_bytes,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class GoalVerification:
    status: str
    evidence: tuple[ArtifactEvidence, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "evidence": [item.to_dict() for item in self.evidence],
        }


# ctime is not stable between path stat and descriptor stat on Windows.
def _file_state(info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    )


def verify_artifact(reference: dict[str, Any]) -> ArtifactEvidence:
    """Observe the current file independently of the producing tool result."""
    path_value = reference.get("path") if isinstance(reference, dict) else ""
    if not is_artifact_reference(reference):
        return ArtifactEvidence(
            str(path_value),
            "VERIFICATION_UNAVAILABLE",
            reason="invalid artifact contract",
        )
    path = Path(reference["path"])
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return ArtifactEvidence(
                reference["path"],
                "STALE_ARTIFACT",
                expected_size_bytes=reference["size_bytes"],
                expected_sha256=reference["sha256"],
                reason="artifact path is not a regular file",
            )
        with path.open("rb") as artifact_file:
            opened = os.fstat(artifact_file.fileno())
            if _file_state(before) != _file_state(opened):
                return ArtifactEvidence(
                    reference["path"],
                    "STALE_ARTIFACT",
                    expected_size_bytes=reference["size_bytes"],
                    expected_sha256=reference["sha256"],
                    reason="artifact identity changed while opening",
                )
            digest = hashlib.sha256()
            actual_size = 0
            while chunk := artifact_file.read(1024 * 1024):
                actual_size += len(chunk)
                digest.update(chunk)
            finished = os.fstat(artifact_file.fileno())
            current = path.lstat()
            if _file_state(before) != _file_state(finished) or _file_state(
                finished
            ) != _file_state(current):
                return ArtifactEvidence(
                    reference["path"],
                    "STALE_ARTIFACT",
                    expected_size_bytes=reference["size_bytes"],
                    actual_size_bytes=actual_size,
                    expected_sha256=reference["sha256"],
                    actual_sha256=digest.hexdigest(),
                    reason="artifact changed during verification",
                )
    except FileNotFoundError:
        return ArtifactEvidence(
            reference["path"],
            "MISSING_ARTIFACT",
            expected_size_bytes=reference["size_bytes"],
            expected_sha256=reference["sha256"],
        )
    except OSError as exc:
        return ArtifactEvidence(
            reference["path"],
            "VERIFICATION_UNAVAILABLE",
            expected_size_bytes=reference["size_bytes"],
            expected_sha256=reference["sha256"],
            reason=type(exc).__name__,
        )
    actual_hash = digest.hexdigest()
    status = (
        "VERIFIED"
        if actual_size == reference["size_bytes"]
        and actual_hash == reference["sha256"].lower()
        else "STALE_ARTIFACT"
    )
    return ArtifactEvidence(
        reference["path"],
        status,
        expected_size_bytes=reference["size_bytes"],
        actual_size_bytes=actual_size,
        expected_sha256=reference["sha256"],
        actual_sha256=actual_hash,
    )


def verify_goal_artifacts(references: list[dict[str, Any]]) -> GoalVerification:
    """Verify every expected artifact, preserving non-success states."""
    if not references:
        return GoalVerification(
            "VERIFICATION_UNAVAILABLE",
            reason="no expected artifact contract was supplied",
        )
    evidence = tuple(verify_artifact(reference) for reference in references)
    statuses = {item.status for item in evidence}
    if "VERIFICATION_UNAVAILABLE" in statuses:
        status = "VERIFICATION_UNAVAILABLE"
    elif statuses - {"VERIFIED"}:
        status = "VERIFICATION_FAILED"
    else:
        status = "VERIFIED"
    return GoalVerification(status, evidence=evidence)


__all__ = [
    "ArtifactEvidence",
    "GoalVerification",
    "verify_artifact",
    "verify_goal_artifacts",
]
