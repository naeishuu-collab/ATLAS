"""Local-only SDK discovery and fail-closed gates for candidate adapters.

This module never imports an optional OSS package and never starts a browser,
UIA client, subprocess, or transport.  It records presence only; an installed
package is still API- and execution-unverified until a separately approved
integration proves its direct mutation paths are host-controlled.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata, util
from os import PathLike
from pathlib import Path
from typing import Any

from openjarvis.control.candidate_poc import (
    BrowserUseProposalAdapter,
    UfoProposalAdapter,
)
from openjarvis.control.oss_adapter import (
    AdapterMode,
    AdapterResult,
    ObservationSnapshot,
    mode_from_env,
)
from openjarvis.core.execution import ExecutionState


@dataclass(frozen=True, slots=True)
class SdkDescriptor:
    """Names needed for presence inspection without importing the SDK."""

    candidate: str
    distribution: str
    import_name: str
    required_capabilities: tuple[str, ...]
    expected_version: str | None = None


@dataclass(frozen=True, slots=True)
class SdkStatus:
    descriptor: SdkDescriptor
    installed: bool
    importable: bool
    version: str | None
    reason: str

    @property
    def available(self) -> bool:
        return (
            self.installed
            and self.importable
            and (
                self.descriptor.expected_version is None
                or self.version == self.descriptor.expected_version
            )
        )

    @property
    def capability_matrix(self) -> dict[str, str]:
        status = "UNVERIFIED"
        if not self.available:
            status = "UNAVAILABLE"
        return {
            capability: status
            for capability in self.descriptor.required_capabilities
        }


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    requested: tuple[str, ...]
    supported: tuple[str, ...]
    denied: tuple[str, ...]
    reason: str

    @property
    def allowed(self) -> bool:
        return not self.denied and bool(self.requested)


BROWSER_USE = SdkDescriptor(
    "browser-use",
    "browser-use",
    "browser_use",
    (
        "observation",
        "target_identity",
        "host_authorization",
        "controlled_dispatch",
        "independent_verification",
    ),
    "0.13.13",
)
UFO = SdkDescriptor(
    "UFO",
    "ufo",
    "ufo",
    (
        "uia_observation",
        "window_identity",
        "foreground_identity",
        "host_authorization",
        "controlled_dispatch",
        "independent_verification",
    ),
    None,
)


def inspect_sdk(
    descriptor: SdkDescriptor,
    *,
    site_packages: str | PathLike[str] | None = None,
) -> SdkStatus:
    """Inspect installed metadata and import spec without loading candidate code."""

    if site_packages is not None:
        root = Path(site_packages)
        version = None
        for distribution in metadata.distributions(path=[str(root)]):
            if distribution.metadata.get("Name", "").lower() == (
                descriptor.distribution.lower()
            ):
                version = distribution.version
                break
        package_path = root.joinpath(*descriptor.import_name.split("."))
        importable = package_path.is_dir() or package_path.with_suffix(".py").is_file()
        if version is None:
            reason = (
                "SOURCE_PRESENT_NOT_PACKAGED"
                if importable
                else "DISTRIBUTION_NOT_INSTALLED"
            )
            return SdkStatus(descriptor, False, importable, None, reason)
        if not importable:
            return SdkStatus(
                descriptor, True, False, version, "IMPORT_SPEC_UNAVAILABLE"
            )
        if (
            descriptor.expected_version is not None
            and version != descriptor.expected_version
        ):
            return SdkStatus(
                descriptor, True, True, version, "SDK_VERSION_MISMATCH"
            )
        return SdkStatus(
            descriptor, True, True, version, "API_AND_EXECUTION_UNVERIFIED"
        )

    try:
        version = metadata.version(descriptor.distribution)
    except metadata.PackageNotFoundError:
        return SdkStatus(
            descriptor, False, False, None, "DISTRIBUTION_NOT_INSTALLED"
        )
    try:
        importable = util.find_spec(descriptor.import_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        importable = False
    if not importable:
        return SdkStatus(
            descriptor, True, False, version, "IMPORT_SPEC_UNAVAILABLE"
        )
    if (
        descriptor.expected_version is not None
        and version != descriptor.expected_version
    ):
        return SdkStatus(descriptor, True, True, version, "SDK_VERSION_MISMATCH")
    return SdkStatus(
        descriptor, True, True, version, "API_AND_EXECUTION_UNVERIFIED"
    )


def negotiate_capabilities(
    status: SdkStatus,
    requested: tuple[str, ...] | list[str],
) -> CapabilityDecision:
    """Deny every capability until the real SDK boundary is independently proven."""

    normalized = tuple(dict.fromkeys(str(item) for item in requested))
    required = set(status.descriptor.required_capabilities)
    unknown = tuple(item for item in normalized if item not in required)
    denied = tuple(dict.fromkeys((*normalized, *unknown)))
    reason = "SDK_UNAVAILABLE" if not status.available else "SDK_API_UNVERIFIED"
    return CapabilityDecision(normalized, (), denied, reason)


class _SdkGatedAdapter:
    """Proposal-only shell; it never exposes an SDK dispatch function."""

    descriptor: SdkDescriptor
    proposal_adapter: Any

    def __init__(
        self,
        transcript: str,
        *,
        session_id: str,
        mode: AdapterMode | str | None = None,
        status: SdkStatus | None = None,
    ) -> None:
        self.status = status or inspect_sdk(self.descriptor)
        requested_mode = mode_from_env() if mode is None else AdapterMode(mode)
        if requested_mode is AdapterMode.ENFORCE:
            raise ValueError(
                "SDK execution is disabled until physical control is proven"
            )
        self._proposal = self.proposal_adapter(
            transcript, session_id=session_id, mode=requested_mode
        )

    @property
    def mode(self) -> AdapterMode:
        return self._proposal.mode

    def propose(self, snapshot: ObservationSnapshot) -> AdapterResult:
        if self.mode is AdapterMode.LEGACY:
            return self._proposal.propose(snapshot)
        reason = (
            "SDK_UNAVAILABLE"
            if not self.status.available
            else "SDK_API_UNVERIFIED"
        )
        return AdapterResult(ExecutionState.NOT_STARTED, reason)

    def execute(self, *_args: Any, **_kwargs: Any) -> AdapterResult:
        return AdapterResult(
            ExecutionState.NOT_STARTED,
            "SDK_EXECUTION_DISABLED",
        )


class BrowserUseAdapter(_SdkGatedAdapter):
    """Browser-use gate backed only by the existing offline proposal contract."""

    descriptor = BROWSER_USE
    proposal_adapter = BrowserUseProposalAdapter


class UFOAdapter(_SdkGatedAdapter):
    """UFO gate backed only by the existing offline proposal contract."""

    descriptor = UFO
    proposal_adapter = UfoProposalAdapter


__all__ = [
    "BROWSER_USE",
    "UFO",
    "BrowserUseAdapter",
    "CapabilityDecision",
    "SdkDescriptor",
    "SdkStatus",
    "UFOAdapter",
    "inspect_sdk",
    "negotiate_capabilities",
]
