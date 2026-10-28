"""Offline proposal decoders for future browser-use/UFO integrations.

The JSON envelope is an ATLAS PoC contract, not either upstream SDK API.
No SDK, callback, transport, browser or application is loaded by this module.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from openjarvis.control.oss_adapter import (
    ActionProposal,
    AdapterMode,
    AdapterResult,
    AuthorizedAction,
    CandidateDispatchError,
    ControlSurface,
    ObservationSnapshot,
    SafeEngineAdapter,
)
from openjarvis.core.execution import ExecutionState


class _TranscriptCandidate:
    def __init__(self, transcript: str) -> None:
        if type(transcript) is not str or len(transcript) > 16384:
            raise ValueError("bounded JSON proposal required")
        self.transcript = transcript

    def propose(self, _observation: Mapping) -> ActionProposal:
        data = json.loads(self.transcript)
        if not isinstance(data, dict):
            raise ValueError("proposal object required")
        return ActionProposal(**data)

    def dispatch(self, _authorized: AuthorizedAction):
        raise CandidateDispatchError("PROPOSAL_ONLY_ENGINE", dispatched=False)


class _OfflineProposalAdapter(SafeEngineAdapter):
    surface_kind: ControlSurface
    identity_fields: tuple[str, ...]
    actions: dict[str, frozenset[str]]

    def __init__(
        self,
        transcript: str,
        *,
        session_id: str,
        mode: AdapterMode | str | None = None,
    ) -> None:
        super().__init__(
            _TranscriptCandidate(transcript),
            surface=self.surface_kind,
            session_id=session_id,
            mode=mode,
        )
        if self.mode is AdapterMode.ENFORCE:
            raise ValueError("candidate PoC supports proposal/shadow only")

    def propose(self, snapshot: ObservationSnapshot) -> AdapterResult:
        if self.mode is AdapterMode.LEGACY:
            return super().propose(snapshot)
        result = super().propose(snapshot)
        proposal = result.proposal
        if proposal is None:
            return result
        identity = proposal.target_identity
        failure = ""
        if any(not identity.get(field) for field in self.identity_fields):
            failure = "TARGET_IDENTITY_INCOMPLETE"
        elif not self.session_id or identity["session_id"] != self.session_id:
            failure = "SESSION_MISMATCH"
        elif self.surface is ControlSurface.WINDOWS_APP and (
            snapshot.process_id is None
            or identity["process_id"] != snapshot.process_id
        ):
            failure = "CROSS_PROCESS"
        elif self.surface is ControlSurface.WINDOWS_APP and (
            identity["foreground_hwnd"] != identity["hwnd"]
        ):
            failure = "WRONG_FOREGROUND"
        elif proposal.action not in self.actions or (
            set(proposal.arguments) != self.actions[proposal.action]
            or not proposal.mutation
        ):
            failure = "UNSUPPORTED_ACTION_ARGUMENTS"
        elif "value" in proposal.arguments and (
            not isinstance(proposal.arguments["value"], str)
            or len(proposal.arguments["value"]) > 4096
            or "\x00" in proposal.arguments["value"]
        ):
            failure = "INVALID_TEXT_VALUE"
        if failure:
            return AdapterResult(ExecutionState.NOT_STARTED, failure)
        return result


class BrowserUseProposalAdapter(_OfflineProposalAdapter):
    """Decode public, exact browser targets without starting browser-use."""

    surface_kind = ControlSurface.BROWSER
    identity_fields = (
        "session_id", "tab_id", "page_id", "frame_id", "origin", "dom_revision",
    )
    actions = {
        "browser_click": frozenset(),
        "browser_type": frozenset({"value"}),
    }


class UfoProposalAdapter(_OfflineProposalAdapter):
    """Decode public, exact app targets without loading UFO/Win32/UIA."""

    surface_kind = ControlSurface.WINDOWS_APP
    identity_fields = (
        "session_id", "process_id", "process_created", "hwnd", "window_cookie",
        "runtime_id", "foreground_hwnd",
    )
    actions = {"click": frozenset(), "type_into": frozenset({"value"})}
