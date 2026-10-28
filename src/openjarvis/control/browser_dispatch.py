"""ATLAS-owned dispatch facade for browser-use proposals.

The facade accepts SDK-shaped proposals but never owns a browser-use executor.
Mutation dispatch is delegated to the host-owned SafeEngineAdapter only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from openjarvis.control.browser_use_schema import (
    BrowserUseActionSpec,
    BrowserUseSchemaAdapter,
    BrowserUseSchemaError,
)
from openjarvis.control.mutation_boundary import (
    DirectMutationBoundary,
    DirectMutationDecision,
)
from openjarvis.control.oss_adapter import (
    ActionProposal,
    AdapterMode,
    AdapterResult,
    AuthorizedAction,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
)
from openjarvis.core.execution import ExecutionState


class BrowserActionClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    BROWSER_MUTATION = "BROWSER_MUTATION"
    GUI_MUTATION = "GUI_MUTATION"
    FILESYSTEM_MUTATION = "FILESYSTEM_MUTATION"
    PROCESS_MUTATION = "PROCESS_MUTATION"
    NETWORK = "NETWORK"
    UNSUPPORTED = "UNSUPPORTED"


_ACTION_CLASSES = {
    "done": BrowserActionClass.READ_ONLY,
    "dropdown_options": BrowserActionClass.READ_ONLY,
    "extract": BrowserActionClass.READ_ONLY,
    "find_elements": BrowserActionClass.READ_ONLY,
    "find_text": BrowserActionClass.READ_ONLY,
    "read_file": BrowserActionClass.READ_ONLY,
    "search_page": BrowserActionClass.READ_ONLY,
    "wait": BrowserActionClass.READ_ONLY,
    "click": BrowserActionClass.BROWSER_MUTATION,
    "close": BrowserActionClass.BROWSER_MUTATION,
    "evaluate": BrowserActionClass.BROWSER_MUTATION,
    "go_back": BrowserActionClass.BROWSER_MUTATION,
    "input": BrowserActionClass.BROWSER_MUTATION,
    "navigate": BrowserActionClass.BROWSER_MUTATION,
    "scroll": BrowserActionClass.BROWSER_MUTATION,
    "select_dropdown": BrowserActionClass.BROWSER_MUTATION,
    "send_keys": BrowserActionClass.BROWSER_MUTATION,
    "switch": BrowserActionClass.BROWSER_MUTATION,
    "upload_file": BrowserActionClass.BROWSER_MUTATION,
    "replace_file": BrowserActionClass.FILESYSTEM_MUTATION,
    "save_as_pdf": BrowserActionClass.FILESYSTEM_MUTATION,
    "screenshot": BrowserActionClass.FILESYSTEM_MUTATION,
    "write_file": BrowserActionClass.FILESYSTEM_MUTATION,
    "search": BrowserActionClass.NETWORK,
}

_BROWSER_DIRECT_ENTRYPOINTS = (
    "Agent.run",
    "Agent.step",
    "BrowserSession.start",
    "BrowserSession.connect",
    "BrowserSession.navigate_to",
    "BrowserSession.close",
    "Tools.click",
    "Tools.input",
    "Tools.scroll",
    "Tools.send_keys",
    "Tools.screenshot",
    "Tools.write_file",
    "Tools.replace_file",
    "Tools.evaluate",
    "Playwright/CDP",
    "internal_retry",
    "background_task",
    "subprocess",
    "network",
    "llm",
)


@dataclass(frozen=True, slots=True)
class BrowserDispatchEvidence:
    action_id: str
    sdk_action: str
    atlas_action: str
    action_class: BrowserActionClass
    state: ExecutionState
    failure: str
    dispatched: bool
    verified: bool
    retryable: bool = False
    journal_state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "sdk_action": self.sdk_action,
            "atlas_action": self.atlas_action,
            "action_class": self.action_class.value,
            "state": self.state.value,
            "failure": self.failure,
            "dispatched": self.dispatched,
            "verified": self.verified,
            "retryable": self.retryable,
            "journal_state": self.journal_state,
        }


@dataclass(frozen=True, slots=True)
class BrowserDispatchResult:
    proposal: ActionProposal | None
    adapter_result: AdapterResult
    evidence: BrowserDispatchEvidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence": self.evidence.to_dict(),
            "proposal": (
                {
                    "action_id": self.proposal.action_id,
                    "observation_id": self.proposal.observation_id,
                    "target_id": self.proposal.target_id,
                    "action": self.proposal.action,
                    "mutation": self.proposal.mutation,
                }
                if self.proposal is not None
                else None
            ),
        }


class BrowserDispatchFacade:
    """Single host-owned entry point from browser-use schema to dispatch."""

    def __init__(
        self,
        schema: Iterable[BrowserUseActionSpec],
        *,
        host: SafeEngineAdapter,
        session_id: str,
    ) -> None:
        if not isinstance(host, SafeEngineAdapter):
            raise TypeError("DISPATCH_HOST_REQUIRED")
        if host.surface is not ControlSurface.BROWSER:
            raise ValueError("DISPATCH_SURFACE_MISMATCH")
        if host.mode is not AdapterMode.ENFORCE:
            raise ValueError("DISPATCH_ENFORCE_REQUIRED")
        if not host.seal_key or host.session_id != session_id:
            raise ValueError("DISPATCH_SESSION_OR_SEAL_REQUIRED")
        self._host = host
        self._direct_boundary = DirectMutationBoundary(
            ControlSurface.BROWSER,
            _BROWSER_DIRECT_ENTRYPOINTS,
        )
        self._adapter = BrowserUseSchemaAdapter(schema, session_id=session_id)

    @property
    def schema(self) -> tuple[BrowserUseActionSpec, ...]:
        return self._adapter.schema

    @staticmethod
    def classify_action(sdk_action: str) -> BrowserActionClass:
        return _ACTION_CLASSES.get(sdk_action, BrowserActionClass.UNSUPPORTED)

    def action_matrix(self) -> list[dict[str, Any]]:
        return [
            {
                "sdk_action": spec.sdk_name,
                "atlas_action": spec.atlas_action,
                "action_class": self.classify_action(spec.sdk_name).value,
                "mutation": spec.mutation,
                "direct_sdk_dispatch": "DENIED",
                "retry": spec.retry,
                "failure": spec.failure,
            }
            for spec in self.schema
        ]

    def deny_direct_sdk(
        self, entrypoint: str
    ) -> DirectMutationDecision:
        return self._direct_boundary.deny(entrypoint)

    def invoke_direct_sdk(
        self,
        entrypoint: str,
        callback: Callable[..., Any] | None = None,
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
        return self._adapter.to_proposal(action, snapshot, action_id=action_id)

    def dispatch(
        self,
        action: Mapping[str, Any],
        snapshot: ObservationSnapshot,
        *,
        action_id: str,
        authorized: AuthorizedAction | None,
        verify: Callable[[ActionProposal, DispatchResult], bool] | None,
    ) -> BrowserDispatchResult:
        sdk_action = self._action_name(action)
        action_class = self.classify_action(sdk_action)
        try:
            proposal = self.propose(action, snapshot, action_id=action_id)
        except BrowserUseSchemaError as exc:
            result = AdapterResult(ExecutionState.NOT_STARTED, exc.reason)
            return self._result(
                None,
                result,
                action_id=action_id,
                sdk_action=sdk_action,
                action_class=action_class,
            )

        if not proposal.mutation:
            result = AdapterResult(
                ExecutionState.NOT_STARTED,
                "READ_ONLY_NOT_DISPATCHABLE",
                proposal=proposal,
            )
            return self._result(
                proposal,
                result,
                action_id=action_id,
                sdk_action=sdk_action,
                action_class=action_class,
            )

        return self.dispatch_proposal(
            proposal,
            snapshot,
            authorized=authorized,
            verify=verify,
        )

    def dispatch_proposal(
        self,
        proposal: ActionProposal,
        snapshot: ObservationSnapshot,
        *,
        authorized: AuthorizedAction | None,
        verify: Callable[[ActionProposal, DispatchResult], bool] | None,
    ) -> BrowserDispatchResult:
        if not isinstance(proposal, ActionProposal):
            result = AdapterResult(ExecutionState.NOT_STARTED, "PROPOSAL_INVALID")
            return self._result(
                None,
                result,
                action_id="",
                sdk_action="",
                action_class=BrowserActionClass.UNSUPPORTED,
            )
        if not proposal.mutation:
            result = AdapterResult(
                ExecutionState.NOT_STARTED,
                "READ_ONLY_NOT_DISPATCHABLE",
                proposal=proposal,
            )
            return self._result(
                proposal,
                result,
                action_id=proposal.action_id,
                sdk_action=proposal.action.removeprefix("browser_sdk_"),
                action_class=self.classify_action(
                    proposal.action.removeprefix("browser_sdk_")
                ),
            )

        result = self._host.execute(
            proposal,
            snapshot,
            authorized=authorized,
            verify=verify,
        )
        return self._result(
            proposal,
            result,
            action_id=proposal.action_id,
            sdk_action=proposal.action.removeprefix("browser_sdk_"),
            action_class=self.classify_action(
                proposal.action.removeprefix("browser_sdk_")
            ),
        )

    def _result(
        self,
        proposal: ActionProposal | None,
        result: AdapterResult,
        *,
        action_id: str,
        sdk_action: str,
        action_class: BrowserActionClass,
    ) -> BrowserDispatchResult:
        journal_state = ""
        if proposal is not None:
            journal_state = self._host.journal.get(proposal.action_id, "")
        evidence = BrowserDispatchEvidence(
            action_id=action_id if isinstance(action_id, str) else "",
            sdk_action=sdk_action,
            atlas_action=proposal.action if proposal is not None else "",
            action_class=action_class,
            state=result.state,
            failure=result.failure,
            dispatched=result.dispatched,
            verified=result.verified,
            retryable=False,
            journal_state=journal_state,
        )
        return BrowserDispatchResult(proposal, result, evidence)

    @staticmethod
    def _action_name(action: Mapping[str, Any]) -> str:
        if not isinstance(action, Mapping):
            return ""
        if set(action) == {"name", "arguments"}:
            name = action.get("name")
            return name if isinstance(name, str) else ""
        if len(action) == 1:
            name = next(iter(action))
            return name if isinstance(name, str) else ""
        return ""


__all__ = [
    "BrowserActionClass",
    "BrowserDispatchEvidence",
    "BrowserDispatchFacade",
    "BrowserDispatchResult",
]
