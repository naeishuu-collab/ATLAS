"""Proposal-only boundary for untrusted Browser/App control engines.

The candidate engine never owns Astra authorization.  It receives a sanitized
observation, may return one exact target-bound proposal, and can dispatch only
after a host-issued, session/nonce-bound HMAC seal is checked.  The default
mode is the legacy engine; no candidate is wired into production by this
module.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Protocol

from openjarvis.core.execution import ExecutionState, MutationIntent


class AdapterMode(str, Enum):
    LEGACY = "legacy"
    SHADOW = "shadow"
    PROPOSAL_ONLY = "proposal_only"
    ENFORCE = "enforce"


class ControlSurface(str, Enum):
    BROWSER = "browser"
    WINDOWS_APP = "windows_app"


_ALLOWED_ACTIONS = {
    ControlSurface.BROWSER: frozenset(
        {
            "browser_snapshot",
            "browser_click",
            "browser_type",
            "browser_fill_form",
            "browser_press_key",
            "browser_select_option",
            "browser_hover",
            "browser_drag",
            "browser_wait_for",
            "browser_close",
            "browser_sdk_click",
            "browser_sdk_close",
            "browser_sdk_done",
            "browser_sdk_dropdown_options",
            "browser_sdk_evaluate",
            "browser_sdk_extract",
            "browser_sdk_find_elements",
            "browser_sdk_find_text",
            "browser_sdk_go_back",
            "browser_sdk_input",
            "browser_sdk_navigate",
            "browser_sdk_read_file",
            "browser_sdk_replace_file",
            "browser_sdk_save_as_pdf",
            "browser_sdk_screenshot",
            "browser_sdk_scroll",
            "browser_sdk_search",
            "browser_sdk_search_page",
            "browser_sdk_select_dropdown",
            "browser_sdk_send_keys",
            "browser_sdk_switch",
            "browser_sdk_upload_file",
            "browser_sdk_wait",
            "browser_sdk_write_file",
        }
    ),
    ControlSurface.WINDOWS_APP: frozenset(
        {
            "click",
            "type_into",
            "press",
            "select",
            "scroll",
            "close",
            "ufo_sdk_click_input",
            "ufo_sdk_set_edit_text",
            "ufo_sdk_keyboard_input",
            "ufo_sdk_key_press",
            "ufo_sdk_scroll",
            "ufo_sdk_type",
        }
    ),
}


class CandidateDispatchError(RuntimeError):
    """Candidate transport failure with an explicit dispatch boundary."""

    def __init__(self, reason: str, *, dispatched: bool | None = None) -> None:
        super().__init__(reason)
        self.dispatched = dispatched


class CandidateEngine(Protocol):
    def propose(self, observation: Mapping[str, Any]) -> "ActionProposal | None": ...

    def dispatch(self, authorized: "AuthorizedAction") -> "DispatchResult": ...


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("non-serializable authorization payload")


@dataclass(frozen=True, slots=True)
class ObservationSnapshot:
    surface: ControlSurface
    observation_id: str
    targets: tuple[Mapping[str, Any], ...]
    privacy: str = "UNKNOWN"
    has_screenshot: bool = False
    process_id: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface", ControlSurface(self.surface))
        object.__setattr__(
            self,
            "targets",
            tuple(_freeze(target) for target in self.targets),
        )

    def public_payload(self) -> dict[str, Any]:
        """Return only public identity data; private/screenshot input is denied."""
        if self.privacy.upper() != "PUBLIC" or self.has_screenshot:
            raise ValueError("PRIVACY_DENIED")
        if not self.observation_id or not self.targets:
            raise ValueError("OBSERVATION_INCOMPLETE")
        targets = []
        for target in self.targets:
            target_id = target.get("target_id")
            identity = target.get("identity")
            if not isinstance(target_id, str) or not target_id:
                raise ValueError("TARGET_IDENTITY_REQUIRED")
            if not isinstance(identity, Mapping):
                raise ValueError("TARGET_IDENTITY_REQUIRED")
            targets.append(
                {
                    "target_id": target_id,
                    "identity": _plain(identity),
                }
            )
        return {
            "surface": self.surface.value,
            "observation_id": self.observation_id,
            "targets": targets,
        }


@dataclass(frozen=True, slots=True)
class ActionProposal:
    action_id: str
    observation_id: str
    target_id: str
    target_identity: Mapping[str, Any]
    action: str
    arguments: Mapping[str, Any]
    mutation: bool = True

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.action_id,
                self.observation_id,
                self.target_id,
                self.action,
            )
        ):
            raise ValueError("proposal identity/action is required")
        if not isinstance(self.target_identity, Mapping):
            raise ValueError("proposal target identity is required")
        if not isinstance(self.arguments, Mapping):
            raise ValueError("proposal arguments must be a mapping")
        if not isinstance(self.mutation, bool):
            raise ValueError("proposal mutation flag must be boolean")
        object.__setattr__(self, "target_identity", _freeze(self.target_identity))
        object.__setattr__(self, "arguments", _freeze(self.arguments))

    def payload(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "observation_id": self.observation_id,
            "target_id": self.target_id,
            "target_identity": _plain(self.target_identity),
            "action": self.action,
            "arguments": _plain(self.arguments),
            "mutation": bool(self.mutation),
        }


@dataclass(frozen=True, slots=True)
class AuthorizedAction:
    proposal: ActionProposal
    intent: MutationIntent
    session_id: str
    nonce: str
    seal: str


@dataclass(frozen=True, slots=True)
class DispatchResult:
    dispatched: bool
    value: Any = None


@dataclass(frozen=True, slots=True)
class AdapterResult:
    state: ExecutionState
    failure: str = ""
    proposal: ActionProposal | None = None
    dispatched: bool = False
    verified: bool = False


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("non-serializable authorization payload")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        _plain(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _seal(
    proposal: ActionProposal,
    intent: MutationIntent,
    session_id: str,
    nonce: str,
    key: bytes,
) -> str:
    body = {
        "proposal": proposal.payload(),
        "intent": intent.to_dict(),
        "session_id": session_id,
        "nonce": nonce,
    }
    return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def make_authorized_action(
    proposal: ActionProposal,
    intent: MutationIntent,
    *,
    session_id: str,
    nonce: str,
    key: bytes,
) -> AuthorizedAction:
    if not session_id or not nonce or not isinstance(key, bytes) or not key:
        raise ValueError("session, nonce and seal key are required")
    return AuthorizedAction(
        proposal=proposal,
        intent=intent,
        session_id=session_id,
        nonce=nonce,
        seal=_seal(proposal, intent, session_id, nonce, key),
    )


def mode_from_env(value: str | None = None) -> AdapterMode:
    raw = value if value is not None else os.environ.get(
        "ASTRA_CONTROL_ENGINE", "legacy"
    )
    try:
        return AdapterMode(raw.strip().lower())
    except (AttributeError, ValueError) as exc:
        raise ValueError("unknown ASTRA_CONTROL_ENGINE mode") from exc


class SafeEngineAdapter:
    """Host-owned boundary for a Browser/App candidate engine."""

    def __init__(
        self,
        engine: CandidateEngine,
        *,
        surface: ControlSurface,
        mode: AdapterMode | str | None = None,
        session_id: str = "",
        seal_key: bytes | None = None,
    ) -> None:
        self.engine = engine
        self.surface = ControlSurface(surface)
        self.mode = mode_from_env() if mode is None else AdapterMode(mode)
        self.session_id = session_id
        self.seal_key = seal_key
        self._journal: dict[str, str] = {}
        self._nonces: set[str] = set()
        self._metrics = {
            "observations": 0,
            "proposals": 0,
            "proposal_denials": 0,
            "dispatch_attempts": 0,
            "dispatch_denials": 0,
            "verified": 0,
            "unknown_outcomes": 0,
            "transport_calls": 0,
        }

    @property
    def journal(self) -> dict[str, str]:
        return dict(self._journal)

    def metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    def propose(self, snapshot: ObservationSnapshot) -> AdapterResult:
        if self.mode is AdapterMode.LEGACY:
            return AdapterResult(ExecutionState.NOT_STARTED, "LEGACY_ENGINE_ACTIVE")
        if snapshot.surface is not self.surface:
            self._metrics["proposal_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "SURFACE_MISMATCH")
        try:
            payload = snapshot.public_payload()
        except (TypeError, ValueError) as exc:
            self._metrics["proposal_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, str(exc))
        self._metrics["observations"] += 1
        try:
            proposal = self.engine.propose(copy.deepcopy(payload))
        except Exception:  # noqa: BLE001 - candidate is untrusted
            self._metrics["proposal_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "CANDIDATE_ERROR")
        if not isinstance(proposal, ActionProposal):
            self._metrics["proposal_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "PROPOSAL_INVALID")
        failure = self._validate_proposal(proposal, snapshot)
        if failure:
            self._metrics["proposal_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, failure)
        self._metrics["proposals"] += 1
        return AdapterResult(ExecutionState.EXECUTED, proposal=proposal)

    def execute(
        self,
        proposal: ActionProposal,
        snapshot: ObservationSnapshot,
        *,
        authorized: AuthorizedAction | None,
        verify: Callable[[ActionProposal, DispatchResult], bool] | None,
    ) -> AdapterResult:
        if self.mode is not AdapterMode.ENFORCE:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "OSS_EXECUTION_DISABLED")
        if not proposal.mutation:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(
                ExecutionState.NOT_STARTED, "MUTATION_ACTION_REQUIRED"
            )
        failure = self._validate_proposal(proposal, snapshot)
        if failure:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, failure)
        if authorized is None:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "AUTHORIZATION_REQUIRED")
        if authorized.proposal != proposal:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "AUTHORIZATION_MISMATCH")
        if not callable(verify):
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "VERIFICATION_REQUIRED")
        if not self.session_id or authorized.session_id != self.session_id:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "SESSION_MISMATCH")
        if not self.seal_key:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "SEAL_UNAVAILABLE")
        expected = _seal(
            proposal,
            authorized.intent,
            authorized.session_id,
            authorized.nonce,
            self.seal_key,
        )
        if not hmac.compare_digest(expected, authorized.seal):
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "SEAL_MISMATCH")
        if authorized.nonce in self._nonces:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "NONCE_REPLAY")
        if proposal.action_id in self._journal:
            self._metrics["dispatch_denials"] += 1
            return AdapterResult(ExecutionState.NOT_STARTED, "DUPLICATE_ACTION")

        self._journal[proposal.action_id] = "PENDING"
        self._nonces.add(authorized.nonce)
        self._metrics["dispatch_attempts"] += 1
        self._metrics["transport_calls"] += 1
        try:
            result = self.engine.dispatch(authorized)
        except CandidateDispatchError as exc:
            if exc.dispatched is False:
                self._journal[proposal.action_id] = "REJECTED"
                return AdapterResult(ExecutionState.NOT_STARTED, "CANDIDATE_REJECTED")
            self._journal[proposal.action_id] = "UNKNOWN"
            self._metrics["unknown_outcomes"] += 1
            return AdapterResult(
                ExecutionState.UNKNOWN_OUTCOME,
                "UNKNOWN_OUTCOME",
                dispatched=True,
            )
        except Exception:  # noqa: BLE001 - crossing the boundary is uncertain
            self._journal[proposal.action_id] = "UNKNOWN"
            self._metrics["unknown_outcomes"] += 1
            return AdapterResult(
                ExecutionState.UNKNOWN_OUTCOME,
                "UNKNOWN_OUTCOME",
                dispatched=True,
            )
        if not isinstance(result, DispatchResult):
            self._journal[proposal.action_id] = "UNKNOWN"
            self._metrics["unknown_outcomes"] += 1
            return AdapterResult(
                ExecutionState.UNKNOWN_OUTCOME,
                "INVALID_DISPATCH_RESULT",
                dispatched=True,
            )
        if not result.dispatched:
            self._journal[proposal.action_id] = "REJECTED"
            return AdapterResult(ExecutionState.NOT_STARTED, "CANDIDATE_REJECTED")
        try:
            verified = bool(verify(proposal, result))
        except Exception:  # noqa: BLE001 - verification failure is not success
            verified = False
        if not verified:
            self._journal[proposal.action_id] = "UNKNOWN"
            self._metrics["unknown_outcomes"] += 1
            return AdapterResult(
                ExecutionState.UNKNOWN_OUTCOME,
                "VERIFICATION_FAILED",
                dispatched=True,
            )
        self._journal[proposal.action_id] = "COMPLETED"
        self._metrics["verified"] += 1
        return AdapterResult(
            ExecutionState.VERIFIED,
            proposal=proposal,
            dispatched=True,
            verified=True,
        )

    def _validate_proposal(
        self,
        proposal: ActionProposal,
        snapshot: ObservationSnapshot,
    ) -> str:
        if proposal.action not in _ALLOWED_ACTIONS[self.surface]:
            return "ACTION_NOT_ALLOWLISTED"
        if proposal.observation_id != snapshot.observation_id:
            return "STALE_TARGET"
        try:
            targets = [
                target
                for target in snapshot.targets
                if target.get("target_id") == proposal.target_id
            ]
        except AttributeError:
            return "OBSERVATION_INCOMPLETE"
        if len(targets) != 1:
            return "AMBIGUOUS_TARGET" if len(targets) > 1 else "STALE_TARGET"
        target_identity = targets[0].get("identity")
        if not isinstance(target_identity, Mapping):
            return "TARGET_IDENTITY_REQUIRED"
        if _plain(proposal.target_identity) != _plain(target_identity):
            return "TARGET_IDENTITY_MISMATCH"
        if snapshot.process_id is not None:
            candidate_pid = target_identity.get("process_id")
            nested = target_identity.get("process")
            if candidate_pid is None and isinstance(nested, Mapping):
                candidate_pid = nested.get("pid")
            if candidate_pid != snapshot.process_id:
                return "CROSS_PROCESS"
        return ""


__all__ = [
    "ActionProposal",
    "AdapterMode",
    "AdapterResult",
    "AuthorizedAction",
    "CandidateDispatchError",
    "ControlSurface",
    "DispatchResult",
    "ObservationSnapshot",
    "SafeEngineAdapter",
    "make_authorized_action",
    "mode_from_env",
]
