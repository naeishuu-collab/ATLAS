"""Durable, sequential execution of host-authorized browser mutations.

This internal API accepts only host-owned observations and verifiers. It does
not issue authorizations or expose a worker directly to an untrusted caller.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from openjarvis.control.browser_dispatch import BrowserDispatchFacade
from openjarvis.control.browser_use_schema import BrowserUseSchemaError
from openjarvis.control.oss_adapter import (
    AdapterResult,
    AuthorizedAction,
    ControlSurface,
    ObservationSnapshot,
)
from openjarvis.core.execution import ExecutionState
from openjarvis.tools.execution_journal import ExecutionJournal


@dataclass(frozen=True, slots=True)
class AuthorizedBatchStep:
    authorization: AuthorizedAction
    action: Mapping[str, Any]
    observe: Callable[[], ObservationSnapshot]
    verify: Callable[..., bool]


def execute_authorized_batch(
    facade: BrowserDispatchFacade,
    journal: ExecutionJournal,
    scope: str,
    steps: Sequence[AuthorizedBatchStep],
) -> list[AdapterResult]:
    """Dispatch each preauthorized action once and stop at the first uncertainty."""
    if not isinstance(steps, Sequence) or not 1 <= len(steps) <= 32:
        raise ValueError("Invalid batch size")
    steps = tuple(steps)
    if (
        not isinstance(facade, BrowserDispatchFacade)
        or not isinstance(journal, ExecutionJournal)
        or not isinstance(scope, str)
        or not scope.strip()
        or not 1 <= len(steps) <= 32
    ):
        raise ValueError("Invalid batch host, journal, scope or size")
    action_ids = set()
    intents = set()
    actions = []
    for step in steps:
        if (
            not isinstance(step, AuthorizedBatchStep)
            or not isinstance(step.authorization, AuthorizedAction)
            or not callable(step.observe)
            or not callable(step.verify)
            or not step.authorization.proposal.mutation
            or step.authorization.session_id != facade._host.session_id
            or step.authorization.proposal.action
            not in {
                "browser_sdk_click",
                "browser_sdk_input",
                "browser_sdk_select_dropdown",
            }
        ):
            raise ValueError(
                "Every batch step needs host authorization and verification"
            )
        try:
            action_data = json.loads(json.dumps(step.action, ensure_ascii=True))
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid batch action") from exc
        if not isinstance(action_data, dict):
            raise ValueError("Invalid batch action")
        actions.append(action_data)
        action = step.authorization.proposal
        intent = step.authorization.intent
        identity = (intent.execution_id, intent.step_id, intent.mutation_intent_id)
        if action.action_id in action_ids or identity in intents:
            raise ValueError("Duplicate batch action or mutation intent")
        action_ids.add(action.action_id)
        intents.add(identity)

    results = []
    for step, action_data in zip(steps, actions):
        authorized = step.authorization
        proposal = authorized.proposal
        try:
            observation = step.observe()
            if (
                not isinstance(observation, ObservationSnapshot)
                or observation.surface is not ControlSurface.BROWSER
            ):
                raise ValueError("Invalid browser observation")
            observation.public_payload()
        except Exception:
            results.append(
                AdapterResult(ExecutionState.NOT_STARTED, "OBSERVATION_DENIED")
            )
            break
        if observation.observation_id != proposal.observation_id:
            results.append(AdapterResult(ExecutionState.NOT_STARTED, "STALE_TARGET"))
            break
        try:
            candidate = facade.propose(
                action_data, observation, action_id=proposal.action_id
            )
        except BrowserUseSchemaError as exc:
            results.append(AdapterResult(ExecutionState.NOT_STARTED, exc.reason))
            break
        if candidate != proposal:
            results.append(
                AdapterResult(ExecutionState.NOT_STARTED, "AUTHORIZATION_MISMATCH")
            )
            break
        try:
            claim = journal.reserve_intent(
                scope, "computer_use_browser", proposal.action_id, authorized.intent
            )
        except Exception:
            results.append(AdapterResult(ExecutionState.NOT_STARTED, "JOURNAL_ERROR"))
            break
        token = claim.get("token")
        if not token:
            state = claim.get("state")
            results.append(
                AdapterResult(
                    ExecutionState.UNKNOWN_OUTCOME
                    if state in {"PREPARED", "EXECUTING", "EXECUTED", "UNKNOWN_OUTCOME"}
                    else ExecutionState.NOT_STARTED,
                    claim.get("failure", "DENIED"),
                )
            )
            break
        try:
            if not journal.begin_dispatch(token):
                results.append(AdapterResult(ExecutionState.NOT_STARTED, "CANCELLED"))
                break
            result = facade.dispatch(
                action_data,
                observation,
                action_id=proposal.action_id,
                authorized=authorized,
                verify=step.verify,
            ).adapter_result
            if result.state is ExecutionState.NOT_STARTED and not result.dispatched:
                journal.mark_not_dispatched(
                    token, evidence="Host rejected before dispatch"
                )
            else:
                journal.finish(
                    token,
                    uncertain=result.state is not ExecutionState.VERIFIED,
                    state=result.state.value,
                )
        except Exception:
            try:
                journal.finish(token, uncertain=True)
            except Exception:
                pass
            result = AdapterResult(
                ExecutionState.UNKNOWN_OUTCOME, "JOURNAL_OR_DISPATCH_ERROR"
            )
        results.append(result)
        if result.state is not ExecutionState.VERIFIED:
            break
    return results
