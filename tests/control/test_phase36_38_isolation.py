"""Phase 36-38 direct-boundary, UFO contract, and RPC tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from openjarvis.control import (
    AdapterMode,
    ControlSurface,
    DirectMutationBoundary,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    UfoProposalAdapter,
    UfoProposalError,
    UfoRpcError,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from openjarvis.control.browser_dispatch import BrowserDispatchFacade
from openjarvis.control.browser_use_schema import extract_browser_use_action_schema
from openjarvis.control.oss_adapter import make_authorized_action
from openjarvis.core.execution import ExecutionState, MutationIntent

_KEY = b"phase36-38-test-only-key"
_BROWSER_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / ".astra-artifacts"
    / "phase30-32-20261025"
    / "browser-use-action-schema.json"
)


class _FakeExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def dispatch(self, _authorized):
        self.calls += 1
        return DispatchResult(True, {"calls": self.calls})


def _ufo_snapshot(
    *,
    observation_id="obs-ufo-1",
    process_id=41,
    identity_overrides=None,
    targets=None,
):
    identity = {
        "session_id": "ufo-session",
        "process_id": 41,
        "process_created": 123,
        "hwnd": 500,
        "foreground_hwnd": 500,
        "window_cookie": "window-cookie-1",
        "runtime_id": [1, 2],
    }
    identity.update(identity_overrides or {})
    if targets is None:
        targets = ({"target_id": "control-1", "identity": identity},)
    return ObservationSnapshot(
        ControlSurface.WINDOWS_APP,
        observation_id,
        tuple(targets),
        privacy="PUBLIC",
        process_id=process_id,
    )


def _ufo_action(function="type", *, target_id="control-1", params=None):
    if params is None:
        params = {"text": "fixture"}
    return {
        "function": function,
        "arguments": {"params": params},
        "target": {"kind": "control", "name": "fixture", "id": target_id},
    }


def _ufo_stack():
    executor = _FakeExecutor()
    host = SafeEngineAdapter(
        executor,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="ufo-session",
        seal_key=_KEY,
    )
    adapter = UfoProposalAdapter(session_id="ufo-session")
    return adapter, host, executor


def _browser_facade():
    evidence = json.loads(_BROWSER_EVIDENCE.read_text(encoding="utf-8"))
    rows = {
        item["sdk_action"]: {"schema": item["sdk_schema"]}
        for item in evidence["actions"]
    }
    schema = extract_browser_use_action_schema(rows, version=evidence["version"])
    host = SafeEngineAdapter(
        _FakeExecutor(),
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="browser-session",
        seal_key=_KEY,
    )
    return BrowserDispatchFacade(schema, host=host, session_id="browser-session")


def test_direct_boundary_never_evaluates_callbacks_or_allows_alternate_executor():
    boundary = DirectMutationBoundary(
        "browser",
        {"Agent.run", "Tools.click", "internal_retry"},
    )
    calls = []
    for entrypoint in ("Agent.run", "Tools.click", "internal_retry", "other"):
        decision = boundary.invoke(entrypoint, lambda: calls.append(entrypoint))
        assert decision.allowed is False
        assert decision.dispatched is False
        assert decision.verified is False
        assert decision.retryable is False
    assert calls == []


def test_browser_facade_denies_agent_tools_retry_and_fallback_bypass():
    facade = _browser_facade()
    calls = []
    for entrypoint in (
        "Agent.run",
        "Tools.click",
        "internal_retry",
        "alternate_executor",
    ):
        decision = facade.invoke_direct_sdk(
            entrypoint,
            lambda: calls.append(entrypoint),
        )
        assert decision.allowed is False
        assert decision.failure.startswith("DIRECT_")
    assert calls == []


def test_ufo_contract_is_real_source_shaped_and_direct_dispatch_is_denied():
    adapter, _, _ = _ufo_stack()
    rows = adapter.contract_matrix()
    assert len(rows) == 6
    assert {row["ufo_function"] for row in rows} == {
        "click_input",
        "set_edit_text",
        "keyboard_input",
        "key_press",
        "scroll",
        "type",
    }
    assert all(row["direct_dispatch"] == "DENIED" for row in rows)
    assert all(row["retry"] == "ATLAS_ONLY" for row in rows)
    calls = []
    decision = adapter.invoke_direct_sdk(
        "ActionExecutor.execute",
        lambda: calls.append("executed"),
    )
    assert decision.allowed is False
    assert decision.failure == "DIRECT_SDK_DISPATCH_DENIED"
    assert calls == []


def test_ufo_proposal_reaches_safety_authority_and_fake_executor_once():
    adapter, host, executor = _ufo_stack()
    snapshot = _ufo_snapshot()
    proposal = adapter.propose(
        _ufo_action("type"),
        snapshot,
        action_id="ufo-action-1",
    )
    authorized = make_authorized_action(
        proposal,
        MutationIntent("execution-ufo", "step-ufo", "intent-ufo"),
        session_id="ufo-session",
        nonce="ufo-nonce-1",
        key=_KEY,
    )
    result = host.execute(
        proposal,
        snapshot,
        authorized=authorized,
        verify=lambda _proposal, dispatch: dispatch.dispatched,
    )
    assert result.state is ExecutionState.VERIFIED
    assert result.verified is True
    assert executor.calls == 1


def test_ufo_adapter_accepts_real_action_command_metadata_without_trusting_it():
    adapter, _, _ = _ufo_stack()
    action = _ufo_action()
    action.update(
        {
            "status": "",
            "result": {"status": "none"},
            "action_string": "type(params=...)",
            "action_representation": "",
        }
    )
    proposal = adapter.propose(
        action,
        _ufo_snapshot(),
        action_id="real-contract-shape",
    )
    assert proposal.action == "ufo_sdk_type"


@pytest.mark.parametrize(
    ("identity_overrides", "expected"),
    [
        ({"process_id": 42}, "CROSS_PROCESS"),
        ({"foreground_hwnd": 501}, "WRONG_FOREGROUND"),
        ({"session_id": "other"}, "SESSION_MISMATCH"),
    ],
)
def test_ufo_target_identity_is_fail_closed(identity_overrides, expected):
    adapter, _, _ = _ufo_stack()
    with pytest.raises(UfoProposalError, match=expected):
        adapter.propose(
            _ufo_action(),
            _ufo_snapshot(identity_overrides=identity_overrides),
            action_id="identity-failure",
        )


def test_ufo_stale_ambiguous_wrong_target_and_payload_are_denied():
    adapter, host, executor = _ufo_stack()
    original = _ufo_snapshot()
    proposal = adapter.propose(_ufo_action(), original, action_id="stale-ufo")
    auth = make_authorized_action(
        proposal,
        MutationIntent("e", "s", "i"),
        session_id="ufo-session",
        nonce="stale-nonce",
        key=_KEY,
    )
    stale = host.execute(
        proposal,
        _ufo_snapshot(observation_id="obs-ufo-2"),
        authorized=auth,
        verify=lambda *_: True,
    )
    assert stale.failure == "STALE_TARGET"
    assert executor.calls == 0

    with pytest.raises(UfoProposalError, match="STALE_TARGET"):
        adapter.propose(
            _ufo_action(target_id="missing"),
            original,
            action_id="wrong-target",
        )

    ambiguous = _ufo_snapshot(
        targets=(
            {"target_id": "control-1", "identity": original.targets[0]["identity"]},
            {"target_id": "control-1", "identity": original.targets[0]["identity"]},
        )
    )
    with pytest.raises(UfoProposalError, match="AMBIGUOUS_TARGET"):
        adapter.propose(_ufo_action(), ambiguous, action_id="ambiguous")

    tampered = replace(
        auth,
        proposal=replace(proposal, arguments={"params": {"text": "other"}}),
    )
    result = host.execute(
        proposal,
        original,
        authorized=tampered,
        verify=lambda *_: True,
    )
    assert result.failure == "AUTHORIZATION_MISMATCH"
    assert executor.calls == 0


@pytest.mark.parametrize("keys", [7, ["CTRL", 7]])
def test_ufo_keyboard_payload_type_is_fail_closed(keys):
    adapter, _, _ = _ufo_stack()
    with pytest.raises(UfoProposalError, match="INVALID_KEYS_VALUE"):
        adapter.propose(
            _ufo_action("keyboard_input", params={"keys": keys}),
            _ufo_snapshot(),
            action_id="invalid-keys",
        )


@pytest.mark.parametrize(
    "function",
    [
        "atomic_execution",
        "click_on_coordinates",
        "execute_command",
        "execute_all_commands",
        "save",
    ],
)
def test_ufo_dynamic_or_alternate_mutation_entrypoints_are_unsupported(function):
    adapter, _, _ = _ufo_stack()
    with pytest.raises(UfoProposalError, match="UNSUPPORTED_ACTION"):
        adapter.propose(
            _ufo_action(function),
            _ufo_snapshot(),
            action_id="unsupported",
        )


def test_ufo_rpc_round_trip_binds_session_nonce_and_request():
    action = _ufo_action()
    raw = encode_request(
        request_id="request-1",
        session_id="ufo-session",
        nonce="nonce-1",
        observation_id="obs-ufo-1",
        action=action,
    )
    request = decode_request(raw)
    assert request["action"] == action
    response_raw = encode_response(
        request_id="request-1",
        session_id="ufo-session",
        nonce="nonce-1",
        status="PROPOSAL",
        proposal={"action": "ufo_sdk_type"},
    )
    response = decode_response(
        response_raw,
        request_id="request-1",
        session_id="ufo-session",
        nonce="nonce-1",
    )
    assert response["status"] == "PROPOSAL"


def test_ufo_rpc_rejects_extra_keys_tampering_and_oversize():
    raw = encode_request(
        request_id="request-2",
        session_id="ufo-session",
        nonce="nonce-2",
        observation_id="obs-ufo-1",
        action=_ufo_action(),
    )
    payload = json.loads(raw)
    payload["extra"] = "deny"
    with pytest.raises(UfoRpcError, match="RPC_REQUEST_KEYS_INVALID"):
        decode_request(json.dumps(payload))

    response = encode_response(
        request_id="request-2",
        session_id="ufo-session",
        nonce="nonce-2",
        status="DENIED",
        error="FAIL_CLOSED",
    )
    with pytest.raises(UfoRpcError, match="RPC_SESSION_MISMATCH"):
        decode_response(
            response,
            request_id="request-2",
            session_id="other-session",
            nonce="nonce-2",
        )

    missing_proposal = json.loads(
        encode_response(
            request_id="request-2",
            session_id="ufo-session",
            nonce="nonce-2",
            status="PROPOSAL",
            proposal={"action": "ufo_sdk_type"},
        )
    )
    missing_proposal["proposal"] = None
    with pytest.raises(UfoRpcError, match="RPC_PROPOSAL_REQUIRED"):
        decode_response(
            json.dumps(missing_proposal),
            request_id="request-2",
            session_id="ufo-session",
            nonce="nonce-2",
        )

    with pytest.raises(UfoRpcError, match="RPC_MESSAGE_TOO_LARGE"):
        decode_request(b"{" + b'"x":"' + b"a" * 20000 + b'"}')


def test_ufo_rpc_to_proposal_isolated_e2e_has_no_worker_execution():
    adapter, host, executor = _ufo_stack()
    snapshot = _ufo_snapshot()
    raw = encode_request(
        request_id="request-3",
        session_id="ufo-session",
        nonce="nonce-3",
        observation_id=snapshot.observation_id,
        action=_ufo_action("click_input", params={"button": "left"}),
    )
    request = decode_request(raw)
    proposal = adapter.propose(
        request["action"],
        snapshot,
        action_id=request["request_id"],
    )
    authorized = make_authorized_action(
        proposal,
        MutationIntent("e3", "s3", "i3"),
        session_id="ufo-session",
        nonce=request["nonce"],
        key=_KEY,
    )
    result = host.execute(
        proposal,
        snapshot,
        authorized=authorized,
        verify=lambda _proposal, dispatch: dispatch.dispatched,
    )
    assert result.state is ExecutionState.VERIFIED
    assert executor.calls == 1
