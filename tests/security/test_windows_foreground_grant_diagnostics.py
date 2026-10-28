"""Deterministic diagnostics coverage; no real Win32 foreground or mutation."""

import ctypes
import os
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from tests.security.windows_mutation_fixture import (
    Application,
    FixtureProcess,
    _foreground_context,
    _grant_foreground,
    _identity_digest,
    _validate_grant_evidence,
    _validate_registered_identity,
    _window_identity,
)


@pytest.mark.parametrize("raw,error", [(1, 87), (0, 5), (0, 0)])
@pytest.mark.parametrize("helper", [False, True])
def test_grant_captures_immediate_error_once(monkeypatch, raw, error, helper):
    events = []
    last_error = [999]  # A stale value must be cleared before the call.

    def set_error(value):
        events.append("clear")
        last_error[0] = value

    def grant(pid):
        events.append("grant")
        assert pid == 123
        assert last_error[0] == 0
        last_error[0] = error
        return raw

    def get_error():
        events.append("capture")
        return last_error[0]

    monkeypatch.setattr(ctypes, "set_last_error", set_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", get_error, raising=False)
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_timing_snapshot",
        lambda user, event, process_pid=None, process_thread_id=None: {
            "event": event,
            "process_pid": process_pid,
            "process_thread_id": process_thread_id,
            "monotonic_timestamp": len(events),
            "foreground_hwnd": 900,
            "foreground_pid": 901,
            "foreground_thread_id": 902,
            "last_input_tick": 100,
            "current_tick": 101,
            "foreground_lock_timeout": 102,
            "api_bool": None,
            "last_error": None,
            "focus_hwnd": None,
            "observation_limitations": [],
        },
    )
    user = Mock()
    user.AllowSetForegroundWindow.side_effect = grant
    app = Application.__new__(Application)
    app.user = user
    if helper:
        monkeypatch.setattr(
            "tests.security.windows_mutation_fixture._validate_registered_identity",
            lambda *args, **kwargs: (True, None, {}),
        )
    result = (
        app.command(
            "grant_foreground",
            {"pid": 123, "target_identity": {"pid": 123}},
        )
        if helper else _grant_foreground(user, 123)
    )
    assert result["granted"] is bool(raw)
    assert result["last_error"] == (error if not raw else None)
    prefix = "helper_" if helper else ""
    assert [item["event"] for item in result["timeline"]] == [
        f"{prefix}allow_set_foreground_window_before",
        f"{prefix}allow_set_foreground_window_result",
    ]
    assert result["timeline"][1]["api_bool"] is bool(raw)
    assert result["timeline"][1]["last_error"] == (error if not raw else None)
    assert events == ["clear", "grant"] + (["capture"] if not raw else [])
    assert user.mock_calls == [call.AllowSetForegroundWindow(123)]


@pytest.mark.parametrize(
    "runner,delegated,alive,foreground,expected",
    [
        (True, None, True, 900, True),
        (False, None, True, 900, False),
        (False, True, True, 200, True),
        (True, False, True, 200, False),
        (False, True, False, 200, False),
        (False, True, True, 100, False),
    ],
)
def test_focus_preserves_grant_delegation_and_requests(
    monkeypatch, runner, delegated, alive, foreground, expected
):
    user = Mock()
    user.GetForegroundWindow.return_value = foreground
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=user), raising=False)
    runner_result = {
        "granted": runner,
        "last_error": None if runner else 0,
        "timeline": [{"event": "runner_grant"}],
    }
    grant = Mock(return_value=runner_result)
    monkeypatch.setattr("tests.security.windows_mutation_fixture._grant_foreground", grant)
    context = Mock(return_value={"foreground_eligibility": "UNKNOWN"})
    monkeypatch.setattr("tests.security.windows_mutation_fixture._foreground_context", context)
    source = SimpleNamespace(
        hwnd=200, pid=222, process=Mock(),
        rpc=Mock(
            return_value={
                "granted": delegated,
                "last_error": None if delegated else 5,
                "timeline": [{"event": "delegated_grant"}],
            }
        ),
    )
    source.process.is_alive.return_value = alive
    app = FixtureProcess.__new__(FixtureProcess)
    app.pid, app.hwnd = 111, 100
    monkeypatch.setattr(FixtureProcess, "live", [app, source])
    app.process = Mock()
    state = {
        "foreground": 100, "focus": 101,
        "snapshot": {"controls": {"201": {"hwnd": 101}}},
        "foreground_request_accepted": True, "count": 0, "events": [],
    }
    app.rpc = Mock(return_value=state)
    identity = _identity_record(app.pid, app.hwnd, 101)
    app.rpc.side_effect = lambda command, args: (
        {"native_evidence": True, "identity": identity}
        if command == "verified_identity"
        else state
    )
    result = app.focus()
    grant.assert_called_once_with(user, 111, event_prefix="runner_allow_set_foreground_window")
    context.assert_called_once_with(user, 111, foreground, [app, source])
    expected_rpc = ["focus"]
    if foreground == source.hwnd and alive:
        expected_rpc.insert(0, "verified_identity")
    assert [item.args[0] for item in app.rpc.call_args_list] == expected_rpc
    if foreground == source.hwnd and alive:
        source.rpc.assert_called_once_with(
            "grant_foreground",
            {
                "pid": 111,
                "target_identity": identity,
            },
        )
        assert result["foreground_grant_diagnostics"]["delegated_grant"] == source.rpc.return_value
    else:
        source.rpc.assert_not_called()
        assert result["foreground_grant_diagnostics"]["delegated_grant"] is None
    assert result["scoped_foreground_grant"] is expected
    assert result["foreground_request_accepted"] is True
    assert result["count"] == 0 and result["events"] == []
    assert result["foreground_grant_diagnostics"]["runner_grant"] == runner_result
    assert result["foreground_grant_diagnostics"]["timeline"] == (
        runner_result["timeline"]
        + ([{"event": "delegated_grant"}] if foreground == source.hwnd and alive else [])
    )


@pytest.mark.parametrize("raw,error", [(1, 87), (0, 5), (0, 0)])
def test_helper_focus_timeline_captures_result_and_final_state(
    monkeypatch, raw, error
):
    events = []
    last_error = [999]

    def set_error(value):
        events.append("clear")
        last_error[0] = value

    def set_foreground(hwnd):
        events.append("set_foreground")
        assert hwnd == 500
        last_error[0] = error
        return raw

    def get_error():
        events.append("capture")
        return last_error[0]

    monkeypatch.setattr(ctypes, "set_last_error", set_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", get_error, raising=False)
    snapshots = [
        {
            "event": "before",
            "monotonic_timestamp": 1,
            "observation_limitations": [],
        },
        {
            "event": "final",
            "monotonic_timestamp": 3,
            "observation_limitations": [],
        },
    ]
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_timing_snapshot",
        lambda *args, **kwargs: snapshots.pop(0).copy(),
    )
    user = Mock()
    user.SetForegroundWindow.side_effect = set_foreground
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app.count = 0
    app.handles = {201: 501}
    app.state = Mock(return_value={"foreground": 500, "focus": 501})

    result = app.command("focus", {"control_id": 201})

    assert result["foreground_request_accepted"] is bool(raw)
    assert result["foreground_timeline"][0]["event"] == "before"
    assert result["foreground_timeline"][1]["event"] == "helper_set_foreground_window_result"
    assert result["foreground_timeline"][1]["api_bool"] is bool(raw)
    assert result["foreground_timeline"][1]["last_error"] == (error if not raw else None)
    assert result["foreground_timeline"][2]["event"] == "final"
    assert result["foreground_timeline"][2]["focus_hwnd"] == 501
    assert events == ["clear", "set_foreground"] + (["capture"] if not raw else [])
    user.SetForegroundWindow.assert_called_once_with(500)
    user.SetFocus.assert_called_once_with(501)
    user.AllowSetForegroundWindow.assert_not_called()


@pytest.mark.parametrize("session_ok", [True, False])
def test_context_is_read_only_and_unknown_is_explicit(monkeypatch, session_ok):
    kernel, user = Mock(), Mock()

    def session(pid, output):
        output._obj.value = 7
        return session_ok

    def owner(hwnd, output):
        assert hwnd == 200
        output._obj.value = 222
        return 333

    kernel.ProcessIdToSessionId.side_effect = session
    user.GetWindowThreadProcessId.side_effect = owner
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    source = SimpleNamespace(hwnd=200, process=Mock())
    source.process.is_alive.return_value = True
    result = _foreground_context(user, 111, 200, [source])
    assert result["runner_pid"] > 0 and result["runner_thread_id"] > 0
    assert result["helper_pid"] == 111
    for key in ("runner_session_id", "helper_session_id", "foreground_owner_session_id"):
        assert result[key] == (7 if session_ok else "UNKNOWN")
    assert result["foreground_owner_pid"] == 222
    assert result["foreground_owner_thread_id"] == 333
    assert result["foreground_is_live_fixture"] is True
    assert result["foreground_eligibility"] == "UNKNOWN"
    assert len(user.mock_calls) == 1
    assert len(kernel.mock_calls) == 3


def _identity_record(pid, hwnd, control_hwnd=None, session_id=7, created=100):
    desktop = {
        "session_id": session_id,
        "window_station_name": "WinSta0",
        "desktop_name": "Default",
        "interactive": True,
    }
    result = {
        "pid": pid,
        "created_filetime": created,
        "session_id": session_id,
        "hwnd": hwnd,
        "top_owner_pid": pid,
        "top_owner_thread_id": pid + 10,
        "top_ancestor_hwnd": hwnd,
        "top_is_top_level": True,
        "window_cookie": f"root-{pid}",
        "window_property_name": f"AstraProperty-{pid}",
        "window_property_marker": pid + 100,
        "channel_token": f"channel-{pid}",
        "desktop": desktop,
    }
    if control_hwnd is not None:
        result.update(
            {
                "control_id": "201",
                "control_hwnd": control_hwnd,
                "control_cookie": f"control-{pid}",
                "control_owner_pid": pid,
                "control_owner_thread_id": pid + 20,
                "control_property_marker": pid + 200,
            }
        )
    result["identity_digest"] = _identity_digest(result)
    return result


@pytest.mark.parametrize("child", [False, True])
def test_window_identity_observes_root_ancestor(monkeypatch, child):
    user = Mock()
    user.IsWindow.return_value = True
    user.GetWindowThreadProcessId.side_effect = (
        lambda hwnd, output: (setattr(output._obj, "value", 1234) or 1254)
    )
    user.GetAncestor.return_value = 600
    user.IsChild.return_value = True
    user.GetPropW.return_value = 700
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_session_id",
        lambda pid: 7,
    )

    result = _window_identity(
        user,
        601 if child else 600,
        top_hwnd=600 if child else None,
        property_name="cookie",
        property_marker=700,
    )

    assert result["ancestor_hwnd"] == 600
    assert result["is_top_level"] is (not child)
    assert result["is_descendant"] is True
    user.GetAncestor.assert_called_once()
    ancestor_args = user.GetAncestor.call_args.args
    assert ancestor_args[0].value == (601 if child else 600)
    assert ancestor_args[1] == 2


def _guardian_fixture(identity=None):
    identity = identity or _identity_record(2001, 2101)
    fixture = FixtureProcess.__new__(FixtureProcess)
    fixture.pid = identity["pid"]
    fixture.hwnd = identity["hwnd"]
    fixture._channel_token = identity.get("channel_token")
    fixture.process = Mock()
    fixture.process.is_alive.return_value = True
    fixture.state = Mock(return_value={"count": 0, "events": []})
    fixture.rpc = Mock()
    return fixture


def _target_fixture(identity=None):
    identity = identity or _identity_record(3001, 3101, 3201)
    fixture = FixtureProcess.__new__(FixtureProcess)
    fixture.pid = identity["pid"]
    fixture.hwnd = identity["hwnd"]
    fixture._channel_token = identity.get("channel_token")
    fixture.control_id = 201
    fixture.control_hwnd = identity["control_hwnd"]
    fixture.process = Mock()
    fixture.process.is_alive.return_value = True
    fixture.state = Mock(
        return_value={
            "count": 0,
            "events": [],
            "foreground": identity["hwnd"],
            "focus": identity["control_hwnd"],
        }
    )
    fixture.rpc = Mock()
    return fixture


def _observation(guardian, target, foreground=None, **overrides):
    foreground = foreground or guardian
    return {
        "activation_observed": True,
        "monotonic_timestamp": 1.0,
        "last_input_tick": 100,
        "current_tick": 110,
        "foreground_lock_timeout": 200000,
        "foreground": {
            "hwnd": foreground.hwnd,
            "pid": foreground.pid,
            "session_id": 7,
            "is_window": True,
        },
        **overrides,
    }


def _prepare_guardian_handoff(
    guardian,
    target,
    *,
    grant=True,
    error=None,
    focus=True,
    grant_override=None,
):
    guardian_identity = _identity_record(guardian.pid, guardian.hwnd)
    target_identity = _identity_record(
        target.pid, target.hwnd, target.control_hwnd
    )
    target_identity["identity_digest"] = _identity_digest(target_identity)
    grant_result = grant_override or {
        "state": "S3_GRANT_RESULT",
        "granted": grant,
        "native_bool": grant,
        "immediate_last_error": None if grant else error,
        "last_error": None if grant else error,
        "last_error_capture": (
            "not_applicable_on_success" if grant else "captured_on_failure"
        ),
        "requested_pid": target.pid,
        "grant_attempted": True,
        "grant_call_count": 1,
        "guardian_identity": {
            "pid": guardian.pid,
            "hwnd": guardian.hwnd,
            "session_id": 7,
            "is_window": True,
            "created_filetime": guardian_identity["created_filetime"],
            "desktop": guardian_identity["desktop"],
            "channel_token": guardian_identity["channel_token"],
        },
        "target_identity": target_identity,
        "failure": None if grant else "GRANT_REJECTED",
        "ordering": (
            [
                "guardian_identity_reverified",
                "target_identity_verified",
                "foreground_identity_reverified",
                "grant_call",
                "grant_returned",
            ]
            if grant
            else [
                "guardian_identity_reverified",
                "target_identity_verified",
                "foreground_identity_reverified",
                "grant_call",
                "last_error_captured",
            ]
        ),
        "timeline": [
            {"event": "verified_guardian_grant_before"},
            {
                "event": "verified_guardian_allow_set_foreground_window_result",
                "api_bool": bool(grant),
                "last_error": None if grant else error,
            },
        ],
    }
    focus_result = {
        "foreground_request_accepted": grant,
        "focus_attempted": grant,
        "failure": None if grant and focus else (
            "TARGET_FOCUS_REJECTED" if grant else "TARGET_FOREGROUND_REJECTED"
        ),
        "foreground": target.hwnd,
        "focus": target.control_hwnd if focus else 0,
        "count": 0,
        "events": [],
        "foreground_timeline": [{"event": "target_focus"}],
    }

    def guardian_rpc(command, args):
        if command == "verified_identity":
            return {"native_evidence": True, "identity": guardian_identity}
        if command == "register_verified_handoff":
            return {
                "registered": True,
                "handoff_id": args["handoff_id"],
                "target_identity_digest": target_identity["identity_digest"],
                "target_identity": target_identity,
            }
        if command == "grant_foreground_verified":
            return grant_result
        raise AssertionError(command)

    def target_rpc(command, args):
        if command == "verified_identity":
            return {"native_evidence": True, "identity": target_identity}
        if command == "prepare_verified_handoff":
            return {
                "bound": True,
                "handoff_id": args["handoff_id"],
                "target_identity_digest": target_identity["identity_digest"],
                "target_channel_token": target_identity["channel_token"],
            }
        if command == "focus_from_verified_guardian":
            return focus_result
        raise AssertionError(command)

    guardian.rpc.side_effect = guardian_rpc
    target.rpc.side_effect = target_rpc
    return guardian_identity, target_identity, grant_result, focus_result


def _valid_no_attempt_result(guardian, target, failure):
    guardian_identity = _identity_record(guardian.pid, guardian.hwnd)
    target_identity = _identity_record(
        target.pid, target.hwnd, target.control_hwnd
    )
    return {
        "state": "S3_GRANT_RESULT",
        "failure": failure,
        "grant_attempted": False,
        "granted": None,
        "requested_pid": None,
        "guardian_identity": {
            "pid": guardian.pid,
            "hwnd": guardian.hwnd,
            "session_id": guardian_identity["session_id"],
            "is_window": True,
            "created_filetime": guardian_identity["created_filetime"],
            "desktop": guardian_identity["desktop"],
            "channel_token": guardian_identity["channel_token"],
        },
        "target_identity": target_identity,
        "native_bool": None,
        "immediate_last_error": None,
        "last_error": None,
        "last_error_capture": "not_attempted",
        "grant_call_count": 0,
        "ordering": ["guardian_identity_reverified"],
        "timeline": [
            {"event": "verified_guardian_grant_before"},
            {"event": "verified_guardian_ownership_changed"},
        ],
    }


def _run_handoff(monkeypatch, guardian, target, provider=None):
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._independent_target_verification",
        lambda identity: (True, None, {"native": True}),
    )
    return target.focus_from_verified_guardian(
        guardian,
        observation_provider=provider
        or (lambda phase, *_: _observation(guardian, target)),
    )


def test_verified_guardian_handoff_accepts_registered_identity_without_runner_grant(
    monkeypatch,
):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _, target_identity, _, _ = _prepare_guardian_handoff(guardian, target)

    result = _run_handoff(monkeypatch, guardian, target)

    assert result["success"] is True
    assert result["state"] == "S6_PROBE_COMPLETED"
    assert result["state_history"] == [
        "S0_FIXTURES_READY",
        "S1_AWAIT_USER_ACTIVATION",
        "S2_GUARDIAN_VERIFIED",
        "S3_GRANT_RESULT",
        "S4_TARGET_FOCUS_RESULT",
        "S5_TARGET_VERIFIED",
        "S6_PROBE_COMPLETED",
    ]
    assert [call_args.args[0] for call_args in guardian.rpc.call_args_list] == [
        "verified_identity",
        "register_verified_handoff",
        "grant_foreground_verified",
    ]
    grant_args = guardian.rpc.call_args_list[2].args[1]
    assert "target_pid" not in grant_args
    focus_args = target.rpc.call_args_list[2].args[1]
    assert "target_pid" not in focus_args
    assert focus_args["target_identity_digest"] == target_identity["identity_digest"]
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}
    assert result["dispatch_count"] == 0
    assert result["retry_count"] == 0


@pytest.mark.parametrize(
    "failure",
    [
        "INVALID_TARGET_PID",
        "TARGET_PROCESS_IDENTITY_MISMATCH",
        "TARGET_HWND_OWNER_MISMATCH",
        "CONTROL_IDENTITY_MISMATCH",
        "DESKTOP_IDENTITY_UNKNOWN",
    ],
)
def test_registration_failure_stops_before_grant_and_focus(failure):
    guardian = _guardian_fixture()
    target = _target_fixture()
    guardian_identity = _identity_record(guardian.pid, guardian.hwnd)
    target_identity = _identity_record(target.pid, target.hwnd, target.control_hwnd)

    def rpc(command, args):
        if command == "verified_identity":
            return {
                "native_evidence": True,
                "identity": (
                    guardian_identity if args == {} else target_identity
                ),
            }
        if command == "register_verified_handoff":
            return {"registered": False, "failure": failure}
        raise AssertionError(command)

    guardian.rpc.side_effect = rpc
    target.rpc.side_effect = lambda command, args: (
        {"native_evidence": True, "identity": target_identity}
        if command == "verified_identity"
        else {
            "bound": True,
            "handoff_id": args["handoff_id"],
            "target_identity_digest": target_identity["identity_digest"],
            "target_channel_token": target_identity["channel_token"],
        }
        if command == "prepare_verified_handoff"
        else (_ for _ in ()).throw(AssertionError(command))
    )
    result = target.focus_from_verified_guardian(
        guardian,
        observation_provider=lambda phase, *_: _observation(guardian, target),
    )
    assert result["failure"] == failure
    assert result["state"] == "S0_FIXTURES_READY"
    assert guardian.rpc.call_args_list[-1].args[0] == "register_verified_handoff"
    assert not any(
        item.args[0] == "grant_foreground_verified"
        for item in guardian.rpc.call_args_list
    )
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}


@pytest.mark.parametrize(
    "failure",
    [
        "GUARDIAN_OWNERSHIP_CHANGED",
        "TARGET_PROCESS_IDENTITY_MISMATCH",
        "TARGET_HWND_OWNER_MISMATCH",
        "CONTROL_IDENTITY_MISMATCH",
        "TARGET_IDENTITY_MISMATCH",
        "TARGET_FOCUS_UNKNOWN",
        "DESKTOP_IDENTITY_UNKNOWN",
    ],
)
def test_valid_no_attempt_rejection_preserves_exact_failure_and_stops(
    failure, monkeypatch
):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _prepare_guardian_handoff(
        guardian,
        target,
        grant_override=_valid_no_attempt_result(guardian, target, failure),
    )
    runner_grant = Mock(side_effect=AssertionError("runner grant fallback"))
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._grant_foreground", runner_grant
    )

    result = _run_handoff(monkeypatch, guardian, target)

    assert result["failure"] == failure
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}
    assert result["dispatch_count"] == 0
    assert result["retry_count"] == 0
    runner_grant.assert_not_called()
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.pop("guardian_identity"),
        lambda item: item.update(granted=True),
        lambda item: item.update(native_bool=True),
        lambda item: item.update(grant_call_count=1),
        lambda item: item.update(ordering=[]),
        lambda item: item.update(last_error=5),
    ],
)
def test_invalid_no_attempt_evidence_is_rejected_without_fallback(
    mutate, monkeypatch
):
    guardian = _guardian_fixture()
    target = _target_fixture()
    evidence = _valid_no_attempt_result(
        guardian, target, "GUARDIAN_OWNERSHIP_CHANGED"
    )
    mutate(evidence)
    _prepare_guardian_handoff(guardian, target, grant_override=evidence)
    runner_grant = Mock(side_effect=AssertionError("runner grant fallback"))
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._grant_foreground", runner_grant
    )

    result = _run_handoff(monkeypatch, guardian, target)

    assert result["failure"] == "GRANT_EVIDENCE_INVALID"
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}
    assert result["dispatch_count"] == 0
    assert result["retry_count"] == 0
    runner_grant.assert_not_called()
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.parametrize("error", [5, 0])
def test_grant_false_with_error_is_rejected_without_target_focus(error, monkeypatch):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _prepare_guardian_handoff(guardian, target, grant=False, error=error)
    result = _run_handoff(monkeypatch, guardian, target)
    assert result["failure"] == "GRANT_REJECTED"
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["scoped_foreground_grant"] is False
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.parametrize("pid", [0, -1, 0xFFFFFFFF, "123", None])
def test_legacy_grant_rejects_invalid_pid_before_native_call(pid):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    result = app.command("grant_foreground", {"pid": pid})

    assert result["failure"] == "INVALID_TARGET_PID"
    assert result["grant_attempted"] is False
    assert result["grant_call_count"] == 0
    user.AllowSetForegroundWindow.assert_not_called()


def test_legacy_grant_requires_native_target_identity_before_native_call():
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    result = app.command("grant_foreground", {"pid": 123})

    assert result["failure"] == "LEGACY_TARGET_IDENTITY_REQUIRED"
    assert result["grant_attempted"] is False
    assert result["grant_call_count"] == 0
    user.AllowSetForegroundWindow.assert_not_called()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda item: item.pop("guardian_identity"),
        lambda item: item.update(
            target_identity={**item["target_identity"], "identity_digest": "wrong"}
        ),
        lambda item: item.update(grant_call_count=0),
        lambda item: item.update(ordering=["grant_call"]),
        lambda item: item.update(state="S4_TARGET_FOCUS_RESULT"),
        lambda item: item.update(native_bool=True),
        lambda item: item.update(
            timeline=[{"event": "verified_guardian_grant_before"}]
        ),
    ],
)
def test_invalid_grant_failure_evidence_blocks_target_focus(mutate, monkeypatch):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _, _, grant_result, _ = _prepare_guardian_handoff(
        guardian, target, grant=False, error=5
    )
    mutate(grant_result)
    runner_grant = Mock(side_effect=AssertionError("runner grant fallback"))
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._grant_foreground", runner_grant
    )

    result = _run_handoff(monkeypatch, guardian, target)

    assert result["failure"] == "GRANT_EVIDENCE_INVALID"
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}
    assert result["dispatch_count"] == 0
    assert result["retry_count"] == 0
    runner_grant.assert_not_called()
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.parametrize(
    "timeline",
    [
        [],
        [{"event": "verified_guardian_grant_before"}],
        [
            {"event": "verified_guardian_grant_before"},
            {
                "event": "verified_guardian_allow_set_foreground_window_result",
                "api_bool": True,
                "last_error": None,
            },
            {
                "event": "verified_guardian_allow_set_foreground_window_result",
                "api_bool": True,
                "last_error": None,
            },
        ],
        [
            {
                "event": "verified_guardian_allow_set_foreground_window_result",
                "api_bool": True,
                "last_error": None,
            },
            {"event": "verified_guardian_grant_before"},
        ],
        [
            {"event": "verified_guardian_grant_before"},
            {
                "event": "verified_guardian_allow_set_foreground_window_result",
                "api_bool": False,
                "last_error": 5,
            },
        ],
    ],
)
def test_success_grant_rejects_missing_duplicate_reordered_or_failure_timeline(
    timeline, monkeypatch
):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _, _, grant_result, _ = _prepare_guardian_handoff(guardian, target)
    grant_result["timeline"] = timeline

    result = _run_handoff(monkeypatch, guardian, target)

    assert result["failure"] == "GRANT_EVIDENCE_INVALID"
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["mutation_counts"] == {"guardian": 0, "target": 0}
    assert result["dispatch_count"] == 0
    assert result["retry_count"] == 0
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.parametrize(
    "grant_override",
    [
        {"grant_attempted": True},
        {
            "grant_attempted": True,
            "granted": True,
            "native_bool": False,
            "immediate_last_error": 5,
            "last_error_capture": "captured_on_failure",
            "failure": None,
        },
        {
            "grant_attempted": False,
            "granted": True,
            "native_bool": True,
            "requested_pid": 3001,
            "grant_call_count": 1,
            "failure": None,
        },
    ],
)
def test_missing_or_contradictory_grant_evidence_blocks_target_focus(
    grant_override, monkeypatch
):
    guardian = _guardian_fixture()
    target = _target_fixture()
    _prepare_guardian_handoff(
        guardian,
        target,
        grant_override=grant_override,
    )
    result = _run_handoff(monkeypatch, guardian, target)
    assert result["failure"] == "GRANT_EVIDENCE_INVALID"
    assert result["state"] == "S3_GRANT_RESULT"
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


def test_guardian_ownership_change_is_exact_and_does_not_grant(monkeypatch):
    guardian = _guardian_fixture()
    target = _target_fixture()
    guardian_identity = _identity_record(guardian.pid, guardian.hwnd)
    target_identity = _identity_record(
        target.pid, target.hwnd, target.control_hwnd
    )
    no_attempt = {
        "state": "S3_GRANT_RESULT",
        "grant_attempted": False,
        "granted": None,
        "requested_pid": None,
        "guardian_identity": {
            "pid": guardian.pid,
            "hwnd": guardian.hwnd,
            "session_id": guardian_identity["session_id"],
            "is_window": True,
            "created_filetime": guardian_identity["created_filetime"],
            "desktop": guardian_identity["desktop"],
            "channel_token": guardian_identity["channel_token"],
        },
        "target_identity": target_identity,
        "native_bool": None,
        "immediate_last_error": None,
        "last_error": None,
        "last_error_capture": "not_attempted",
        "grant_call_count": 0,
        "ordering": ["guardian_identity_reverified"],
        "failure": "GUARDIAN_OWNERSHIP_CHANGED",
        "timeline": [
            {"event": "verified_guardian_grant_before"},
            {"event": "verified_guardian_ownership_changed"},
        ],
    }
    _prepare_guardian_handoff(
        guardian,
        target,
        grant_override=no_attempt,
    )
    result = _run_handoff(monkeypatch, guardian, target)
    assert result["failure"] == "GUARDIAN_OWNERSHIP_CHANGED"
    assert result["state"] == "S3_GRANT_RESULT"
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


def test_helper_rejects_unregistered_or_invalid_pid_before_grant(monkeypatch):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app._handoff_registry = {}
    result = app.command(
        "grant_foreground_verified",
        {
            "handoff_id": "missing",
            "guardian_pid": os.getpid(),
            "guardian_hwnd": 500,
            "guardian_session_id": 7,
        },
    )
    assert result["failure"] == "HANDOFF_NOT_REGISTERED"
    assert result["state"] == "S3_GRANT_RESULT"
    assert result["grant_attempted"] is False
    assert result["granted"] is None
    assert result["native_bool"] is None
    assert result["immediate_last_error"] is None
    assert result["last_error"] is None
    assert result["grant_call_count"] == 0
    assert result["ordering"] == []
    user.AllowSetForegroundWindow.assert_not_called()

    for pid in (0, -1, 0xFFFFFFFF, os.getpid()):
        identity = _identity_record(pid, 600, 601)
        app._handoff_registry = {
            "h": {
                "target_identity": identity,
                "target_identity_digest": _identity_digest(identity),
                "grant_count": 0,
            }
        }
        result = app.command(
            "grant_foreground_verified",
            {
                "handoff_id": "h",
                "guardian_pid": os.getpid(),
                "guardian_hwnd": 500,
                "guardian_session_id": 7,
            },
        )
        assert result["grant_attempted"] is False
        assert result["failure"] == "INVALID_TARGET_PID"
        assert result["granted"] is None
        assert result["last_error_capture"] == "not_attempted"
        assert result["grant_call_count"] == 0
    user.AllowSetForegroundWindow.assert_not_called()


def test_top_hwnd_identity_change_before_grant_blocks_allow(monkeypatch):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app.count = 0
    app._handoff_registry = {
        "h": {
            "target_identity": _identity_record(1234, 600, 601),
            "target_identity_digest": "digest",
            "grant_count": 0,
        }
    }
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._validate_registered_identity",
        lambda *args, **kwargs: (
            False,
            "TARGET_HWND_OWNER_MISMATCH",
            {"top": {"is_window": True, "ancestor_hwnd": 601}},
        ),
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_timing_snapshot",
        lambda *args, **kwargs: {"event": "before"},
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_session_id",
        lambda pid: 7,
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_identity",
        lambda user: {
            "hwnd": 500,
            "pid": os.getpid(),
            "session_id": 7,
            "is_window": True,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": 100,
            "session_id": 7,
            "alive": True,
            "failure": None,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._desktop_identity",
        lambda *args, **kwargs: {
            "session_id": 7,
            "window_station_name": "WinSta0",
            "desktop_name": "Default",
            "interactive": True,
        },
    )

    result = app.command(
        "grant_foreground_verified",
        {
            "handoff_id": "h",
            "guardian_pid": os.getpid(),
            "guardian_hwnd": 500,
            "guardian_session_id": 7,
        },
    )

    assert result["failure"] == "TARGET_HWND_OWNER_MISMATCH"
    assert result["grant_attempted"] is False
    assert app.count == 0
    user.AllowSetForegroundWindow.assert_not_called()


def test_top_hwnd_identity_change_before_focus_blocks_foreground(monkeypatch):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app.count = 0
    app.events = []
    app._focus_handoffs = set()
    identity = _identity_record(os.getpid(), 500, 501)
    app.channel_token = identity["channel_token"]
    app._target_handoff_registry = {
        "h": {
            "target_identity_digest": identity["identity_digest"],
            "target_channel_token": identity["channel_token"],
        }
    }
    changed = {**identity, "top_ancestor_hwnd": 999}
    changed["identity_digest"] = _identity_digest(changed)
    app._verified_identity = Mock(side_effect=[identity, changed])

    result = app.command(
        "focus_from_verified_guardian",
        {
                "handoff_id": "h",
                "target_identity_digest": identity["identity_digest"],
                "target_channel_token": identity["channel_token"],
                "control_id": 201,
        },
    )

    assert result["failure"] == "TARGET_IDENTITY_CHANGED"
    assert result["focus_attempted"] is False
    assert app.count == 0
    user.SetForegroundWindow.assert_not_called()
    user.SetFocus.assert_not_called()


def test_duplicate_grant_is_blocked_after_first_attempt(monkeypatch):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app._handoff_registry = {}
    identity = _identity_record(1234, 600, 601)
    app._handoff_registry["h"] = {
        "target_identity": identity,
        "target_identity_digest": identity["identity_digest"],
        "grant_count": 0,
    }
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": identity["created_filetime"],
            "session_id": 7,
            "alive": True,
            "failure": None,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._validate_registered_identity",
        lambda *args, **kwargs: (True, None, {}),
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_timing_snapshot",
        lambda *args, **kwargs: {"event": "before"},
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_identity",
        lambda user: {
            "hwnd": 500,
            "pid": os.getpid(),
            "session_id": 7,
            "is_window": True,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_session_id",
        lambda pid: 7,
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._desktop_identity",
        lambda *args, **kwargs: dict(identity["desktop"]),
    )
    monkeypatch.setattr(ctypes, "set_last_error", lambda value: None, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    user.AllowSetForegroundWindow.return_value = 1

    args = {
        "handoff_id": "h",
        "guardian_pid": os.getpid(),
        "guardian_hwnd": 500,
        "guardian_session_id": 7,
    }
    first = app.command("grant_foreground_verified", args)
    second = app.command("grant_foreground_verified", args)
    assert first["grant_attempted"] is True
    assert second["failure"] == "DUPLICATE_GRANT"
    user.AllowSetForegroundWindow.assert_called_once_with(1234)


def test_target_focus_rejects_duplicate_request(monkeypatch):
    user = Mock()
    app = Application.__new__(Application)
    app.user = user
    app.hwnd = 500
    app.count = 0
    app.events = []
    app._focus_handoffs = set()
    app.state = Mock(
        return_value={"count": 0, "events": [], "foreground": 500, "focus": 501}
    )
    identity = _identity_record(os.getpid(), 500, 501)
    app.channel_token = identity["channel_token"]
    app._target_handoff_registry = {
        "h": {
            "target_identity_digest": identity["identity_digest"],
            "target_channel_token": identity["channel_token"],
        }
    }

    app._verified_identity = Mock(return_value=identity)
    user.SetForegroundWindow.return_value = 1
    user.SetFocus.return_value = 777
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._foreground_timing_snapshot",
        lambda *args, **kwargs: {
            "event": "sample",
            "monotonic_timestamp": 1,
            "observation_limitations": [],
        },
    )
    monkeypatch.setattr(ctypes, "set_last_error", lambda value: None, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)

    args = {
        "handoff_id": "h",
        "target_identity_digest": identity["identity_digest"],
        "target_channel_token": identity["channel_token"],
        "control_id": 201,
    }
    first = app.command("focus_from_verified_guardian", args)
    second = app.command("focus_from_verified_guardian", args)
    assert first["failure"] is None
    assert second["failure"] == "DUPLICATE_FOCUS_REQUEST"
    user.SetForegroundWindow.assert_called_once_with(500)
    user.SetFocus.assert_called_once_with(501)


def test_window_and_desktop_validation_fail_closed(monkeypatch):
    identity = _identity_record(1234, 600, 601)
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": identity["created_filetime"],
            "session_id": 7,
            "alive": True,
            "failure": None,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._window_identity",
        lambda *args, **kwargs: {
            "is_window": True,
            "owner_pid": 9999,
            "owner_thread_id": 1,
            "owner_session_id": 7,
            "ancestor_hwnd": 600,
            "is_top_level": True,
            "cookie_valid": True,
            "is_descendant": True,
        },
    )
    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )
    assert not valid
    assert failure == "TARGET_HWND_OWNER_MISMATCH"

    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._window_identity",
        lambda *args, **kwargs: {
            "is_window": True,
            "owner_pid": 1234,
            "owner_thread_id": (
                1254 if kwargs.get("top_hwnd") is not None else 1244
            ),
            "owner_session_id": 7,
            "ancestor_hwnd": 600,
            "is_top_level": kwargs.get("top_hwnd") is None,
            "cookie_valid": True,
            "is_descendant": True,
        },
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._desktop_identity",
        lambda *args, **kwargs: {
            "session_id": 7,
            "window_station_name": "OtherStation",
            "desktop_name": "Default",
            "interactive": True,
        },
    )
    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )
    assert not valid
    assert failure == "DESKTOP_IDENTITY_UNKNOWN"


def test_cleanup_does_not_restore_foreground():
    app = FixtureProcess.__new__(FixtureProcess)
    app.connection = Mock()
    app.connection.closed = False
    app.process = Mock()
    app.process.is_alive.return_value = False
    app.guardian = Mock()
    app.rpc = Mock()
    app.live = []
    app.close_without_foreground_restore()
    app.rpc.assert_not_called()
    app.guardian.rpc.assert_not_called()
    app.connection.close.assert_called_once()


def test_live_no_restore_cleanup_has_no_foreground_calls(monkeypatch):
    app = FixtureProcess.__new__(FixtureProcess)
    app.connection = Mock()
    app.connection.closed = False
    app.process = Mock()
    app.process.is_alive.side_effect = [True, True, False, False]
    app.guardian = Mock()
    app.guardian.process.is_alive.return_value = True
    app.guardian.rpc.return_value = {
        "native_evidence": True,
        "identity": {"pid": 600, "hwnd": 601},
    }
    app.rpc = Mock()
    app.hwnd = 500
    app.live = []
    app._foreground_events = []
    user = Mock()
    user.GetForegroundWindow.return_value = 500
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=user), raising=False)

    app.close_without_foreground_restore()

    app.rpc.assert_not_called()
    app.guardian.rpc.assert_not_called()
    user.GetForegroundWindow.assert_not_called()
    app.connection.send_bytes.assert_called_once()
    app.connection.close.assert_called_once()
    assert app._cleanup_errors == []


def test_cleanup_rpc_failure_still_closes_helper(monkeypatch):
    app = FixtureProcess.__new__(FixtureProcess)
    app.connection = Mock()
    app.connection.closed = False
    app.process = Mock()
    app.process.is_alive.side_effect = [True, True, False, False]
    app.guardian = Mock()
    app.guardian.process.is_alive.return_value = True
    app.guardian.rpc.return_value = {
        "native_evidence": True,
        "identity": {"pid": 600, "hwnd": 601},
    }
    app.rpc = Mock(side_effect=RuntimeError("grant RPC failed"))
    app.hwnd = 500
    app.live = []
    user = Mock()
    user.GetForegroundWindow.return_value = 500
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=user), raising=False)

    with pytest.raises(RuntimeError, match="grant RPC failed"):
        app.close()

    app.connection.send_bytes.assert_called_once()
    app.process.join.assert_called()
    app.connection.close.assert_called_once()
    assert app._cleanup_errors


def test_context_manager_handoff_uses_no_restore_cleanup(monkeypatch):
    app = FixtureProcess.__new__(FixtureProcess)
    app.connection = Mock()
    app.connection.closed = False
    app.process = Mock()
    app.process.is_alive.side_effect = [True, True, False, False]
    app.guardian = Mock()
    app.guardian.process.is_alive.return_value = True
    app.rpc = Mock()
    app.hwnd = 500
    app.live = []
    app._handoff_cleanup_required = True
    user = Mock()
    user.GetForegroundWindow.return_value = 500
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=user), raising=False)

    app.__exit__(None, None, None)

    app.rpc.assert_not_called()
    user.GetForegroundWindow.assert_not_called()


def test_fixture_startup_malformed_ready_cleans_process_and_connections(monkeypatch):
    class FakeConnection:
        def __init__(self, payload=None):
            self.payload = payload
            self.closed = False

        def poll(self, _timeout):
            return True

        def recv_bytes(self):
            return self.payload

        def close(self):
            self.closed = True

    class FakeChild:
        def close(self):
            self.closed = True

    class FakeProcess:
        def __init__(self):
            self.alive = True
            self.terminated = False
            self.joins = []

        def start(self):
            return None

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.terminated = True
            self.alive = False

        def join(self, timeout):
            self.joins.append(timeout)

    class FakeContext:
        def __init__(self):
            self.parent = FakeConnection(b"not-json")
            self.events = FakeConnection()
            self.process = FakeProcess()
            self.pipe_count = 0

        def Pipe(self, duplex=True):
            self.pipe_count += 1
            if duplex:
                return self.parent, FakeChild()
            return self.events, FakeChild()

        def Process(self, **_kwargs):
            return self.process

    context = FakeContext()
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture.multiprocessing.get_context",
        lambda name: context,
    )

    with pytest.raises(Exception):
        FixtureProcess()

    assert context.process.terminated is True
    assert context.process.joins == [3]
    assert context.parent.closed is True
    assert context.events.closed is True


def _patch_valid_native_identity(monkeypatch, identity):
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": identity["created_filetime"],
            "session_id": identity["session_id"],
            "alive": True,
            "failure": None,
        },
    )

    def window_identity(_user, hwnd, **kwargs):
        if kwargs.get("top_hwnd") is None:
            return {
                "is_window": True,
                "owner_pid": identity["pid"],
                "owner_thread_id": identity["top_owner_thread_id"],
                "owner_session_id": identity["session_id"],
                "ancestor_hwnd": identity["hwnd"],
                "is_top_level": True,
                "cookie_valid": True,
                "is_descendant": True,
            }
        return {
            "is_window": True,
            "owner_pid": identity["pid"],
            "owner_thread_id": identity["control_owner_thread_id"],
            "owner_session_id": identity["session_id"],
            "cookie_valid": True,
            "is_descendant": True,
        }

    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._window_identity",
        window_identity,
    )
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._desktop_identity",
        lambda *args, **kwargs: dict(identity["desktop"]),
    )


def test_registered_identity_rejects_wrong_valid_pid(monkeypatch):
    identity = _identity_record(1234, 600, 601)
    _patch_valid_native_identity(monkeypatch, identity)
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid + 1,
            "created_filetime": identity["created_filetime"],
            "session_id": identity["session_id"],
            "alive": True,
            "failure": None,
        },
    )
    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )
    assert valid is False
    assert failure == "TARGET_PROCESS_IDENTITY_MISMATCH"


def test_registered_identity_rejects_pid_reuse(monkeypatch):
    identity = _identity_record(1234, 600, 601)
    _patch_valid_native_identity(monkeypatch, identity)
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": identity["created_filetime"] + 1,
            "session_id": identity["session_id"],
            "alive": True,
            "failure": None,
        },
    )
    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )
    assert valid is False
    assert failure == "TARGET_PROCESS_IDENTITY_MISMATCH"


@pytest.mark.parametrize(
    ("mutate_window", "expected"),
    [
        (
            lambda item: item.update({"owner_pid": 9999}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"cookie_valid": False}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"is_window": False}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"owner_thread_id": 9999}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"ancestor_hwnd": 601}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"is_top_level": False}),
            "TARGET_HWND_OWNER_MISMATCH",
        ),
        (
            lambda item: item.update({"is_descendant": False}),
            "CONTROL_IDENTITY_MISMATCH",
        ),
    ],
)
def test_registered_identity_rejects_window_reuse_owner_and_ancestry(
    monkeypatch, mutate_window, expected
):
    identity = _identity_record(1234, 600, 601)
    _patch_valid_native_identity(monkeypatch, identity)
    user = Mock()

    def window_identity(_user, hwnd, **kwargs):
        item = {
            "is_window": True,
            "owner_pid": identity["pid"],
            "owner_thread_id": (
                identity["control_owner_thread_id"]
                if kwargs.get("top_hwnd") is not None
                else identity["top_owner_thread_id"]
            ),
            "owner_session_id": identity["session_id"],
            "ancestor_hwnd": identity["hwnd"],
            "is_top_level": kwargs.get("top_hwnd") is None,
            "cookie_valid": True,
            "is_descendant": True,
        }
        if (
            expected == "TARGET_HWND_OWNER_MISMATCH"
            and kwargs.get("top_hwnd") is None
        ):
            mutate_window(item)
        elif (
            expected == "CONTROL_IDENTITY_MISMATCH"
            and kwargs.get("top_hwnd") is not None
        ):
            mutate_window(item)
        return item

    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._window_identity",
        window_identity,
    )
    valid, failure, _ = _validate_registered_identity(
        user, identity, own_pid=os.getpid()
    )
    assert valid is False
    assert failure == expected
    user.AllowSetForegroundWindow.assert_not_called()
    user.SetForegroundWindow.assert_not_called()
    user.SetFocus.assert_not_called()


def test_registered_identity_accepts_verified_top_level_hwnd(monkeypatch):
    identity = _identity_record(1234, 600, 601)
    _patch_valid_native_identity(monkeypatch, identity)

    valid, failure, observed = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )

    assert valid is True
    assert failure is None
    assert observed["top"]["ancestor_hwnd"] == identity["hwnd"]
    assert observed["top"]["is_top_level"] is True


@pytest.mark.parametrize("field", ["top_ancestor_hwnd", "top_is_top_level"])
def test_registered_identity_missing_top_level_evidence_fails_closed(
    monkeypatch, field
):
    identity = _identity_record(1234, 600, 601)
    identity.pop(field)
    _patch_valid_native_identity(monkeypatch, identity)

    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )

    assert valid is False
    assert failure == "TARGET_HWND_OWNER_MISMATCH"


@pytest.mark.parametrize("session_id", [8])
def test_registered_identity_rejects_wrong_session(monkeypatch, session_id):
    identity = _identity_record(1234, 600, 601, session_id=7)
    _patch_valid_native_identity(monkeypatch, identity)
    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._process_identity",
        lambda pid: {
            "pid": pid,
            "created_filetime": identity["created_filetime"],
            "session_id": session_id,
            "alive": True,
            "failure": None,
        },
    )
    valid, failure, _ = _validate_registered_identity(
        Mock(), identity, own_pid=os.getpid()
    )
    assert valid is False
    assert failure == "TARGET_PROCESS_IDENTITY_MISMATCH"


def test_missing_native_identity_evidence_stops_before_registration():
    guardian = _guardian_fixture()
    target = _target_fixture()

    guardian.rpc.side_effect = lambda command, args: (
        {"native_evidence": True, "identity": _identity_record(2001, 2101)}
        if command == "verified_identity"
        else (_ for _ in ()).throw(AssertionError(command))
    )
    target.rpc.side_effect = lambda command, args: (
        {
            "native_evidence": False,
            "identity": None,
            "failure": "NATIVE_IDENTITY_UNKNOWN",
        }
        if command == "verified_identity"
        else (_ for _ in ()).throw(AssertionError(command))
    )
    result = target.focus_from_verified_guardian(
        guardian,
        observation_provider=lambda phase, *_: _observation(guardian, target),
    )
    assert result["failure"] == "SETUP_INVALID"
    assert not any(
        item.args[0] == "register_verified_handoff"
        for item in guardian.rpc.call_args_list
    )
    assert not any(
        item.args[0] == "focus_from_verified_guardian"
        for item in target.rpc.call_args_list
    )


@pytest.mark.skipif(os.name != "nt", reason="Real spawned Win32 helpers")
def test_real_helper_guardian_handoff_ipc_with_foreground_doubles(monkeypatch):
    guardian = None
    target = None
    transport = []
    before_cleanup = None

    def runner_grant_forbidden(*args, **kwargs):
        raise AssertionError("runner-side foreground grant was called")

    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._grant_foreground",
        runner_grant_forbidden,
    )

    try:
        guardian = FixtureProcess()
        target = FixtureProcess()
        target.guardian = guardian
        guardian.rpc(
            "install_foreground_test_double",
            {
                "initial_foreground_hwnd": guardian.hwnd,
                "initial_focus_hwnd": 0,
                "allow_set_foreground_window_return": True,
            },
        )
        target.rpc(
            "install_foreground_test_double",
            {
                "initial_foreground_hwnd": guardian.hwnd,
                "initial_focus_hwnd": 0,
                "set_foreground_window_return": True,
                "set_focus_return": 1,
            },
        )

        guardian_identity = guardian.rpc("verified_identity")
        transport.append("guardian_verified_identity")
        target_identity = target.rpc(
            "verified_identity", {"control_id": 201}
        )
        transport.append("target_verified_identity")
        assert guardian_identity["native_evidence"] is True
        assert target_identity["native_evidence"] is True
        guardian_identity = guardian_identity["identity"]
        target_identity = target_identity["identity"]
        assert guardian_identity["pid"] == guardian.pid
        assert target_identity["pid"] == target.pid
        assert guardian.process.is_alive()
        assert target.process.is_alive()

        handoff_id = "real-ipc-success"
        binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": handoff_id,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        transport.append("target_bind")
        assert binding["bound"] is True
        registration = guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": handoff_id,
                "target_identity": target_identity,
                "target_channel_token": binding["target_channel_token"],
            },
        )
        transport.append("guardian_register")
        assert registration["registered"] is True
        assert (
            registration["target_identity_digest"]
            == target_identity["identity_digest"]
        )

        grant = guardian.rpc(
            "grant_foreground_verified",
            {
                "handoff_id": handoff_id,
                "guardian_pid": guardian_identity["pid"],
                "guardian_hwnd": guardian_identity["hwnd"],
                "guardian_session_id": guardian_identity["session_id"],
            },
        )
        transport.append("guardian_grant")
        assert grant["grant_attempted"] is True
        assert grant["native_bool"] is True
        assert grant["granted"] is True
        assert grant["requested_pid"] == target.pid
        assert grant["grant_call_count"] == 1
        evidence_ok, evidence_failure = _validate_grant_evidence(
            grant,
            target_identity,
            guardian_identity["pid"],
            guardian_identity["hwnd"],
            guardian_session_id=guardian_identity["session_id"],
            guardian_created_filetime=guardian_identity["created_filetime"],
            guardian_desktop=guardian_identity["desktop"],
            target_identity_digest=target_identity["identity_digest"],
        )
        assert evidence_ok is True, evidence_failure

        focus = target.rpc(
            "focus_from_verified_guardian",
            {
                "handoff_id": handoff_id,
                "target_identity_digest": target_identity["identity_digest"],
                "target_channel_token": binding["target_channel_token"],
                "control_id": 201,
            },
        )
        transport.append("target_focus")
        assert focus["failure"] is None
        assert focus["foreground_request_accepted"] is True
        assert focus["focus_attempted"] is True
        assert focus["foreground"] == target_identity["hwnd"]
        assert focus["focus"] == target_identity["control_hwnd"]

        verified_state = target.rpc("state")
        transport.append("target_independent_state")
        verified_identity = target.rpc(
            "verified_identity", {"control_id": 201}
        )
        transport.append("target_independent_identity")
        assert verified_state["foreground"] == target_identity["hwnd"]
        assert verified_state["focus"] == target_identity["control_hwnd"]
        assert verified_state["count"] == 0
        assert verified_state["events"] == []
        assert verified_identity["native_evidence"] is True
        assert (
            verified_identity["identity"]["identity_digest"]
            == target_identity["identity_digest"]
        )

        guardian_double = guardian.rpc("foreground_test_double_state")
        target_double = target.rpc("foreground_test_double_state")
        guardian_allow = [
            event
            for event in guardian_double["events"]
            if event["api"] == "AllowSetForegroundWindow"
        ]
        target_set_foreground = [
            event
            for event in target_double["events"]
            if event["api"] == "SetForegroundWindow"
        ]
        target_set_focus = [
            event
            for event in target_double["events"]
            if event["api"] == "SetFocus"
        ]
        assert len(guardian_allow) == 1
        assert guardian_allow[0]["process_pid"] == guardian.pid
        assert guardian_allow[0]["arguments"] == [target.pid]
        assert guardian_allow[0]["return_value"] == 1
        assert len(target_set_foreground) == 1
        assert target_set_foreground[0]["process_pid"] == target.pid
        assert target_set_foreground[0]["arguments"] == [target.hwnd]
        assert target_set_foreground[0]["return_value"] == 1
        assert len(target_set_focus) == 1
        assert target_set_focus[0]["process_pid"] == target.pid
        assert target_set_focus[0]["arguments"] == [target_identity["control_hwnd"]]
        assert target_set_focus[0]["return_value"] == 1
        assert transport.index("guardian_grant") < transport.index("target_focus")

        guardian_state = guardian.rpc("state")
        assert guardian_state["count"] == 0
        assert guardian_state["events"] == []
        assert guardian_state.get("dispatch_count", 0) == 0
        assert target_double["call_counts"]["SetForegroundWindow"] == 1
        assert target_double["call_counts"]["SetFocus"] == 1

        guardian.rpc(
            "configure_foreground_test_double",
            {
                "initial_foreground_hwnd": guardian.hwnd,
                "allow_set_foreground_window_return": False,
                "allow_set_foreground_window_error": 5,
            },
        )
        transport.append("guardian_configure_rejection")
        rejected_handoff = "real-ipc-rejected"
        rejected_binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": rejected_handoff,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        transport.append("target_bind_rejection")
        rejected_registration = guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": rejected_handoff,
                "target_identity": target_identity,
                "target_channel_token": rejected_binding[
                    "target_channel_token"
                ],
            },
        )
        transport.append("guardian_register_rejection")
        assert rejected_registration["registered"] is True
        rejected_grant = guardian.rpc(
            "grant_foreground_verified",
            {
                "handoff_id": rejected_handoff,
                "guardian_pid": guardian_identity["pid"],
                "guardian_hwnd": guardian_identity["hwnd"],
                "guardian_session_id": guardian_identity["session_id"],
            },
        )
        transport.append("guardian_grant_rejection")
        assert rejected_grant["grant_attempted"] is True
        assert rejected_grant["native_bool"] is False
        assert rejected_grant["failure"] == "GRANT_REJECTED"
        assert rejected_grant["requested_pid"] == target.pid
        assert rejected_grant["immediate_last_error"] == 5
        assert rejected_grant["grant_call_count"] == 1
        target_after_rejection = target.rpc("foreground_test_double_state")
        assert target_after_rejection["call_counts"]["SetForegroundWindow"] == 1
        assert target_after_rejection["call_counts"]["SetFocus"] == 1
        assert "target_focus_rejection" not in transport
        assert guardian.process.is_alive()
        assert target.process.is_alive()
        changing_apis = {
            "AllowSetForegroundWindow",
            "SetForegroundWindow",
            "SetFocus",
        }
        before_cleanup = {
            "guardian": [
                (event["api"], event["arguments"], event["return_value"])
                for event in guardian.foreground_events
                if event["api"] in changing_apis
            ],
            "target": [
                (event["api"], event["arguments"], event["return_value"])
                for event in target.foreground_events
                if event["api"] in changing_apis
            ],
        }
    finally:
        try:
            if target is not None:
                target.close_without_foreground_restore()
        finally:
            if guardian is not None:
                guardian.close_without_foreground_restore()
        if target is not None and guardian is not None and before_cleanup is not None:
            assert not target.process.is_alive()
            assert not guardian.process.is_alive()
            after_cleanup = {
                "guardian": [
                    (event["api"], event["arguments"], event["return_value"])
                    for event in guardian.foreground_events
                    if event["api"] in changing_apis
                ],
                "target": [
                    (event["api"], event["arguments"], event["return_value"])
                    for event in target.foreground_events
                    if event["api"] in changing_apis
                ],
            }
            assert after_cleanup == before_cleanup


@pytest.mark.skipif(os.name != "nt", reason="Real spawned Win32 helpers")
def test_real_helper_guardian_negative_identity_and_ordering_paths(monkeypatch):
    guardian = None
    target = None

    monkeypatch.setattr(
        "tests.security.windows_mutation_fixture._grant_foreground",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("runner-side foreground grant was called")
        ),
    )

    try:
        guardian = FixtureProcess()
        target = FixtureProcess()
        target.guardian = guardian
        guardian.rpc(
            "install_foreground_test_double",
            {
                "initial_foreground_hwnd": guardian.hwnd,
                "initial_focus_hwnd": 0,
                "allow_set_foreground_window_return": True,
            },
        )
        target.rpc(
            "install_foreground_test_double",
            {
                "initial_foreground_hwnd": guardian.hwnd,
                "initial_focus_hwnd": 0,
                "set_foreground_window_return": True,
                "set_focus_return": 1,
            },
        )
        guardian_identity = guardian.rpc("verified_identity")["identity"]
        target_identity = target.rpc(
            "verified_identity", {"control_id": 201}
        )["identity"]

        def clear_events(*, allow=True):
            guardian.rpc(
                "configure_foreground_test_double",
                {
                    "clear_events": True,
                    "allow_set_foreground_window_return": allow,
                    "allow_set_foreground_window_error": 5,
                },
            )
            target.rpc(
                "configure_foreground_test_double",
                {
                    "clear_events": True,
                    "set_foreground_window_return": True,
                    "set_focus_return": 1,
                },
            )

        def mutated(**changes):
            identity = dict(target_identity)
            identity.update(changes)
            identity["identity_digest"] = _identity_digest(identity)
            return identity

        negative_cases = [
            (
                "pid_reuse",
                mutated(created_filetime=target_identity["created_filetime"] + 1),
                "TARGET_PROCESS_IDENTITY_MISMATCH",
            ),
            (
                "wrong_hwnd_owner",
                mutated(hwnd=guardian.hwnd),
                "TARGET_HWND_OWNER_MISMATCH",
            ),
            (
                "child_as_top_hwnd",
                mutated(hwnd=target_identity["control_hwnd"]),
                "TARGET_HWND_OWNER_MISMATCH",
            ),
            (
                "wrong_control_ancestry",
                mutated(control_hwnd=target_identity["hwnd"]),
                "CONTROL_IDENTITY_MISMATCH",
            ),
            (
                "window_cookie_mismatch",
                mutated(window_property_marker=target_identity["window_property_marker"] + 1),
                "TARGET_HWND_OWNER_MISMATCH",
            ),
            (
                "wrong_session",
                mutated(session_id=target_identity["session_id"] + 1),
                "TARGET_PROCESS_IDENTITY_MISMATCH",
            ),
            (
                "desktop_mismatch",
                mutated(
                    desktop={
                        **target_identity["desktop"],
                        "desktop_name": "OtherDesktop",
                    }
                ),
                "DESKTOP_IDENTITY_UNKNOWN",
            ),
        ]
        for case_name, identity, expected_failure in negative_cases:
            clear_events()
            result = guardian.rpc(
                "register_verified_handoff",
                {
                    "handoff_id": f"negative-{case_name}",
                    "target_identity": identity,
                    "target_channel_token": identity["channel_token"],
                },
            )
            assert result["registered"] is False
            assert result["failure"] == expected_failure
            guardian_state = guardian.rpc("foreground_test_double_state")
            target_state = target.rpc("foreground_test_double_state")
            assert guardian_state["call_counts"]["AllowSetForegroundWindow"] == 0
            assert target_state["call_counts"]["SetForegroundWindow"] == 0
            assert target_state["call_counts"]["SetFocus"] == 0
            assert target.rpc("state")["count"] == 0

        clear_events()
        channel_result = guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": "negative-channel-binding",
                "target_identity": target_identity,
                "target_channel_token": "substituted-channel",
            },
        )
        assert channel_result["failure"] == "TARGET_CHANNEL_BINDING_MISMATCH"
        assert guardian.rpc("foreground_test_double_state")["call_counts"][
            "AllowSetForegroundWindow"
        ] == 0

        bind_id = "negative-guardian-ownership"
        binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": bind_id,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": bind_id,
                "target_identity": target_identity,
                "target_channel_token": binding["target_channel_token"],
            },
        )
        changed_guardian = guardian.rpc(
            "grant_foreground_verified",
            {
                "handoff_id": bind_id,
                "guardian_pid": guardian.pid,
                "guardian_hwnd": target.hwnd,
                "guardian_session_id": guardian_identity["session_id"],
            },
        )
        assert changed_guardian["failure"] == "GUARDIAN_OWNERSHIP_CHANGED"
        assert guardian.rpc("foreground_test_double_state")["call_counts"][
            "AllowSetForegroundWindow"
        ] == 0

        clear_events(allow=False)
        reject_id = "negative-grant-rejection"
        reject_binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": reject_id,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": reject_id,
                "target_identity": target_identity,
                "target_channel_token": reject_binding["target_channel_token"],
            },
        )
        rejected = guardian.rpc(
            "grant_foreground_verified",
            {
                "handoff_id": reject_id,
                "guardian_pid": guardian.pid,
                "guardian_hwnd": guardian.hwnd,
                "guardian_session_id": guardian_identity["session_id"],
            },
        )
        assert rejected["failure"] == "GRANT_REJECTED"
        assert rejected["native_bool"] is False
        assert target.rpc("foreground_test_double_state")["call_counts"][
            "SetForegroundWindow"
        ] == 0

        clear_events(allow=True)
        duplicate_id = "negative-duplicate-grant"
        duplicate_binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": duplicate_id,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": duplicate_id,
                "target_identity": target_identity,
                "target_channel_token": duplicate_binding["target_channel_token"],
            },
        )
        grant_args = {
            "handoff_id": duplicate_id,
            "guardian_pid": guardian.pid,
            "guardian_hwnd": guardian.hwnd,
            "guardian_session_id": guardian_identity["session_id"],
        }
        assert guardian.rpc("grant_foreground_verified", grant_args)["granted"] is True
        duplicate_grant = guardian.rpc("grant_foreground_verified", grant_args)
        assert duplicate_grant["failure"] == "DUPLICATE_GRANT"
        assert guardian.rpc("foreground_test_double_state")["call_counts"][
            "AllowSetForegroundWindow"
        ] == 1

        focus_id = "negative-duplicate-focus"
        focus_binding = target.rpc(
            "prepare_verified_handoff",
            {
                "handoff_id": focus_id,
                "target_identity_digest": target_identity["identity_digest"],
                "control_id": 201,
            },
        )
        guardian.rpc(
            "register_verified_handoff",
            {
                "handoff_id": focus_id,
                "target_identity": target_identity,
                "target_channel_token": focus_binding["target_channel_token"],
            },
        )
        focus_grant = guardian.rpc(
            "grant_foreground_verified",
            {
                "handoff_id": focus_id,
                "guardian_pid": guardian.pid,
                "guardian_hwnd": guardian.hwnd,
                "guardian_session_id": guardian_identity["session_id"],
            },
        )
        assert focus_grant["granted"] is True
        focus_args = {
            "handoff_id": focus_id,
            "target_identity_digest": target_identity["identity_digest"],
            "target_channel_token": focus_binding["target_channel_token"],
            "control_id": 201,
        }
        assert target.rpc("focus_from_verified_guardian", focus_args)["failure"] is None
        duplicate_focus = target.rpc("focus_from_verified_guardian", focus_args)
        assert duplicate_focus["failure"] == "DUPLICATE_FOCUS_REQUEST"
        target_state = target.rpc("foreground_test_double_state")
        assert target_state["call_counts"]["SetForegroundWindow"] == 1
        assert target_state["call_counts"]["SetFocus"] == 1
        assert target.rpc("state")["count"] == 0
    finally:
        try:
            if target is not None:
                target.close_without_foreground_restore()
        finally:
            if guardian is not None:
                guardian.close_without_foreground_restore()
