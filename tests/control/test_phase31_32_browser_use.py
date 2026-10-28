"""Phase 31/32 browser-use schema mapping and Fake Executor safety tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from openjarvis.control.browser_use_schema import (
    BROWSER_USE_VERSION,
    BrowserUseSchemaAdapter,
    BrowserUseSchemaError,
    extract_browser_use_action_schema,
)
from openjarvis.control.oss_adapter import (
    AdapterMode,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    make_authorized_action,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

_KEY = b"phase31-test-only-host-key"
_NAMES = {
    "click",
    "close",
    "done",
    "dropdown_options",
    "evaluate",
    "extract",
    "find_elements",
    "find_text",
    "go_back",
    "input",
    "navigate",
    "read_file",
    "replace_file",
    "save_as_pdf",
    "screenshot",
    "scroll",
    "search",
    "search_page",
    "select_dropdown",
    "send_keys",
    "switch",
    "upload_file",
    "wait",
    "write_file",
}


def _row(name: str, properties: dict[str, dict], required: list[str] = []):
    return {"schema": {"properties": properties, "required": required}}


def _real_schema_rows():
    # Names and argument fields are the 0.13.13 registry observed in the isolated venv.
    return {
        "click": _row("click", {"index": {"type": "integer"}}, ["index"]),
        "close": _row("close", {"tab_id": {"type": "string"}}, ["tab_id"]),
        "done": _row("done", {"text": {"type": "string"}}, ["text"]),
        "dropdown_options": _row(
            "dropdown_options", {"index": {"type": "integer"}}, ["index"]
        ),
        "evaluate": _row("evaluate", {"code": {"type": "string"}}, ["code"]),
        "extract": _row("extract", {"query": {"type": "string"}}, ["query"]),
        "find_elements": _row(
            "find_elements", {"selector": {"type": "string"}}, ["selector"]
        ),
        "find_text": _row("find_text", {"text": {"type": "string"}}, ["text"]),
        "go_back": _row("go_back", {}),
        "input": _row(
            "input",
            {"index": {"type": "integer"}, "text": {"type": "string"}},
            ["index", "text"],
        ),
        "navigate": _row("navigate", {"url": {"type": "string"}}, ["url"]),
        "read_file": _row(
            "read_file", {"file_name": {"type": "string"}}, ["file_name"]
        ),
        "replace_file": _row(
            "replace_file",
            {
                "file_name": {"type": "string"},
                "old_str": {"type": "string"},
                "new_str": {"type": "string"},
            },
            ["file_name", "old_str", "new_str"],
        ),
        "save_as_pdf": _row("save_as_pdf", {}),
        "screenshot": _row("screenshot", {}),
        "scroll": _row("scroll", {}),
        "search": _row("search", {"query": {"type": "string"}}, ["query"]),
        "search_page": _row(
            "search_page", {"pattern": {"type": "string"}}, ["pattern"]
        ),
        "select_dropdown": _row(
            "select_dropdown",
            {"index": {"type": "integer"}, "text": {"type": "string"}},
            ["index", "text"],
        ),
        "send_keys": _row("send_keys", {"keys": {"type": "string"}}, ["keys"]),
        "switch": _row("switch", {"tab_id": {"type": "string"}}, ["tab_id"]),
        "upload_file": _row(
            "upload_file",
            {"index": {"type": "integer"}, "path": {"type": "string"}},
            ["index", "path"],
        ),
        "wait": _row("wait", {}),
        "write_file": _row(
            "write_file",
            {"file_name": {"type": "string"}, "content": {"type": "string"}},
            ["file_name", "content"],
        ),
    }


def _schema():
    return extract_browser_use_action_schema(
        _real_schema_rows(), version=BROWSER_USE_VERSION
    )


def _snapshot(*, privacy="PUBLIC", targets=None):
    if targets is None:
        targets = (
            {
                "target_id": "element-3",
                "identity": {
                    "session_id": "s1",
                    "tab_id": "tab1",
                    "page_id": "page1",
                    "frame_id": "frame1",
                    "origin": "https://fixture.invalid",
                    "dom_revision": "r1",
                    "element_index": 3,
                },
            },
        )
    return ObservationSnapshot(
        ControlSurface.BROWSER, "obs1", tuple(targets), privacy=privacy
    )


def test_real_sdk_schema_has_24_actions_and_exact_argument_fields():
    schema = _schema()
    assert {item.sdk_name for item in schema} == _NAMES
    assert len(schema) == 24
    assert next(
        item for item in schema if item.sdk_name == "input"
    ).required_arguments == {
        "index",
        "text",
    }
    assert next(item for item in schema if item.sdk_name == "navigate").mutation
    assert not next(item for item in schema if item.sdk_name == "extract").mutation
    assert next(item for item in schema if item.sdk_name == "screenshot").mutation


def test_schema_set_or_version_mismatch_fails_closed():
    rows = _real_schema_rows()
    rows.pop("click")
    with pytest.raises(BrowserUseSchemaError, match="ACTION_SCHEMA_SET_MISMATCH"):
        extract_browser_use_action_schema(rows, version=BROWSER_USE_VERSION)
    with pytest.raises(BrowserUseSchemaError, match="SDK_VERSION_MISMATCH"):
        extract_browser_use_action_schema(_real_schema_rows(), version="0.99.0")


def test_click_and_input_are_target_bound_proposals():
    adapter = BrowserUseSchemaAdapter(_schema(), session_id="s1")
    click = adapter.to_proposal({"click": {"index": 3}}, _snapshot(), action_id="a1")
    typed = adapter.to_proposal(
        {"name": "input", "arguments": {"index": 3, "text": "ATLAS"}},
        _snapshot(),
        action_id="a2",
    )
    assert click.action == "browser_sdk_click"
    assert click.target_id == "element-3"
    assert typed.action == "browser_sdk_input"
    assert typed.arguments["text"] == "ATLAS"


@pytest.mark.parametrize(
    "action,reason",
    [
        ({"click": {"index": 3}, "wait": {}}, "MULTI_ACTION"),
        ({"click": {"index": 99}}, "STALE_TARGET"),
        ({"click": {"index": 3, "extra": True}}, "ARGUMENTS_UNKNOWN"),
        ({"navigate": {"url": "https://other.invalid/"}}, "CROSS_ORIGIN"),
        ({"search": {"query": "secret"}}, "NAVIGATION_TARGET_UNVERIFIED"),
    ],
)
def test_unsafe_or_ambiguous_schema_actions_fail_closed(action, reason):
    adapter = BrowserUseSchemaAdapter(_schema(), session_id="s1")
    with pytest.raises(BrowserUseSchemaError, match=reason):
        adapter.to_proposal(action, _snapshot(), action_id="bad")


def test_privacy_and_session_boundary_are_checked_before_proposal():
    adapter = BrowserUseSchemaAdapter(_schema(), session_id="s1")
    with pytest.raises(BrowserUseSchemaError, match="PRIVACY_DENIED"):
        adapter.to_proposal(
            {"click": {"index": 3}}, _snapshot(privacy="PRIVATE"), action_id="a1"
        )
    wrong = _snapshot(
        targets=(
            {
                "target_id": "element-3",
                "identity": {
                    **_snapshot().targets[0]["identity"],
                    "session_id": "other",
                },
            },
        )
    )
    with pytest.raises(BrowserUseSchemaError, match="SESSION_MISMATCH"):
        adapter.to_proposal({"click": {"index": 3}}, wrong, action_id="a1")


class _FakeExecutor:
    def __init__(self, failure=None):
        self.calls = 0
        self.failure = failure

    def propose(self, _observation):
        return None

    def dispatch(self, _authorized):
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return DispatchResult(True, {"calls": self.calls})


def test_real_schema_proposal_uses_safety_authority_and_fake_executor_once():
    proposal = BrowserUseSchemaAdapter(_schema(), session_id="s1").to_proposal(
        {"click": {"index": 3}}, _snapshot(), action_id="a1"
    )
    executor = _FakeExecutor()
    host = SafeEngineAdapter(
        executor,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="s1",
        seal_key=_KEY,
    )
    intent = MutationIntent("execution", "step", "intent")
    auth = make_authorized_action(
        proposal, intent, session_id="s1", nonce="n1", key=_KEY
    )
    assert (
        host.execute(
            proposal, _snapshot(), authorized=None, verify=lambda *_: True
        ).failure
        == "AUTHORIZATION_REQUIRED"
    )
    assert executor.calls == 0
    assert (
        host.execute(
            proposal, _snapshot(), authorized=auth, verify=lambda *_: True
        ).state
        is ExecutionState.VERIFIED
    )
    assert (
        host.execute(
            proposal, _snapshot(), authorized=auth, verify=lambda *_: True
        ).failure
        == "NONCE_REPLAY"
    )
    assert executor.calls == 1
    new_auth = make_authorized_action(
        proposal, intent, session_id="s1", nonce="n2", key=_KEY
    )
    assert (
        host.execute(
            proposal, _snapshot(), authorized=new_auth, verify=lambda *_: True
        ).failure
        == "DUPLICATE_ACTION"
    )
    assert executor.calls == 1


@pytest.mark.parametrize(
    "failure,expected",
    [
        (TimeoutError(), "UNKNOWN_OUTCOME"),
        (RuntimeError(), "UNKNOWN_OUTCOME"),
        (None, "VERIFICATION_FAILED"),
    ],
)
def test_unknown_outcome_and_verification_failure_never_retry(failure, expected):
    proposal = BrowserUseSchemaAdapter(_schema(), session_id="s1").to_proposal(
        {"click": {"index": 3}}, _snapshot(), action_id="a1"
    )
    executor = _FakeExecutor(failure)
    host = SafeEngineAdapter(
        executor,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="s1",
        seal_key=_KEY,
    )
    auth = make_authorized_action(
        proposal, MutationIntent("e", "s", "i"), session_id="s1", nonce="n1", key=_KEY
    )
    result = host.execute(
        proposal, _snapshot(), authorized=auth, verify=lambda *_: False
    )
    assert result.failure == expected
    assert executor.calls == 1
    assert (
        host.execute(
            proposal, _snapshot(), authorized=auth, verify=lambda *_: True
        ).failure
        == "NONCE_REPLAY"
    )


def test_payload_tampering_is_denied_without_fake_execution():
    proposal = BrowserUseSchemaAdapter(_schema(), session_id="s1").to_proposal(
        {"click": {"index": 3}}, _snapshot(), action_id="a1"
    )
    executor = _FakeExecutor()
    host = SafeEngineAdapter(
        executor,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="s1",
        seal_key=_KEY,
    )
    auth = make_authorized_action(
        proposal, MutationIntent("e", "s", "i"), session_id="s1", nonce="n1", key=_KEY
    )
    tampered = replace(auth, proposal=replace(proposal, arguments={"index": 99}))
    assert (
        host.execute(
            proposal, _snapshot(), authorized=tampered, verify=lambda *_: True
        ).failure
        == "AUTHORIZATION_MISMATCH"
    )
    assert executor.calls == 0
