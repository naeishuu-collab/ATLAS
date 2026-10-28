"""Real Chromium tests on synthetic documents; no user accounts or services."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from openjarvis.core.types import ToolCall
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.browser import (
    BrowserClickTool,
    BrowserExtractTool,
    BrowserTypeTool,
    _BrowserSession,
)
from openjarvis.tools.browser_axtree import BrowserAXTreeTool


@pytest.fixture(scope="module")
def browser_session():
    session = _BrowserSession()
    # A missing or blocked browser is a test failure in this explicit E2E lane.
    session.run(lambda: session.page.set_content("<p>fixture ready</p>"))
    yield session
    session.close()
    session._runner.shutdown()


@pytest.fixture
def browser(browser_session, monkeypatch):
    monkeypatch.setattr("openjarvis.tools.browser._session", browser_session)
    monkeypatch.setattr("openjarvis.tools.browser_axtree._session", browser_session)
    return browser_session


def _browser_policy():
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("_default", "network:fetch")
    return policy


def prepare(session, html):
    session.run(lambda: session.page.set_content(html))
    executor = ToolExecutor(
        [
            BrowserExtractTool(),
            BrowserClickTool(),
            BrowserTypeTool(),
            BrowserAXTreeTool(),
        ],
        interactive=True,
        confirm_callback=lambda _: True,
        capability_policy=_browser_policy(),
        agent_id="_default",
    )
    observation = executor.execute(ToolCall("observe", "browser_extract", "{}"))
    assert observation.success, observation.content
    return executor, observation.metadata["document_id"]


def invoke(executor, name, identifier="action", **params):
    return executor.execute(ToolCall(identifier, name, json.dumps(params)))


BUTTON = '<button id="save" onclick="window.clicks++">Save</button>'
COUNTER = "<script>window.clicks=0</script>"


def test_agent_obtains_document_identity_from_tool_text_and_verifies_input(browser):
    from openjarvis.agents.orchestrator import OrchestratorAgent
    from openjarvis.core.types import Role

    browser.run(
        lambda: browser.page.set_content('<input id="agent-field" placeholder="Name">')
    )

    class ObservationEngine:
        engine_id = "scripted-browser-fixture"

        def __init__(self):
            self.turn = 0

        def generate(self, messages, **kwargs):
            self.turn += 1
            if self.turn == 1:
                name, arguments = "browser_extract", {}
            elif self.turn == 2:
                text = [
                    message.content for message in messages if message.role == Role.TOOL
                ][-1]
                # This is the actual agent-facing message, with no access to
                # the session or ToolResult metadata to invent a document ID.
                context = json.loads(
                    text.splitlines()[0].removeprefix("[Browser observation data] ")
                )
                target = context["targets"][0]
                assert target["id"] == "agent-field"
                name = "browser_type"
                arguments = {
                    "document_id": context["document_id"],
                    "selector": "#" + target["id"],
                    "text": "agent fixture",
                }
            else:
                return {"content": "Fixture completed", "tool_calls": []}
            return {
                "content": "",
                "tool_calls": [
                    {
                        "id": str(self.turn),
                        "name": name,
                        "arguments": json.dumps(arguments),
                    }
                ],
            }

    agent = OrchestratorAgent(
        ObservationEngine(),
        "fixture-model",
        tools=[BrowserExtractTool(), BrowserTypeTool()],
        interactive=True,
        confirm_callback=lambda _: True,
        capability_policy=_browser_policy(),
    )
    result = agent.run("Observe the Name field and enter the fixture text")
    assert result.turns == 3
    assert len(result.tool_results) == 2
    assert all(tool.success for tool in result.tool_results)
    assert result.tool_results[1].metadata["execution"]["state"] == "VERIFIED"
    assert (
        browser.run(lambda: browser.page.input_value("#agent-field")) == "agent fixture"
    )


def test_executor_observe_type_verify_click_and_current_aria_api(browser):
    executor, document = prepare(browser, COUNTER + '<input id="field">' + BUTTON)
    typed = invoke(
        executor,
        "browser_type",
        document_id=document,
        selector="#field",
        text="fixture input",
    )
    assert typed.success, typed.content
    assert typed.metadata["execution"]["state"] == "VERIFIED"
    assert browser.run(lambda: browser.page.input_value("#field")) == "fixture input"
    clicked = invoke(executor, "browser_click", document_id=document, selector="#save")
    assert clicked.success, clicked.content
    assert clicked.metadata["execution"]["state"] == "EXECUTED"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 1
    aria = invoke(executor, "browser_axtree")
    assert aria.success, aria.content
    assert 'button "Save"' in aria.content
    assert aria.metadata["document_id"] == document


def test_duplicate_controls_fail_before_any_click(browser):
    executor, document = prepare(browser, COUNTER + BUTTON + BUTTON)
    result = invoke(
        executor, "browser_click", document_id=document, selector="Save", by_text=True
    )
    assert not result.success
    assert result.metadata["failure"] == "AMBIGUOUS_TARGET"
    assert result.metadata["execution"]["state"] == "NOT_STARTED"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0


def test_duplicate_controls_across_frames_fail_closed(browser):
    executor, document = prepare(
        browser,
        COUNTER + BUTTON + '<iframe srcdoc="<button>Save</button>"></iframe>',
    )
    result = invoke(
        executor, "browser_click", document_id=document, selector="Save", by_text=True
    )
    assert not result.success
    assert result.metadata["failure"] == "AMBIGUOUS_TARGET"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0


def test_missing_document_identity_is_refused(browser):
    executor, _ = prepare(browser, COUNTER + BUTTON)
    result = invoke(executor, "browser_click", selector="#save")
    assert not result.success
    assert result.metadata["failure"] == "STALE_TARGET"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0


def test_navigation_invalidates_previous_document_identity(browser):
    executor, old = prepare(browser, COUNTER + BUTTON)
    browser.run(lambda: browser.page.goto("data:text/html," + COUNTER + BUTTON))
    result = invoke(executor, "browser_click", selector="#save", document_id=old)
    assert not result.success
    assert result.metadata["failure"] == "STALE_TARGET"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0
    observation = invoke(executor, "browser_extract")
    new = observation.metadata["document_id"]
    assert new != old
    assert invoke(
        executor, "browser_click", identifier="fresh", selector="#save", document_id=new
    ).success


def test_same_selector_replacement_is_not_the_observed_dom_target(browser):
    executor, document = prepare(browser, COUNTER + BUTTON)
    browser.run(
        lambda: browser.page.evaluate(
            "document.querySelector('#save').outerHTML = " + json.dumps(BUTTON),
        )
    )
    result = invoke(executor, "browser_click", document_id=document, selector="#save")
    assert not result.success
    assert result.metadata["failure"] == "STALE_TARGET"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0


def test_pinned_handle_never_retargets_after_replacement_at_dispatch(
    browser, monkeypatch
):
    executor, document = prepare(browser, COUNTER + BUTTON)
    original = browser.require_observed_target

    def replace_after_identity_check(handle):
        original(handle)
        handle.evaluate("(el, html) => el.outerHTML = html", BUTTON)

    monkeypatch.setattr(
        browser, "require_observed_target", replace_after_identity_check
    )
    result = invoke(executor, "browser_click", document_id=document, selector="#save")
    assert not result.success
    assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 0


def test_lost_response_after_real_click_never_dispatches_again(browser):
    from playwright.sync_api import ElementHandle

    executor, document = prepare(browser, COUNTER + BUTTON)
    original = ElementHandle.click

    def click_then_lose_response(handle, **kwargs):
        original(handle, **kwargs)
        raise TimeoutError("response lost after physical click")

    with patch.object(ElementHandle, "click", click_then_lose_response):
        result = invoke(
            executor, "browser_click", document_id=document, selector="#save"
        )
        assert not result.success
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        retry = invoke(
            executor,
            "browser_click",
            identifier="new-id",
            document_id=document,
            selector="#save",
        )
        assert not retry.success
    assert browser.run(lambda: browser.page.evaluate("window.clicks")) == 1


def test_form_verification_failure_cannot_be_reported_as_success(browser):
    executor, document = prepare(
        browser,
        '<input id="field" oninput="this.value=\'unexpected\'">',
    )
    result = invoke(
        executor,
        "browser_type",
        document_id=document,
        selector="#field",
        text="expected",
    )
    assert not result.success
    assert result.metadata["failure"] == "VERIFICATION_FAILURE"
    assert result.metadata["execution"]["retryable"] is False


def test_append_verifies_complete_result(browser):
    executor, document = prepare(browser, '<input id="field" value="before">')
    result = invoke(
        executor,
        "browser_type",
        document_id=document,
        selector="#field",
        text=" after",
        clear=False,
    )
    assert result.success, result.content
    assert browser.run(lambda: browser.page.input_value("#field")) == "before after"


def test_browser_calls_share_one_owner_across_caller_threads(browser):
    def observe(_):
        return browser.run(lambda: (threading.get_ident(), browser.page.title()))

    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(observe, range(8)))
    assert len({owner for owner, _ in results}) == 1
    assert results[0][0] != threading.get_ident()


def test_all_network_requests_keep_ssrf_guard(browser):
    from openjarvis.security.ssrf import check_ssrf

    with patch("openjarvis.security.ssrf.check_ssrf", wraps=check_ssrf) as guarded:
        result = browser.run(
            lambda: browser.page.evaluate(
                "fetch('http://127.0.0.1:9/private').then(()=> 'unexpected')"
                ".catch(()=> 'blocked')",
            )
        )
    assert result == "blocked"
    guarded.assert_any_call("http://127.0.0.1:9/private")
