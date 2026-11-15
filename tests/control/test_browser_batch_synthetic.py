"""Headless Chromium fixture; all navigations are fulfilled in memory."""

from urllib.parse import urlsplit

from openjarvis.control.authorized_batch import (
    AuthorizedBatchStep,
    execute_authorized_batch,
)
from openjarvis.control.oss_adapter import (
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    make_authorized_action,
)
from openjarvis.core.execution import ExecutionState, MutationIntent
from openjarvis.tools.browser_sessions import BrowserSessionManager
from openjarvis.tools.execution_journal import ExecutionJournal
from tests.control.test_authorized_batch import KEY, host


def test_browser_batch_and_cross_agent_storage_with_synthetic_pages(tmp_path):
    manager = BrowserSessionManager()
    a = manager.open("a", "principal-a")
    b = manager.open("b", "principal-b")
    journal = ExecutionJournal(tmp_path / "batch.db")

    def prepare(session):
        def route(request):
            url = urlsplit(request.request.url)
            assert url.hostname == "fixture.invalid"
            body = (
                '<form action="/done"><input id="name" name="name">'
                '<select id="choice" name="choice"><option value="a">A</option>'
                '<option value="b">B</option></select>'
                '<button id="submit">Submit</button>'
                "</form>"
                if url.path == "/start"
                else "<p>Completed</p>"
            )
            request.fulfill(status=200, content_type="text/html", body=body)

        session.page.route("**/*", route)
        session.page.goto("https://fixture.invalid/start")

    def observe(index):
        def capture(session):
            session.observe_targets()
            identity = {
                "session_id": a,
                "element_index": index,
                "document_id": session.document_id,
            }
            return ObservationSnapshot(
                ControlSurface.BROWSER,
                session.document_id,
                ({"target_id": f"target-{index}", "identity": identity},),
                privacy="PUBLIC",
            )

        return manager.run("a", "principal-a", a, capture)

    class PlaywrightFixture:
        def dispatch(self, authorized):
            proposal = authorized.proposal

            def act(session):
                identity = proposal.target_identity
                session.require_document(identity["document_id"])
                index = identity["element_index"]
                target = session.page.locator(["#name", "#choice", "#submit"][index])
                handles = target.element_handles()
                assert len(handles) == 1
                session.require_observed_target(handles[0])
                if proposal.action == "browser_sdk_input":
                    handles[0].fill(proposal.arguments["text"])
                elif proposal.action == "browser_sdk_select_dropdown":
                    handles[0].select_option(value=proposal.arguments["text"])
                else:
                    handles[0].click()
                return DispatchResult(True)

            return manager.run("a", "principal-a", a, act)

    try:
        manager.run("a", "principal-a", a, prepare)
        manager.run("b", "principal-b", b, prepare)
        manager.run(
            "a",
            "principal-a",
            a,
            lambda s: s.page.evaluate("localStorage.setItem('token','only-a')"),
        )
        assert (
            manager.run(
                "b",
                "principal-b",
                b,
                lambda s: s.page.evaluate("localStorage.getItem('token')"),
            )
            is None
        )
        facade = host(PlaywrightFixture(), session_id=a)
        specs = [
            ({"input": {"index": 0, "text": "Alice"}}, 0),
            ({"select_dropdown": {"index": 1, "text": "b"}}, 1),
            ({"click": {"index": 2}}, 2),
        ]
        steps = []
        for number, (action, index) in enumerate(specs):
            observation = observe(index)
            proposal = facade.propose(action, observation, action_id=f"action-{number}")
            intent = MutationIntent("execution", f"step-{number}", f"intent-{number}")
            authorization = make_authorized_action(
                proposal, intent, session_id=a, nonce=f"nonce-{number}", key=KEY
            )
            journal.authorize_intent("scope", intent)

            def verify(_proposal, _result, i=index):
                return manager.run(
                    "a",
                    "principal-a",
                    a,
                    lambda s: (
                        s.page.locator("#name").input_value() == "Alice"
                        if i == 0
                        else s.page.locator("#choice").input_value() == "b"
                        if i == 1
                        else urlsplit(s.page.url).path == "/done"
                    ),
                )

            steps.append(
                AuthorizedBatchStep(
                    authorization, action, lambda i=index: observe(i), verify
                )
            )
        results = execute_authorized_batch(facade, journal, "scope", steps)
        assert [item.state for item in results] == [ExecutionState.VERIFIED] * 3
        assert journal.pending("scope") == []
    finally:
        journal.close()
        manager.revoke("a", "principal-a", a)
        manager.revoke("b", "principal-b", b)
