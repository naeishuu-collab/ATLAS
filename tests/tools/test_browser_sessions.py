"""Owner checks and isolation for host-managed browser contexts."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from openjarvis.tools.browser import BrowserActionError
from openjarvis.tools.browser_sessions import BrowserSessionManager


def test_owner_expiry_revocation_and_recovery():
    manager = BrowserSessionManager(ttl=10)
    with patch("openjarvis.tools.browser_sessions.time.monotonic", return_value=100):
        first = manager.open("agent-a", "principal-a")
        assert manager.open("agent-a", "principal-a") == first
        second = manager.open("agent-b", "principal-b")
        assert second != first
        with pytest.raises(PermissionError):
            manager.open("agent-a", "principal-b")
        with pytest.raises(PermissionError):
            manager.run("agent-b", "principal-b", first, lambda session: None)
        with pytest.raises(PermissionError):
            manager.run("agent-a", "principal-b", first, lambda session: None)
        with patch(
            "openjarvis.tools.browser_sessions.time.monotonic", return_value=111
        ):
            with pytest.raises(PermissionError, match="expired"):
                manager.run("agent-a", "principal-a", first, lambda session: None)
            with pytest.raises(PermissionError, match="expired"):
                manager.open("agent-a", "principal-a")
            assert manager.cleanup_expired() == 2
        with pytest.raises(PermissionError):
            manager.run("agent-a", "principal-a", first, lambda session: None)
        replacement = manager.open("agent-a", "principal-a")
        assert replacement != first
        manager.revoke("agent-a", "principal-a", replacement)


def test_uncertain_execution_quarantines_but_proven_pre_dispatch_does_not():
    manager = BrowserSessionManager()
    sid = manager.open("a", "principal")

    def fail(dispatched):
        raise BrowserActionError("TIMEOUT", "synthetic", dispatched=dispatched)

    try:
        with pytest.raises(BrowserActionError):
            manager.run("a", "principal", sid, lambda _: fail(False))
        assert manager.run("a", "principal", sid, lambda _: "safe") == "safe"
        with pytest.raises(BrowserActionError):
            manager.run("a", "principal", sid, lambda _: fail(True))
        with pytest.raises(PermissionError, match="quarantined"):
            manager.run("a", "principal", sid, lambda _: "never")
    finally:
        manager.revoke("a", "principal", sid)


def test_real_browser_contexts_are_isolated_and_reused():
    manager = BrowserSessionManager()
    a = manager.open("agent-a", "principal-a")
    b = manager.open("agent-b", "principal-b")

    def setup(session):
        page = session.page
        page.route(
            "**/*", lambda route: route.fulfill(status=200, body="<p>fixture</p>")
        )
        page.goto("https://fixture.invalid/")
        return id(session._context)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(manager.run, agent, principal, sid, setup)
                for agent, principal, sid in (
                    ("agent-a", "principal-a", a),
                    ("agent-b", "principal-b", b),
                )
            ]
            assert futures[0].result() != futures[1].result()
        manager.run(
            "agent-a",
            "principal-a",
            a,
            lambda s: s.page.evaluate(
                "() => { localStorage.setItem('secret','agent-a'); "
                "sessionStorage.setItem('secret','agent-a'); "
                "document.cookie='auth=a'; }"
            ),
        )
        assert (
            manager.run(
                "agent-a",
                "principal-a",
                a,
                lambda s: s.page.evaluate("localStorage.getItem('secret')"),
            )
            == "agent-a"
        )
        assert (
            manager.run(
                "agent-b",
                "principal-b",
                b,
                lambda s: s.page.evaluate("localStorage.getItem('secret')"),
            )
            is None
        )
        assert manager.run(
            "agent-b",
            "principal-b",
            b,
            lambda s: s.page.evaluate(
                "[sessionStorage.getItem('secret'), document.cookie]"
            ),
        ) == [None, ""]
        manager.run("agent-a", "principal-a", a, lambda s: s._browser.close())
        with pytest.raises(Exception):
            manager.run("agent-a", "principal-a", a, lambda s: s.page.title())
        with pytest.raises(PermissionError, match="quarantined"):
            manager.run("agent-a", "principal-a", a, lambda s: s.page.title())
        manager.revoke("agent-a", "principal-a", a)
        old = a
        a = manager.open("agent-a", "principal-a")
        assert a != old
        assert manager.run("agent-a", "principal-a", a, lambda s: s.page.title()) == ""
    finally:
        manager.revoke("agent-a", "principal-a", a)
        manager.revoke("agent-b", "principal-b", b)
