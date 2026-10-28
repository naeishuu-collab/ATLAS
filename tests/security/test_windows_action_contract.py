"""Controller fault injection; these tests do not claim physical Windows E2E."""

import copy
from dataclasses import replace

import pytest

from openjarvis.windows.actions import WindowsActionSession
from openjarvis.windows.identity import IdentityError, IdentitySession
from tests.security.test_windows_identity import FixtureBackend, control


class Observer:
    def __init__(self):
        self.backend = FixtureBackend()
        self.backend.elements = []
        for cid in (201, 203, 301, 302):
            element = control(
                (1, cid), str(cid), "Duplicate" if cid == 203 else str(cid)
            )
            element.identity = replace(element.identity, hwnd=cid)
            self.backend.elements.append(element)
        self.session = IdentitySession(self.backend)
        self.broken_post_read = False

    def observe(self, hwnd):
        if self.broken_post_read:
            raise TimeoutError("post-action observation deadline")
        return self.session.observe(hwnd).to_dict()

    def select(self, oid, **hints):
        return self.session.select(oid, **hints)

    def validate(
        self,
        oid,
        tid,
        *,
        require_foreground=True,
        require_value_verifiable=False,
    ):
        return self.session.validate(
            oid,
            tid,
            require_foreground=require_foreground,
            require_value_verifiable=require_value_verifiable,
        )


class Receiver:
    pid = 10

    def __init__(self, observer):
        self.observer = observer
        self.calls = 0
        self.state = {
            "pid": 10,
            "created_filetime": 1000,
            "hwnd": 100,
            "window_cookie": "window-lifetime",
            "revision": 0,
            "controls": {
                str(cid): {"hwnd": cid, "cookie": f"lifetime-{cid}"}
                for cid in (201, 203, 301, 302)
            },
        }
        self.ack = {"dispatched": True}
        self.lost_ack = False
        self.wrong_witness = False

    def snapshot(self):
        return self.state  # intentionally exposes aliases to test cache isolation

    def dispatch(self, request):
        self.calls += 1
        if self.ack.get("dispatched") is True:
            self.state["revision"] += 1
            self.observer.backend.elements[2].name = str(self.state["revision"])
            self.observer.backend.elements[3].name = (
                "wrong" if self.wrong_witness else f"clicked:{request['control_id']}"
            )
        if self.lost_ack:
            raise OSError("lost after dispatch")
        return self.ack


@pytest.fixture
def bound():
    observer = Observer()
    receiver = Receiver(observer)
    session = WindowsActionSession(observer, receiver)
    observation = session.observe(100)
    tid = session.resolve(observation["observation_id"], automation_id="201")
    return observer, receiver, session, observation, tid


def act(bound):
    _, _, session, observation, tid = bound
    return session.act("click", observation["observation_id"], tid)


def test_verified_requires_fresh_independent_witnesses_and_consumes_authority(bound):
    result = act(bound)
    assert result["outcome"] == result["verification"] == "VERIFIED"
    assert result["evidence"]["counter_after"] == 1
    assert (
        result["identity"]["receiver"]["window_cookie"]
        == bound[3]["receiver_identity"]["window_cookie"]
    )
    assert result["evidence"]["post_observation_id"] != bound[3]["observation_id"]
    assert act(bound)["outcome"] == "NOT_STARTED"
    assert bound[1].calls == 1


def test_returned_observation_cannot_silently_redirect_to_another_control(bound):
    observation = bound[3]
    original = copy.deepcopy(observation["controls"][0]["identity"])
    observation["controls"][0]["identity"] = observation["controls"][1]["identity"]
    observation["window"]["process"]["pid"] = 999
    observation["receiver_identity"]["controls"]["201"]["cookie"] = "tampered"
    result = act(bound)
    assert result["outcome"] == "VERIFIED"
    assert result["identity"]["control"] == original
    assert result["identity"]["window"]["process"]["pid"] == 10
    assert result["identity"]["receiver"]["control_cookie"] == "lifetime-201"


def test_receiver_snapshot_alias_does_not_rewrite_captured_authorization(bound):
    bound[1].state["controls"]["201"]["hwnd"] = 203
    result = act(bound)
    # Captured 201 stays 201 despite the source alias changing.
    assert result["identity"]["control"]["hwnd"] == 201


@pytest.mark.parametrize("fault", ["lost_ack", "wrong_witness", "post_read", "bad_ack"])
def test_uncertainty_never_becomes_success_or_replay(bound, fault):
    observer, receiver, *_ = bound
    if fault == "post_read":
        old = receiver.dispatch

        def dispatch(packet):
            ack = old(packet)
            observer.broken_post_read = True
            return ack

        receiver.dispatch = dispatch
    elif fault == "bad_ack":
        receiver.ack = {}
    else:
        setattr(receiver, fault, True)
    result = act(bound)
    assert result["outcome"] == result["failure"] == "UNKNOWN_OUTCOME"
    assert result["verification"] == "NOT_VERIFIED"
    assert result["retryable"] is False
    assert act(bound)["outcome"] == "NOT_STARTED"
    assert receiver.calls == 1


@pytest.mark.parametrize(
    "failure", ["STALE_TARGET", "WRONG_FOREGROUND", "FOCUS_FAILURE"]
)
def test_receiver_proven_rejection_is_zero_mutation_not_unknown(bound, failure):
    bound[1].ack = {"dispatched": False, "failure": failure}
    result = act(bound)
    assert result["outcome"] == "NOT_STARTED"
    assert result["dispatch"] == "NOT_DISPATCHED"
    assert result["failure"] == failure
    assert result["retryable"] is False
    assert bound[1].state["revision"] == 0


def test_wrong_foreground_rejects_before_receiver_dispatch(bound):
    bound[0].backend.front = 999
    result = act(bound)
    assert result["failure"] == "WRONG_FOREGROUND"
    assert bound[1].calls == 0


def test_failed_ambiguous_resolution_invalidates_action_authority(bound):
    observer, receiver, session, observation, _ = bound
    observer.backend.elements[0].name = "Action"
    observer.backend.elements[1].name = "Action"
    # A fresh observation captures both same-name controls.
    observation = session.observe(100)
    with pytest.raises(IdentityError, match="2 matches"):
        session.resolve(observation["observation_id"], name="Action")
    result = session.act(
        "click", observation["observation_id"], observation["controls"][0]["target_id"]
    )
    assert result["outcome"] == "NOT_STARTED"
    assert receiver.calls == 0


@pytest.mark.parametrize("value", ["a" * 4097, "a\x00b", None])
def test_invalid_text_is_rejected_before_dispatch(bound, value):
    result = bound[2].act(
        "type_into", bound[3]["observation_id"], bound[4], value=value
    )
    assert result["outcome"] == "NOT_STARTED"
    assert bound[1].calls == 0


def test_unverifiable_type_is_structured_rejection_before_receiver_dispatch():
    observer = Observer()
    observer.backend.elements[0].identity = replace(
        observer.backend.elements[0].identity,
        control_type=50004,
        class_name="Edit",
    )
    observer.backend.value_verifiable = False
    receiver = Receiver(observer)
    session = WindowsActionSession(observer, receiver)
    observation = session.observe(100)
    target_id = session.resolve(observation["observation_id"], automation_id="201")

    result = session.act(
        "type_into", observation["observation_id"], target_id, value="secret"
    )

    assert result["outcome"] == "NOT_STARTED"
    assert result["dispatch"] == "NOT_DISPATCHED"
    assert result["failure"] == "UNSUPPORTED_CONTROL"
    assert result["verification"] == "NOT_VERIFIED"
    assert receiver.calls == 0
