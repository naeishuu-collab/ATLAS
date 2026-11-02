"""Synthetic receiver-bound UIA reads; no live desktop is used."""

from dataclasses import replace

import pytest

from openjarvis.windows.actions import WindowsActionSession
from openjarvis.windows.identity import IdentityError
from tests.security.test_windows_action_contract import Observer, Receiver


def fixture():
    observer = Observer()
    element = observer.backend.elements[0]
    element.identity = replace(element.identity, control_type=50004, class_name="Edit")
    observer.backend.value = lambda _: "fixture value"
    observer.read_value = observer.session.read_value
    receiver = Receiver(observer)
    session = WindowsActionSession(observer, receiver)
    observation = session.observe(100)
    target = session.resolve(observation["observation_id"], automation_id="201")
    return observer, receiver, session, observation["observation_id"], target


def test_read_requires_bound_observed_value_and_no_mutation():
    _, receiver, session, observation, target = fixture()
    assert session.read_value(observation, target) == "fixture value"
    assert receiver.calls == 0
    with pytest.raises(IdentityError, match="stale"):
        session.read_value(observation, "unobserved")
    with pytest.raises(IdentityError, match="Stale"):
        session.read_value(observation, target)


def test_read_does_not_return_data_after_receiver_changes():
    observer, receiver, session, observation, target = fixture()

    def changed(_):
        receiver.state["revision"] += 1
        return "not returned"

    observer.backend.value = changed
    with pytest.raises(IdentityError, match="Receiver identity changed"):
        session.read_value(observation, target)
    assert receiver.calls == 0


def test_unverifiable_value_is_rejected_before_read():
    observer, _, session, observation, target = fixture()
    observer.backend.value_verifiable = False
    # Observe again so the unavailable capability is part of the identity.
    fresh = session.observe(100)
    target = session.resolve(fresh["observation_id"], automation_id="201")
    observer.backend.value = lambda _: pytest.fail("must not read")
    with pytest.raises(IdentityError, match="Unsupported"):
        session.read_value(fresh["observation_id"], target)
