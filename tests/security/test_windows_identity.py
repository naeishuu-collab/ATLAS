"""Negative identity fixtures independent of the Windows provider."""

from dataclasses import dataclass, replace

import pytest

from openjarvis.windows.identity import (
    ControlIdentity,
    IdentityError,
    IdentitySession,
    ProcessIdentity,
    WindowIdentity,
)


@dataclass
class Element:
    identity: ControlIdentity
    name: str = "Save"
    enabled: bool = True
    offscreen: bool = False
    stale: bool = False


def control(runtime=(1, 2), automation_id="save", name="Save"):
    return Element(
        ControlIdentity(
            runtime,
            10,
            101,
            automation_id,
            50000,
            "Button",
            "Win32",
            ((1,), runtime),
        ),
        name,
    )


class FixtureBackend:
    def __init__(self):
        self.live_window = WindowIdentity(
            ProcessIdentity(10, 1000, "c:/fixture.exe"),
            100,
            20,
            "Fixture",
            "initial",
        )
        self.front = 100
        self.elements = [control()]
        self.window_changes_during_enumeration = False
        self.value_verifiable = True

    def begin_observation(self):
        pass

    def window(self, hwnd):
        return self.live_window

    def foreground(self):
        return self.front

    def enumerate(self, hwnd, limit):
        if self.window_changes_during_enumeration:
            self.live_window = replace(self.live_window, generation="replaced")
        return list(self.elements)

    def control(self, element, hwnd):
        if element.stale:
            raise IdentityError("Stale UIA reference")
        return element.identity, element.name, element.enabled, element.offscreen

    def same_element(self, retained, current):
        return retained is current

    def value_capability(self, element):
        return self.value_verifiable


@pytest.fixture
def fixture():
    backend = FixtureBackend()
    session = IdentitySession(backend)
    observation = session.observe(100)
    return backend, session, observation, observation.controls[0].target_id


def test_positive_identity_does_not_authorize_mutation(fixture):
    _, session, observation, target_id = fixture
    verdict = session.validate(observation.observation_id, target_id)
    assert verdict["identity_valid"] is True
    assert verdict["mutation_allowed"] is False
    assert not hasattr(session, "click")
    assert not hasattr(session, "type")


def test_duplicate_same_name_is_ambiguous():
    backend = FixtureBackend()
    backend.elements.append(control((1, 3), "save-two"))
    session = IdentitySession(backend)
    observation = session.observe(100)
    with pytest.raises(IdentityError, match="2 matches"):
        session.select(observation.observation_id, name="Save")
    first = session.select(observation.observation_id, automation_id="save")
    assert first == observation.controls[0].target_id


def test_duplicate_automation_id_is_ambiguous():
    backend = FixtureBackend()
    backend.elements.append(control((1, 3)))
    session = IdentitySession(backend)
    observation = session.observe(100)
    with pytest.raises(IdentityError, match="2 matches"):
        session.select(observation.observation_id, automation_id="save")


@pytest.mark.parametrize(
    "fields",
    [
        {"pid": 11},
        {"created_filetime": 2000},
        {"executable": "c:/other.exe"},
    ],
)
def test_wrong_process_or_application_restart(fixture, fields):
    backend, session, observation, target = fixture
    backend.live_window = replace(
        backend.live_window,
        process=replace(backend.live_window.process, **fields),
    )
    with pytest.raises(IdentityError, match="lifetime mismatch"):
        session.validate(observation.observation_id, target)
    with pytest.raises(IdentityError, match="Stale or unknown"):
        session.validate(observation.observation_id, target)


@pytest.mark.parametrize(
    "fields",
    [
        {"hwnd": 200},
        {"thread_id": 21},
        {"class_name": "Other"},
        {"generation": "HWND-reused"},
    ],
)
def test_window_recreation_and_hwnd_reuse(fixture, fields):
    backend, session, observation, target = fixture
    backend.live_window = replace(backend.live_window, **fields)
    with pytest.raises(IdentityError, match="lifetime mismatch"):
        session.validate(observation.observation_id, target)


def test_wrong_foreground(fixture):
    backend, session, observation, target = fixture
    backend.front = 200
    with pytest.raises(IdentityError, match="Wrong foreground"):
        session.validate(observation.observation_id, target)


@pytest.mark.parametrize(
    "fields",
    [
        {"runtime_id": (1, 3)},
        {"process_id": 11},
        {"hwnd": 202},
        {"automation_id": "other"},
        {"control_type": 50004},
        {"class_name": "Edit"},
        {"framework": "Other"},
        {"hierarchy": ((9,), (1, 2))},
    ],
)
def test_control_identity_or_hierarchy_mismatch(fixture, fields):
    backend, session, observation, target = fixture
    backend.elements[0].identity = replace(backend.elements[0].identity, **fields)
    with pytest.raises(IdentityError, match="identity/hierarchy mismatch"):
        session.validate(observation.observation_id, target)


def test_stale_control_refused(fixture):
    backend, session, observation, target = fixture
    backend.elements[0].stale = True
    with pytest.raises(IdentityError, match="Stale UIA reference"):
        session.validate(observation.observation_id, target)


def test_replacement_with_same_semantic_and_runtime_properties_refused(fixture):
    backend, session, observation, target = fixture
    backend.elements[0] = control()
    with pytest.raises(IdentityError, match="replaced retained control"):
        session.validate(observation.observation_id, target)


def test_new_duplicate_runtime_identity_refused(fixture):
    backend, session, observation, target = fixture
    backend.elements.append(control())
    with pytest.raises(IdentityError, match="Ambiguous live runtime"):
        session.validate(observation.observation_id, target)


def test_removed_target_cannot_semantically_retarget(fixture):
    backend, session, observation, target = fixture
    backend.elements = [control((1, 3), "save", "Save")]
    with pytest.raises(IdentityError, match="Stale or replaced"):
        session.validate(observation.observation_id, target)


def test_new_observation_invalidates_old_tokens(fixture):
    _, session, observation, target = fixture
    latest = session.observe(100)
    assert latest.observation_id != observation.observation_id
    with pytest.raises(IdentityError, match="Stale or unknown"):
        session.validate(observation.observation_id, target)


@pytest.mark.parametrize("enabled,offscreen", [(False, False), (True, True)])
def test_control_preconditions_fail_closed(fixture, enabled, offscreen):
    backend, session, observation, target = fixture
    backend.elements[0].enabled, backend.elements[0].offscreen = enabled, offscreen
    with pytest.raises(IdentityError, match="preconditions"):
        session.validate(observation.observation_id, target)


def test_partial_observation_is_not_usable():
    backend = FixtureBackend()
    backend.elements.append(control((1, 3)))
    session = IdentitySession(backend, max_controls=1)
    with pytest.raises(IdentityError, match="Incomplete"):
        session.observe(100)
    assert session._latest is None and session._elements == {}


def test_window_change_during_observation_refused():
    backend = FixtureBackend()
    backend.window_changes_during_enumeration = True
    with pytest.raises(IdentityError, match="changed during observation"):
        IdentitySession(backend).observe(100)


@pytest.mark.parametrize("hints", [{}, {"ordinal": 0}, {"name": "not present"}])
def test_no_first_match_or_ordinal_fallback(fixture, hints):
    _, session, observation, _ = fixture
    with pytest.raises(IdentityError):
        session.select(observation.observation_id, **hints)


def test_display_name_change_does_not_change_retained_identity(fixture):
    backend, session, observation, target = fixture
    backend.elements[0].name = "Saved"
    assert session.validate(observation.observation_id, target)["identity_valid"]


def test_value_verification_capability_is_required_before_typing():
    backend = FixtureBackend()
    backend.elements = [control()]
    backend.elements[0].identity = replace(
        backend.elements[0].identity,
        control_type=50004,
        class_name="Edit",
    )
    backend.value_verifiable = False
    session = IdentitySession(backend)
    observation = session.observe(100)
    target = observation.controls[0]
    assert target.value_verifiable is False
    with pytest.raises(IdentityError, match="Value verification capability"):
        session.validate(
            observation.observation_id,
            target.target_id,
            require_value_verifiable=True,
        )
    backend.value_verifiable = True
    observation = session.observe(100)
    target = observation.controls[0]
    assert target.value_verifiable is True
    assert session.validate(
        observation.observation_id,
        target.target_id,
        require_value_verifiable=True,
    )["identity_valid"]
