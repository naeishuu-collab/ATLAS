"""Identity policy for observation-only Windows automation.

Names are search hints inside a complete, current observation. Only retained
native elements and process/window lifetimes can establish a target identity.
Nothing in this module authorizes or performs a physical mutation.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Protocol


class IdentityError(RuntimeError):
    """An ambiguous, stale, unsupported or mismatched identity fails closed."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    created_filetime: int
    executable: str


@dataclass(frozen=True)
class WindowIdentity:
    process: ProcessIdentity
    hwnd: int
    thread_id: int
    class_name: str
    generation: str


@dataclass(frozen=True)
class ControlIdentity:
    runtime_id: tuple[int, ...]
    process_id: int
    hwnd: int
    automation_id: str
    control_type: int
    class_name: str
    framework: str
    hierarchy: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class ControlObservation:
    target_id: str
    identity: ControlIdentity
    name: str
    enabled: bool
    offscreen: bool
    # A type action is safe to authorize only when the retained UIA element
    # can be read back independently after dispatch. ``None`` means this is
    # not a value control (or the backend cannot establish the capability).
    value_verifiable: bool | None = None


@dataclass(frozen=True)
class Observation:
    observation_id: str
    window: WindowIdentity
    foreground_hwnd: int
    controls: tuple[ControlObservation, ...]

    def to_dict(self) -> dict:
        return asdict(self)


class Backend(Protocol):
    """Calls run on one owner thread; element objects never leave that owner."""

    def begin_observation(self) -> None: ...
    def window(self, hwnd: int) -> WindowIdentity: ...
    def foreground(self) -> int: ...
    def enumerate(self, hwnd: int, limit: int) -> list[object]: ...
    def control(
        self, element: object, hwnd: int
    ) -> tuple[ControlIdentity, str, bool, bool]: ...
    def same_element(self, retained: object, current: object) -> bool: ...
    def value_capability(self, element: object) -> bool: ...
    def value(self, element: object) -> str: ...


class IdentitySession:
    """Retain only the latest complete observation and its native references."""

    def __init__(self, backend: Backend, *, max_controls: int = 128):
        if not 1 <= max_controls <= 1024:
            raise ValueError("max_controls must be between 1 and 1024")
        self.backend = backend
        self.max_controls = max_controls
        self._latest: Observation | None = None
        self._elements: dict[str, object] = {}

    def invalidate(self) -> None:
        self._latest = None
        self._elements.clear()

    def read_value(self, observation_id: str, target_id: str) -> str:
        """Read independently from a freshly retained UIA element."""
        self.validate(observation_id, target_id, require_foreground=False)
        value = self.backend.value(self._elements[target_id])
        self.validate(observation_id, target_id, require_foreground=False)
        return value

    def observe(self, hwnd: int) -> Observation:
        self.invalidate()
        try:
            self.backend.begin_observation()
            window = self.backend.window(hwnd)
            if (
                window.hwnd != hwnd
                or window.process.pid <= 0
                or window.process.created_filetime <= 0
                or not window.process.executable
                or not window.generation
            ):
                raise IdentityError("Incomplete native process/window identity")
            elements = self.backend.enumerate(hwnd, self.max_controls)
            if len(elements) > self.max_controls:
                raise IdentityError("Incomplete control enumeration")
            seen: set[tuple[int, ...]] = set()
            controls = []
            retained = {}
            for element in elements:
                identity, name, enabled, offscreen = self.backend.control(element, hwnd)
                if (
                    not identity.runtime_id
                    or identity.runtime_id in seen
                    or identity.process_id != window.process.pid
                    or not identity.hierarchy
                ):
                    raise IdentityError(
                        "Missing, duplicate or wrong-process UIA identity"
                    )
                seen.add(identity.runtime_id)
                target_id = uuid.uuid4().hex
                value_verifiable = None
                if identity.control_type == 50004:
                    capability = getattr(self.backend, "value_capability", None)
                    if capability is not None:
                        try:
                            value_verifiable = bool(capability(element))
                        except Exception:
                            # Capability uncertainty is safe to carry as a
                            # negative result; mutation will fail closed.
                            value_verifiable = False
                    else:
                        value_verifiable = False
                controls.append(
                    ControlObservation(
                        target_id,
                        identity,
                        name,
                        enabled,
                        offscreen,
                        value_verifiable,
                    )
                )
                retained[target_id] = element
            if self.backend.window(hwnd) != window:
                raise IdentityError("Window changed during observation")
            observation = Observation(
                uuid.uuid4().hex,
                window,
                self.backend.foreground(),
                tuple(controls),
            )
            self._elements = retained
            self._latest = observation
            return observation
        except Exception:
            self.invalidate()
            raise

    def _observation(self, observation_id: str) -> Observation:
        if self._latest is None or self._latest.observation_id != observation_id:
            raise IdentityError("Stale or unknown observation")
        return self._latest

    def select(self, observation_id: str, **hints) -> str:
        """Resolve all matches; no ordinal, first-match or semantic fallback."""
        observation = self._observation(observation_id)
        allowed = {"name", "automation_id", "control_type", "class_name", "framework"}
        if not hints or hints.keys() - allowed:
            raise IdentityError("Explicit supported control hints required")
        matches = [
            control
            for control in observation.controls
            if all(
                (control.name if key == "name" else getattr(control.identity, key))
                == value
                for key, value in hints.items()
            )
        ]
        if len(matches) != 1:
            raise IdentityError(f"Ambiguous or absent target: {len(matches)} matches")
        return matches[0].target_id

    def validate(
        self,
        observation_id: str,
        target_id: str,
        *,
        require_foreground: bool = True,
        require_value_verifiable: bool = False,
    ) -> dict:
        """Check live identity/preconditions. Result is never mutation authority."""
        observation = self._observation(observation_id)
        matching = [c for c in observation.controls if c.target_id == target_id]
        if len(matching) != 1 or target_id not in self._elements:
            raise IdentityError("Target was not retained in this observation")
        target = matching[0]
        try:
            if self.backend.window(observation.window.hwnd) != observation.window:
                raise IdentityError("Process/window lifetime mismatch")
            if (
                require_foreground
                and self.backend.foreground() != observation.window.hwnd
            ):
                raise IdentityError("Wrong foreground window")
            retained = self._elements[target_id]
            current_identity, _, enabled, offscreen = self.backend.control(
                retained,
                observation.window.hwnd,
            )
            if current_identity != target.identity:
                raise IdentityError("Retained control identity/hierarchy mismatch")
            if not enabled or offscreen:
                raise IdentityError("Control preconditions are not satisfied")
            if require_value_verifiable:
                capability = getattr(self.backend, "value_capability", None)
                if capability is None or not capability(retained):
                    raise IdentityError("Value verification capability is unavailable")
            # Enumerate completely again: duplicate matches/runtime IDs cannot
            # disappear behind an early successful match to the retained object.
            current = self.backend.enumerate(observation.window.hwnd, self.max_controls)
            if len(current) > self.max_controls:
                raise IdentityError("Incomplete control enumeration")
            identities = [
                self.backend.control(e, observation.window.hwnd)[0] for e in current
            ]
            if len({i.runtime_id for i in identities}) != len(identities):
                raise IdentityError("Ambiguous live runtime identity")
            matches = [e for e, i in zip(current, identities) if i == target.identity]
            if len(matches) != 1 or not self.backend.same_element(retained, matches[0]):
                raise IdentityError("Stale or replaced retained control")
            if self.backend.window(observation.window.hwnd) != observation.window:
                raise IdentityError("Window changed during validation")
            if (
                require_foreground
                and self.backend.foreground() != observation.window.hwnd
            ):
                raise IdentityError("Foreground changed during validation")
            return {
                "identity_valid": True,
                "mutation_allowed": False,
                "observation_id": observation_id,
                "target_id": target_id,
            }
        except Exception:
            self.invalidate()
            raise
