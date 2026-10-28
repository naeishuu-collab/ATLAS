"""Observation-bound mutations for explicitly trusted cooperative receivers.

No arbitrary application receives control messages from this controller.
The receiver must perform compare-and-dispatch on its GUI owner thread.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Protocol

from openjarvis.windows.identity import IdentityError


class Receiver(Protocol):
    pid: int

    def snapshot(self) -> dict: ...
    def dispatch(self, request: dict) -> dict: ...


def failure_code(error: Exception) -> str:
    text = str(error).lower()
    if "foreground" in text:
        return "WRONG_FOREGROUND"
    if "ambiguous" in text or "matches" in text:
        return "AMBIGUOUS_TARGET"
    if "stale" in text or "unknown observation" in text or "does not exist" in text:
        return "STALE_TARGET"
    if "mismatch" in text or "terminated" in text:
        return "IDENTITY_MISMATCH"
    if "unsupported" in text or "capability" in text:
        return "UNSUPPORTED_CONTROL"
    return "PRECONDITION_FAILURE"


def native_window(identity: dict) -> dict:
    return copy.deepcopy({k: v for k, v in identity.items() if k != "generation"})


class WindowsActionSession:
    """One explicit cooperative application, one latest authorization.

    The existing executor/journal supplies durable quarantine. Consumption here
    is one-use observation authority, not a separate replay/quarantine store.
    """

    def __init__(self, observer, receiver: Receiver):
        self.observer = observer
        self.receiver = receiver
        self._lock = threading.RLock()
        self._observation = None
        self._receiver_state = None

    def observe(self, hwnd: int) -> dict:
        with self._lock:
            self._observation = None
            self._receiver_state = None
            before = copy.deepcopy(self.receiver.snapshot())
            observation = self.observer.observe(hwnd)
            after = copy.deepcopy(self.receiver.snapshot())
            if (
                before != after
                or observation["window"]["process"]["pid"] != self.receiver.pid
                or hwnd != after["hwnd"]
                or observation["window"]["process"]["created_filetime"]
                != after["created_filetime"]
            ):
                raise IdentityError("Bound application identity mismatch")
            observation["receiver_identity"] = copy.deepcopy(after)
            self._observation = copy.deepcopy(observation)
            self._receiver_state = after
            return observation

    def resolve(self, observation_id: str, **hints) -> str:
        with self._lock:
            self._current(observation_id)
            try:
                return self.observer.select(observation_id, **hints)
            except Exception:
                self._observation = None
                self._receiver_state = None
                raise

    def _current(self, observation_id: str):
        if (
            self._observation is None
            or self._observation["observation_id"] != observation_id
        ):
            raise IdentityError("Stale or unknown observation")
        return self._observation

    def act(
        self, action: str, observation_id: str, target_id: str, *, value: str = ""
    ) -> dict:
        with self._lock:
            result = {
                "action": action,
                "observation_id": observation_id,
                "target_id": target_id,
                "identity": None,
                "preconditions": "NOT_CHECKED",
                "dispatch": "NOT_DISPATCHED",
                "outcome": "NOT_STARTED",
                "verification": "NOT_VERIFIED",
                "failure": "NONE",
                "retryable": False,
                "evidence": {},
            }
            sent = False
            try:
                if action not in {"click", "type_into"}:
                    raise IdentityError("Unsupported Windows action")
                if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                    raise IdentityError("Invalid bounded text value")
                observation = self._current(observation_id)
                controls = [
                    c for c in observation["controls"] if c["target_id"] == target_id
                ]
                if len(controls) != 1:
                    raise IdentityError("Stale target identity")
                target = controls[0]
                identity = target["identity"]
                result["identity"] = copy.deepcopy(
                    {
                        "window": observation["window"],
                        "control": identity,
                    }
                )
                expected_type = 50000 if action == "click" else 50004
                expected_class = "Button" if action == "click" else "Edit"
                if (
                    identity["control_type"] != expected_type
                    or identity["class_name"] != expected_class
                    or identity["framework"] != "Win32"
                ):
                    raise IdentityError("Unsupported native control identity")
                if action == "type_into" and target.get("value_verifiable") is not True:
                    raise IdentityError(
                        "Unsupported control value verification capability"
                    )
                state = self._receiver_state
                control = state["controls"].get(identity["automation_id"])
                if not control or control["hwnd"] != identity["hwnd"]:
                    raise IdentityError("Receiver control identity mismatch")
                result["identity"]["receiver"] = {
                    "window_cookie": state["window_cookie"],
                    "control_cookie": control["cookie"],
                    "revision": state["revision"],
                }
                # Establish lifetime identity before reporting a focus failure.
                # The second validation still requires foreground before dispatch.
                self.observer.validate(
                    observation_id, target_id, require_foreground=False
                )
                self.observer.validate(
                    observation_id,
                    target_id,
                    require_foreground=True,
                    require_value_verifiable=action == "type_into",
                )
                result["preconditions"] = "PASSED"
                request = {
                    "action": action,
                    "window": native_window(observation["window"]),
                    "window_cookie": state["window_cookie"],
                    "revision": state["revision"],
                    "control_id": identity["automation_id"],
                    "control": copy.deepcopy(control),
                    "value": value,
                }
                # Consume authority before crossing the dispatch boundary.
                self._observation = None
                self._receiver_state = None
                sent = True
                result["dispatch"] = "POSSIBLE"
                ack = self.receiver.dispatch(request)
                if ack.get("dispatched") is not True:
                    if ack.get("dispatched") is not False or not ack.get("failure"):
                        raise RuntimeError("Invalid receiver acknowledgement")
                    result["dispatch"] = "NOT_DISPATCHED"
                    result["failure"] = ack["failure"]
                    result["preconditions"] = "REJECTED_AT_RECEIVER"
                    return result
                result["dispatch"] = "DISPATCHED"
                result["outcome"] = "UNKNOWN_OUTCOME"
                after = self.observer.observe(observation["window"]["hwnd"])
                receiver_after = self.receiver.snapshot()
                if (
                    native_window(after["window"])
                    != native_window(observation["window"])
                    or receiver_after["window_cookie"] != state["window_cookie"]
                    or receiver_after["revision"] != state["revision"] + 1
                    or receiver_after["controls"].get(identity["automation_id"])
                    != control
                ):
                    raise IdentityError(
                        "Post-action application lifetime/state mismatch"
                    )
                post_targets = [
                    c for c in after["controls"] if c["identity"] == identity
                ]
                if len(post_targets) != 1:
                    raise IdentityError("Post-action target identity mismatch")
                if action == "click":
                    for automation_id, expected in (
                        ("301", str(state["revision"] + 1)),
                        ("302", f"clicked:{identity['automation_id']}"),
                    ):
                        pre = [
                            c
                            for c in observation["controls"]
                            if c["identity"]["automation_id"] == automation_id
                        ]
                        post = [
                            c
                            for c in after["controls"]
                            if c["identity"]["automation_id"] == automation_id
                        ]
                        if (
                            len(pre) != 1
                            or len(post) != 1
                            or pre[0]["identity"] != post[0]["identity"]
                            or post[0]["name"] != expected
                            or receiver_after["controls"].get(automation_id)
                            != state["controls"].get(automation_id)
                        ):
                            raise IdentityError("Independent click witness mismatch")
                    result["evidence"] = {
                        "counter_before": state["revision"],
                        "counter_after": state["revision"] + 1,
                    }
                else:
                    actual = self.observer.read_value(
                        after["observation_id"], post_targets[0]["target_id"]
                    )
                    if actual != value:
                        raise IdentityError("Independent text verification mismatch")
                    result["evidence"] = {
                        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
                        "value_length": len(value),
                    }
                result["evidence"]["post_observation_id"] = after["observation_id"]
                result["outcome"] = "VERIFIED"
                result["verification"] = "VERIFIED"
                return result
            except Exception as error:
                self._observation = None
                self._receiver_state = None
                result["failure"] = "UNKNOWN_OUTCOME" if sent else failure_code(error)
                result["outcome"] = "UNKNOWN_OUTCOME" if sent else "NOT_STARTED"
                result["preconditions"] = (
                    result["preconditions"] if sent else "REJECTED"
                )
                result["evidence"]["error_type"] = type(error).__name__
                return result
