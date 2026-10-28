"""Test-owned cooperative Win32 application; no user data or GUI framework."""

import ctypes
import hashlib
import json
import multiprocessing
import os
import threading
import time
import uuid
from ctypes import wintypes as w

from openjarvis.windows.receiver import GuardedWin32Receiver


_ASFW_ANY = 0xFFFFFFFF
_GA_ROOT = 2
_DESKTOP_READOBJECTS = 0x0001
_UOI_NAME = 2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _ForegroundTestDoubleCall:
    """Callable replacement for one foreground API in a test helper."""

    def __init__(self, double, api_name):
        self.double = double
        self.api_name = api_name
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.double.call(self.api_name, args)


class _ForegroundTestDouble:
    """Test-only foreground seam; installed explicitly over helper user32 calls."""

    _APIS = (
        "AllowSetForegroundWindow",
        "SetForegroundWindow",
        "SetFocus",
        "GetForegroundWindow",
        "GetFocus",
    )

    def __init__(self, config, event_sink=None):
        self.event_sink = event_sink
        self.events = []
        self.allow_result = True
        self.allow_error = 0
        self.set_foreground_result = True
        self.set_foreground_error = 0
        self.set_focus_result = 1
        self.set_focus_error = 0
        self.foreground_hwnd = 0
        self.focus_hwnd = 0
        self.configure(config)

    def configure(self, config):
        config = config or {}
        if "allow_set_foreground_window_return" in config:
            self.allow_result = bool(
                config["allow_set_foreground_window_return"]
            )
        if "allow_set_foreground_window_error" in config:
            self.allow_error = int(config["allow_set_foreground_window_error"])
        if "set_foreground_window_return" in config:
            self.set_foreground_result = bool(
                config["set_foreground_window_return"]
            )
        if "set_foreground_window_error" in config:
            self.set_foreground_error = int(
                config["set_foreground_window_error"]
            )
        if "set_focus_return" in config:
            self.set_focus_result = int(config["set_focus_return"])
        if "set_focus_error" in config:
            self.set_focus_error = int(config["set_focus_error"])
        if "initial_foreground_hwnd" in config:
            self.foreground_hwnd = int(config["initial_foreground_hwnd"])
        if "initial_focus_hwnd" in config:
            self.focus_hwnd = int(config["initial_focus_hwnd"])
        if config.get("clear_events"):
            self.events.clear()
        return self.snapshot()

    @staticmethod
    def _arguments(args):
        result = []
        for value in args:
            try:
                result.append(int(value))
            except (TypeError, ValueError):
                result.append(str(value))
        return result

    def call(self, api_name, args):
        arguments = self._arguments(args)
        if api_name == "AllowSetForegroundWindow":
            result = 1 if self.allow_result else 0
            if not result:
                ctypes.set_last_error(self.allow_error)
        elif api_name == "SetForegroundWindow":
            result = 1 if self.set_foreground_result else 0
            if result and arguments:
                self.foreground_hwnd = arguments[0]
            elif not result:
                ctypes.set_last_error(self.set_foreground_error)
        elif api_name == "SetFocus":
            result = self.set_focus_result
            if result and arguments:
                self.focus_hwnd = arguments[0]
            elif not result:
                ctypes.set_last_error(self.set_focus_error)
        elif api_name == "GetForegroundWindow":
            result = self.foreground_hwnd
        elif api_name == "GetFocus":
            result = self.focus_hwnd
        else:
            raise ValueError(f"Unknown foreground test API: {api_name}")
        event = {
            "api": api_name,
            "process_pid": os.getpid(),
            "process_thread_id": threading.get_native_id(),
            "sequence": len(self.events) + 1,
            "call_count": sum(
                event["api"] == api_name for event in self.events
            )
            + 1,
            "arguments": arguments,
            "return_value": result,
        }
        self.events.append(event)
        if self.event_sink is not None:
            try:
                self.event_sink.send_bytes(json.dumps(event).encode())
            except (OSError, EOFError):
                pass
        return result

    def snapshot(self):
        return {
            "installed": True,
            "events": list(self.events),
            "call_counts": {
                api_name: sum(
                    event["api"] == api_name for event in self.events
                )
                for api_name in self._APIS
            },
            "virtual_foreground_hwnd": self.foreground_hwnd,
            "virtual_focus_hwnd": self.focus_hwnd,
        }


def _valid_pid(pid, *, own_pid=None):
    """Validate before ctypes can coerce a value to DWORD."""
    if type(pid) is not int or pid <= 0 or pid > 0xFFFFFFFF:
        return False
    if pid == _ASFW_ANY:
        return False
    return own_pid is None or pid != int(own_pid)


def _process_identity(pid):
    if not _valid_pid(pid):
        return {
            "pid": pid,
            "created_filetime": "UNKNOWN",
            "session_id": "UNKNOWN",
            "alive": False,
            "failure": "INVALID_PID",
        }
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [w.LPVOID] * 4
    kernel.GetProcessTimes.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    handle = kernel.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        w.DWORD(pid),
    )
    if not handle:
        return {
            "pid": pid,
            "created_filetime": "UNKNOWN",
            "session_id": "UNKNOWN",
            "alive": False,
            "failure": "PROCESS_IDENTITY_UNKNOWN",
        }
    try:
        times = [w.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(
            handle, *(ctypes.byref(value) for value in times)
        ):
            return {
                "pid": pid,
                "created_filetime": "UNKNOWN",
                "session_id": "UNKNOWN",
                "alive": False,
                "failure": "PROCESS_IDENTITY_UNKNOWN",
            }
        created = (int(times[0].dwHighDateTime) << 32) | int(
            times[0].dwLowDateTime
        )
        session = _process_session_id(pid)
        if session == "UNKNOWN":
            return {
                "pid": pid,
                "created_filetime": created,
                "session_id": "UNKNOWN",
                "alive": True,
                "failure": "SESSION_IDENTITY_UNKNOWN",
            }
        return {
            "pid": pid,
            "created_filetime": created,
            "session_id": session,
            "alive": True,
            "failure": None,
        }
    finally:
        kernel.CloseHandle(handle)


def _user_object_name(user, handle):
    if not handle:
        return "UNKNOWN"
    try:
        user.GetUserObjectInformationW.argtypes = [
            w.HANDLE,
            w.INT,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        user.GetUserObjectInformationW.restype = w.BOOL
        buffer = ctypes.create_unicode_buffer(256)
        returned = w.DWORD()
        if not user.GetUserObjectInformationW(
            handle,
            _UOI_NAME,
            buffer,
            ctypes.sizeof(buffer),
            ctypes.byref(returned),
        ):
            return "UNKNOWN"
        return buffer.value or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def _desktop_identity(user, thread_id, session_id=None):
    """Read desktop identity in the process that owns the thread."""
    result = {
        "session_id": (
            _process_session_id(os.getpid())
            if session_id is None
            else session_id
        ),
        "window_station_name": "UNKNOWN",
        "desktop_name": "UNKNOWN",
        "interactive": "UNKNOWN",
    }
    if result["session_id"] == "UNKNOWN" or not thread_id:
        return result
    input_desktop = None
    try:
        user.GetThreadDesktop.argtypes = [w.DWORD]
        user.GetThreadDesktop.restype = w.HANDLE
        user.GetProcessWindowStation.argtypes = []
        user.GetProcessWindowStation.restype = w.HANDLE
        user.OpenInputDesktop.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        user.OpenInputDesktop.restype = w.HANDLE
        user.CloseDesktop.argtypes = [w.HANDLE]
        user.CloseDesktop.restype = w.BOOL
        desktop = user.GetThreadDesktop(w.DWORD(int(thread_id)))
        station = user.GetProcessWindowStation()
        result["desktop_name"] = _user_object_name(user, desktop)
        result["window_station_name"] = _user_object_name(user, station)
        input_desktop = user.OpenInputDesktop(
            0,
            False,
            _DESKTOP_READOBJECTS,
        )
        input_name = _user_object_name(user, input_desktop)
        if (
            result["desktop_name"] != "UNKNOWN"
            and result["window_station_name"] != "UNKNOWN"
            and input_name != "UNKNOWN"
        ):
            result["interactive"] = bool(
                result["desktop_name"] == input_name
                and result["window_station_name"].lower() == "winsta0"
            )
    except Exception:
        return result
    finally:
        if input_desktop:
            try:
                user.CloseDesktop(input_desktop)
            except Exception:
                pass
    return result


def _window_identity(
    user,
    hwnd,
    *,
    top_hwnd=None,
    property_name=None,
    property_marker=None,
):
    """Read owner, ancestry and fixture-cookie evidence without changing focus."""
    result = {
        "hwnd": int(hwnd or 0),
        "owner_pid": "UNKNOWN",
        "owner_thread_id": "UNKNOWN",
        "owner_session_id": "UNKNOWN",
        "is_window": False,
        "ancestor_hwnd": "UNKNOWN",
        "is_top_level": "UNKNOWN",
        "is_descendant": "UNKNOWN",
        "cookie_valid": "UNKNOWN",
    }
    if not result["hwnd"]:
        return result
    try:
        user.IsWindow.argtypes = [w.HWND]
        user.IsWindow.restype = w.BOOL
        result["is_window"] = bool(user.IsWindow(w.HWND(result["hwnd"])))
        if not result["is_window"]:
            return result
        owner_pid = w.DWORD()
        user.GetWindowThreadProcessId.argtypes = [
            w.HWND,
            ctypes.POINTER(w.DWORD),
        ]
        user.GetWindowThreadProcessId.restype = w.DWORD
        owner_thread = int(
            user.GetWindowThreadProcessId(
                w.HWND(result["hwnd"]), ctypes.byref(owner_pid)
            )
        )
        if not owner_thread or not owner_pid.value:
            return result
        result["owner_pid"] = int(owner_pid.value)
        result["owner_thread_id"] = owner_thread
        result["owner_session_id"] = _process_session_id(int(owner_pid.value))
        user.GetAncestor.argtypes = [w.HWND, w.UINT]
        user.GetAncestor.restype = w.HWND
        ancestor = int(
            user.GetAncestor(w.HWND(result["hwnd"]), _GA_ROOT) or 0
        )
        result["ancestor_hwnd"] = ancestor
        result["is_top_level"] = ancestor == result["hwnd"]
        if top_hwnd is None:
            result["is_descendant"] = result["is_top_level"]
        else:
            user.IsChild.argtypes = [w.HWND, w.HWND]
            user.IsChild.restype = w.BOOL
            result["is_descendant"] = bool(
                ancestor == int(top_hwnd)
                and user.IsChild(w.HWND(top_hwnd), w.HWND(result["hwnd"]))
            )
        if property_name and property_marker is not None:
            user.GetPropW.argtypes = [w.HWND, w.LPCWSTR]
            user.GetPropW.restype = w.HANDLE
            result["cookie_valid"] = bool(
                int(user.GetPropW(w.HWND(result["hwnd"]), property_name) or 0)
                == int(property_marker)
            )
        else:
            result["cookie_valid"] = False
    except Exception:
        return result
    return result


def _identity_digest(identity):
    identity = dict(identity)
    identity.pop("identity_digest", None)
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _desktop_matches(expected, observed):
    if not isinstance(expected, dict) or not isinstance(observed, dict):
        return False
    required = ("session_id", "window_station_name", "desktop_name")
    if any(expected.get(key) in (None, "UNKNOWN") for key in required):
        return False
    if any(observed.get(key) in (None, "UNKNOWN") for key in required):
        return False
    return all(expected.get(key) == observed.get(key) for key in required) and (
        expected.get("interactive") is True
        and observed.get("interactive") is True
    )


def _validate_registered_identity(user, identity, *, own_pid):
    """Guardian-side validation of a frozen target identity record."""
    if not isinstance(identity, dict):
        return False, "TARGET_IDENTITY_MISMATCH", {}
    pid = identity.get("pid")
    if not _valid_pid(pid, own_pid=own_pid):
        return False, "INVALID_TARGET_PID", {}
    process = _process_identity(pid)
    if (
        process.get("pid") != pid
        or
        not process.get("alive")
        or process.get("created_filetime") != identity.get("created_filetime")
        or process.get("session_id") != identity.get("session_id")
    ):
        return False, "TARGET_PROCESS_IDENTITY_MISMATCH", {"process": process}
    top = _window_identity(
        user,
        identity.get("hwnd"),
        property_name=identity.get("window_property_name"),
        property_marker=identity.get("window_property_marker"),
    )
    control = _window_identity(
        user,
        identity.get("control_hwnd"),
        top_hwnd=identity.get("hwnd"),
        property_name=identity.get("window_property_name"),
        property_marker=identity.get("control_property_marker"),
    )
    if (
        not top.get("is_window")
        or top.get("owner_pid") != pid
        or top.get("owner_thread_id") != identity.get("top_owner_thread_id")
        or top.get("owner_session_id") != identity.get("session_id")
        or top.get("is_top_level") is not True
        or top.get("ancestor_hwnd") != identity.get("hwnd")
        or identity.get("top_ancestor_hwnd") != identity.get("hwnd")
        or identity.get("top_is_top_level") is not True
        or top.get("cookie_valid") is not True
    ):
        return False, "TARGET_HWND_OWNER_MISMATCH", {"process": process, "top": top}
    if (
        not control.get("is_window")
        or control.get("owner_pid") != pid
        or control.get("owner_thread_id")
        != identity.get("control_owner_thread_id")
        or control.get("owner_session_id") != identity.get("session_id")
        or control.get("is_descendant") is not True
        or control.get("cookie_valid") is not True
    ):
        return False, "CONTROL_IDENTITY_MISMATCH", {
            "process": process,
            "top": top,
            "control": control,
        }
    observed_desktop = _desktop_identity(user, top.get("owner_thread_id"))
    if not _desktop_matches(identity.get("desktop"), observed_desktop):
        return False, "DESKTOP_IDENTITY_UNKNOWN", {
            "process": process,
            "top": top,
            "control": control,
            "desktop": observed_desktop,
        }
    if identity.get("identity_digest") != _identity_digest(identity):
        return False, "TARGET_IDENTITY_MISMATCH", {
            "process": process,
            "top": top,
            "control": control,
            "desktop": observed_desktop,
        }
    return True, None, {
        "process": process,
        "top": top,
        "control": control,
        "desktop": observed_desktop,
    }


def _independent_target_verification(identity):
    """Runner-side read-only verification; provider values are not authority."""
    if not isinstance(identity, dict):
        return False, "TARGET_IDENTITY_MISMATCH", {}
    user = ctypes.WinDLL("user32", use_last_error=True)
    process = _process_identity(identity.get("pid"))
    if (
        process.get("pid") != identity.get("pid")
        or
        not process.get("alive")
        or process.get("created_filetime") != identity.get("created_filetime")
        or process.get("session_id") != identity.get("session_id")
    ):
        return False, "TARGET_PROCESS_IDENTITY_MISMATCH", {"process": process}
    foreground = _foreground_identity(user)
    if (
        foreground.get("hwnd") != identity.get("hwnd")
        or foreground.get("pid") != identity.get("pid")
        or foreground.get("session_id") != identity.get("session_id")
        or not foreground.get("is_window")
    ):
        return False, "TARGET_FOREGROUND_MISMATCH", {"foreground": foreground}
    top = _window_identity(
        user,
        identity.get("hwnd"),
        property_name=identity.get("window_property_name"),
        property_marker=identity.get("window_property_marker"),
    )
    control = _window_identity(
        user,
        identity.get("control_hwnd"),
        top_hwnd=identity.get("hwnd"),
        property_name=identity.get("window_property_name"),
        property_marker=identity.get("control_property_marker"),
    )
    if (
        top.get("owner_pid") != identity.get("pid")
        or top.get("owner_thread_id") != identity.get("top_owner_thread_id")
        or top.get("is_top_level") is not True
        or top.get("ancestor_hwnd") != identity.get("hwnd")
        or top.get("cookie_valid") is not True
        or control.get("owner_pid") != identity.get("pid")
        or control.get("owner_thread_id")
        != identity.get("control_owner_thread_id")
        or control.get("is_descendant") is not True
        or control.get("cookie_valid") is not True
    ):
        return False, "TARGET_IDENTITY_MISMATCH", {
            "foreground": foreground,
            "top": top,
            "control": control,
        }
    desktop = _desktop_identity(
        user,
        top.get("owner_thread_id"),
        session_id=identity.get("session_id"),
    )
    if not _desktop_matches(identity.get("desktop"), desktop):
        return False, "DESKTOP_IDENTITY_UNKNOWN", {
            "foreground": foreground,
            "top": top,
            "control": control,
            "desktop": desktop,
        }
    gui_info = {
        "focus_hwnd": "UNKNOWN",
        "active_hwnd": "UNKNOWN",
    }
    try:
        class GuiThreadInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", w.DWORD),
                ("flags", w.DWORD),
                ("hwndActive", w.HWND),
                ("hwndFocus", w.HWND),
                ("hwndCapture", w.HWND),
                ("hwndMenuOwner", w.HWND),
                ("hwndMoveSize", w.HWND),
                ("hwndCaret", w.HWND),
                ("rcCaret", w.RECT),
            ]

        user.GetGUIThreadInfo.argtypes = [w.DWORD, ctypes.POINTER(GuiThreadInfo)]
        user.GetGUIThreadInfo.restype = w.BOOL
        info = GuiThreadInfo()
        info.cbSize = ctypes.sizeof(info)
        if not user.GetGUIThreadInfo(
            w.DWORD(identity["top_owner_thread_id"]), ctypes.byref(info)
        ):
            return False, "TARGET_FOCUS_UNKNOWN", {
                "foreground": foreground,
                "top": top,
                "control": control,
                "desktop": desktop,
            }
        gui_info = {
            "focus_hwnd": int(info.hwndFocus or 0),
            "active_hwnd": int(info.hwndActive or 0),
        }
    except Exception:
        return False, "TARGET_FOCUS_UNKNOWN", {
            "foreground": foreground,
            "top": top,
            "control": control,
            "desktop": desktop,
        }
    if gui_info["focus_hwnd"] != identity.get("control_hwnd"):
        return False, "TARGET_FOCUS_MISMATCH", {
            "foreground": foreground,
            "top": top,
            "control": control,
            "desktop": desktop,
            "gui_thread": gui_info,
        }
    return True, None, {
        "foreground": foreground,
        "top": top,
        "control": control,
        "desktop": desktop,
        "gui_thread": gui_info,
    }


_NO_ATTEMPT_FAILURES = frozenset(
    {
        "HANDOFF_NOT_REGISTERED",
        "DUPLICATE_GRANT",
        "INVALID_TARGET_PID",
        "GUARDIAN_OWNERSHIP_CHANGED",
        "TARGET_PROCESS_IDENTITY_MISMATCH",
        "TARGET_HWND_OWNER_MISMATCH",
        "CONTROL_IDENTITY_MISMATCH",
        "TARGET_IDENTITY_MISMATCH",
        "TARGET_FOCUS_UNKNOWN",
        "DESKTOP_IDENTITY_UNKNOWN",
    }
)
_NO_ATTEMPT_REVERIFICATION_FAILURES = frozenset(
    {
        "GUARDIAN_OWNERSHIP_CHANGED",
        "TARGET_PROCESS_IDENTITY_MISMATCH",
        "TARGET_HWND_OWNER_MISMATCH",
        "CONTROL_IDENTITY_MISMATCH",
        "TARGET_IDENTITY_MISMATCH",
        "TARGET_FOCUS_UNKNOWN",
        "DESKTOP_IDENTITY_UNKNOWN",
    }
)
_GRANT_ORDER_PREFIX = [
    "guardian_identity_reverified",
    "target_identity_verified",
    "foreground_identity_reverified",
    "grant_call",
]


def _validate_grant_timeline(grant, *, expect_success):
    timeline = grant.get("timeline") if isinstance(grant, dict) else None
    if not isinstance(timeline, list) or len(timeline) != 2:
        return False
    before, result = timeline
    if not isinstance(before, dict) or not isinstance(result, dict):
        return False
    if before.get("event") != "verified_guardian_grant_before":
        return False
    if result.get("event") != (
        "verified_guardian_allow_set_foreground_window_result"
    ):
        return False
    expected_bool = True if expect_success else False
    if result.get("api_bool") is not expected_bool:
        return False
    if expect_success:
        return result.get("last_error") is None
    return type(result.get("last_error")) is int


def _validate_no_attempt_grant_evidence(grant):
    required = {
        "state",
        "failure",
        "grant_attempted",
        "granted",
        "requested_pid",
        "guardian_identity",
        "target_identity",
        "native_bool",
        "immediate_last_error",
        "last_error",
        "last_error_capture",
        "grant_call_count",
        "ordering",
        "timeline",
    }
    if not isinstance(grant, dict) or not required.issubset(grant):
        return False, "GRANT_EVIDENCE_INVALID"
    failure = grant.get("failure")
    expected_ordering = (
        ["guardian_identity_reverified"]
        if failure in _NO_ATTEMPT_REVERIFICATION_FAILURES
        else []
    )
    identity = grant.get("guardian_identity")
    target_identity = grant.get("target_identity")
    structural_valid = (
        grant.get("state") == "S3_GRANT_RESULT"
        and failure in _NO_ATTEMPT_FAILURES
        and grant.get("grant_attempted") is False
        and grant.get("granted") is None
        and grant.get("requested_pid") is None
        and isinstance(identity, dict)
        and isinstance(target_identity, dict)
        and grant.get("native_bool") is None
        and grant.get("immediate_last_error") is None
        and grant.get("last_error") is None
        and grant.get("last_error_capture") == "not_attempted"
        and grant.get("grant_call_count") == 0
        and grant.get("ordering") == expected_ordering
        and isinstance(grant.get("timeline"), list)
    )
    if not structural_valid:
        return False, "GRANT_EVIDENCE_INVALID"
    if failure in _NO_ATTEMPT_REVERIFICATION_FAILURES:
        timeline_events = (
            [event.get("event") for event in grant["timeline"]]
            if all(isinstance(event, dict) for event in grant["timeline"])
            else None
        )
        if (
            identity.get("pid") is None
            or identity.get("hwnd") is None
            or identity.get("session_id") in (None, "UNKNOWN")
            or identity.get("is_window") is not True
            or not identity.get("channel_token")
            or not target_identity
            or timeline_events
            != [
                "verified_guardian_grant_before",
                "verified_guardian_ownership_changed",
            ]
        ):
            return False, "GRANT_EVIDENCE_INVALID"
    elif identity or target_identity or grant.get("timeline"):
        return False, "GRANT_EVIDENCE_INVALID"
    return True, failure


def _validate_grant_evidence(
    grant,
    target_identity,
    guardian_pid,
    guardian_hwnd,
    guardian_session_id=None,
    guardian_created_filetime=None,
    guardian_desktop=None,
    target_identity_digest=None,
    expect_success=True,
):
    required = {
        "state",
        "grant_attempted",
        "requested_pid",
        "guardian_identity",
        "target_identity",
        "native_bool",
        "granted",
        "immediate_last_error",
        "last_error",
        "last_error_capture",
        "grant_call_count",
        "ordering",
        "failure",
        "timeline",
    }
    if not isinstance(grant, dict) or not required.issubset(grant):
        return False, "GRANT_EVIDENCE_INVALID"
    guardian_identity = grant.get("guardian_identity")
    target_evidence = grant.get("target_identity")
    if not isinstance(guardian_identity, dict) or not isinstance(
        target_evidence, dict
    ) or not isinstance(target_identity, dict):
        return False, "GRANT_EVIDENCE_INVALID"
    ordering = grant.get("ordering")
    expected_final_event = "grant_returned" if expect_success else "last_error_captured"
    semantic_invalid = (
        grant.get("state") != "S3_GRANT_RESULT"
        or grant.get("grant_attempted") is not True
        or grant.get("requested_pid") != target_identity.get("pid")
        or not _valid_pid(grant.get("requested_pid"), own_pid=guardian_pid)
        or guardian_identity.get("pid") != guardian_pid
        or guardian_identity.get("hwnd") != guardian_hwnd
        or (
            guardian_session_id is not None
            and guardian_identity.get("session_id") != guardian_session_id
        )
        or (
            guardian_created_filetime is not None
            and guardian_identity.get("created_filetime")
            != guardian_created_filetime
        )
        or (
            guardian_desktop is not None
            and not _desktop_matches(
                guardian_desktop, guardian_identity.get("desktop")
            )
        )
        or guardian_identity.get("is_window") is not True
        or not guardian_identity.get("channel_token")
        or not target_evidence.get("channel_token")
        or grant.get("grant_call_count") != 1
        or (
            target_identity_digest is not None
            and target_evidence.get("identity_digest") != target_identity_digest
        )
        or not isinstance(ordering, list)
        or ordering != _GRANT_ORDER_PREFIX + [expected_final_event]
        or not _validate_grant_timeline(grant, expect_success=expect_success)
        or _identity_digest(target_evidence)
        != target_evidence.get("identity_digest")
        or target_evidence.get("identity_digest") != target_identity_digest
    )
    if semantic_invalid:
        return False, "GRANT_EVIDENCE_INVALID"
    if expect_success:
        semantic_invalid = semantic_invalid or (
            grant.get("native_bool") is not True
            or grant.get("granted") is not True
            or grant.get("failure") is not None
            or grant.get("immediate_last_error") is not None
            or grant.get("last_error") is not None
            or grant.get("last_error_capture")
            != "not_applicable_on_success"
        )
    else:
        semantic_invalid = semantic_invalid or (
            grant.get("native_bool") is not False
            or grant.get("granted") is not False
            or grant.get("failure") != "GRANT_REJECTED"
            or type(grant.get("immediate_last_error")) is not int
            or grant.get("last_error") != grant.get("immediate_last_error")
            or grant.get("last_error_capture") != "captured_on_failure"
        )
    if semantic_invalid:
        return False, "GRANT_EVIDENCE_INVALID"
    return True, None


def _process_session_id(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [w.DWORD, ctypes.POINTER(w.DWORD)]
    kernel.ProcessIdToSessionId.restype = w.BOOL
    session = w.DWORD()
    if not pid or not kernel.ProcessIdToSessionId(int(pid), ctypes.byref(session)):
        return "UNKNOWN"
    return int(session.value)


def _foreground_identity(user):
    user.GetForegroundWindow.restype = w.HWND
    hwnd = int(user.GetForegroundWindow() or 0)
    pid = w.DWORD()
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    thread_id = (
        int(user.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid)))
        if hwnd
        else 0
    )
    user.IsWindow.argtypes = [w.HWND]
    user.IsWindow.restype = w.BOOL
    return {
        "hwnd": hwnd,
        "pid": int(pid.value) if hwnd else 0,
        "thread_id": thread_id,
        "session_id": _process_session_id(int(pid.value)) if hwnd else "UNKNOWN",
        "is_window": bool(user.IsWindow(w.HWND(hwnd))) if hwnd else False,
    }


def _foreground_timing_snapshot(user, event, process_pid=None, process_thread_id=None):
    """Read-only timing sample; values are not an atomic cross-process snapshot."""
    process_pid = int(os.getpid() if process_pid is None else process_pid)
    process_thread_id = int(
        threading.get_native_id() if process_thread_id is None else process_thread_id
    )
    user.GetForegroundWindow.restype = w.HWND
    foreground = int(user.GetForegroundWindow() or 0)
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    foreground_pid = w.DWORD()
    foreground_thread_id = user.GetWindowThreadProcessId(
        w.HWND(foreground), ctypes.byref(foreground_pid)
    ) if foreground else 0
    foreground_pid_value = int(foreground_pid.value) if foreground else "UNKNOWN"

    last_input_tick = "UNKNOWN"
    try:
        class LastInputInfo(ctypes.Structure):
            _fields_ = [("cbSize", w.UINT), ("dwTime", w.DWORD)]

        info = LastInputInfo(ctypes.sizeof(LastInputInfo), 0)
        user.GetLastInputInfo.argtypes = [ctypes.POINTER(LastInputInfo)]
        user.GetLastInputInfo.restype = w.BOOL
        if user.GetLastInputInfo(ctypes.byref(info)):
            last_input_tick = int(info.dwTime)
    except Exception:
        pass

    current_tick = "UNKNOWN"
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetTickCount.argtypes = []
        kernel.GetTickCount.restype = w.DWORD
        current_tick = int(kernel.GetTickCount())
    except Exception:
        pass

    foreground_lock_timeout = "UNKNOWN"
    try:
        timeout = w.DWORD()
        user.SystemParametersInfoW.argtypes = [
            w.UINT,
            w.UINT,
            ctypes.c_void_p,
            w.UINT,
        ]
        user.SystemParametersInfoW.restype = w.BOOL
        if user.SystemParametersInfoW(0x2000, 0, ctypes.byref(timeout), 0):
            foreground_lock_timeout = int(timeout.value)
    except Exception:
        pass

    return {
        "event": event,
        "process_pid": process_pid,
        "process_thread_id": process_thread_id,
        "monotonic_timestamp": time.monotonic(),
        "foreground_hwnd": foreground,
        "foreground_pid": foreground_pid_value,
        "foreground_session_id": (
            _process_session_id(foreground_pid_value)
            if foreground
            else "UNKNOWN"
        ),
        "foreground_thread_id": int(foreground_thread_id) if foreground else "UNKNOWN",
        "foreground_is_window": "UNKNOWN",
        "last_input_tick": last_input_tick,
        "current_tick": current_tick,
        "foreground_lock_timeout": foreground_lock_timeout,
        "api_bool": None,
        "last_error": None,
        "focus_hwnd": None,
        "observation_limitations": [
            "cross_process_snapshot_not_atomic",
            "last_input_recipient_not_observed",
        ],
    }


def _grant_foreground(
    user,
    pid,
    event_prefix="allow_set_foreground_window",
    pre_snapshot=None,
    own_pid=None,
):
    if not _valid_pid(pid, own_pid=own_pid):
        return {
            "granted": False,
            "native_bool": None,
            "last_error": None,
            "immediate_last_error": None,
            "last_error_capture": "not_attempted",
            "requested_pid": None,
            "grant_attempted": False,
            "grant_call_count": 0,
            "failure": "INVALID_TARGET_PID",
            "timeline": [],
        }
    user.AllowSetForegroundWindow.argtypes = [w.DWORD]
    user.AllowSetForegroundWindow.restype = w.BOOL
    timeline = [
        pre_snapshot
        if pre_snapshot is not None
        else _foreground_timing_snapshot(user, f"{event_prefix}_before")
    ]
    ctypes.set_last_error(0)
    granted_raw = user.AllowSetForegroundWindow(pid)
    # Capture before any other Win32 call; zero on failure remains failure.
    error = ctypes.get_last_error() if not granted_raw else None
    result_event = dict(timeline[0])
    result_event.update(
        event=f"{event_prefix}_result",
        monotonic_timestamp=time.monotonic(),
        api_bool=bool(granted_raw),
        last_error=error,
    )
    result_event["observation_limitations"] = list(
        result_event.get("observation_limitations", [])
    ) + ["foreground_fields_are_pre_call_observation"]
    timeline.append(result_event)
    return {
        "granted": bool(granted_raw),
        "native_bool": bool(granted_raw),
        "last_error": error,
        "immediate_last_error": error,
        "last_error_capture": (
            "captured_on_failure" if not granted_raw else "not_applicable_on_success"
        ),
        "requested_pid": int(pid),
        "grant_call_count": 1,
        "timeline": timeline,
    }


def _foreground_context(user, helper_pid, foreground, live):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [w.DWORD, ctypes.POINTER(w.DWORD)]
    kernel.ProcessIdToSessionId.restype = w.BOOL

    def session_id(pid):
        session = w.DWORD()
        if not pid or not kernel.ProcessIdToSessionId(pid, ctypes.byref(session)):
            return "UNKNOWN"
        return int(session.value)

    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    owner = w.DWORD()
    owner_thread = user.GetWindowThreadProcessId(foreground, ctypes.byref(owner))
    return {
        "sample": "after_runner_grant_before_focus_request",
        "runner_pid": os.getpid(),
        "runner_thread_id": threading.get_native_id(),
        "runner_session_id": session_id(os.getpid()),
        "helper_pid": helper_pid,
        "helper_session_id": session_id(helper_pid),
        "foreground_hwnd": foreground,
        "foreground_owner_pid": int(owner.value) or "UNKNOWN",
        "foreground_owner_thread_id": int(owner_thread) or "UNKNOWN",
        "foreground_owner_session_id": session_id(owner.value),
        "foreground_is_live_fixture": any(
            source.hwnd == foreground and source.process.is_alive() for source in live
        ),
        "foreground_eligibility": "UNKNOWN",
    }


class Application:
    def __init__(self, foreground_event_sink=None, channel_token=None):
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.foreground_event_sink = foreground_event_sink
        self.channel_token = channel_token or uuid.uuid4().hex
        self.count = 0
        self.events = []
        self.activation_events = []
        self.ready = False
        self.handles = {}
        self._handoff_registry = {}
        self._target_handoff_registry = {}
        self._focus_handoffs = set()
        self.user.CreateWindowExW.argtypes = (
            [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD]
            + [ctypes.c_int] * 4
            + [w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID]
        )
        self.user.CreateWindowExW.restype = w.HWND
        self.user.GetWindowLongPtrW.argtypes = [w.HWND, ctypes.c_int]
        self.user.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        self.user.SetWindowLongPtrW.argtypes = [w.HWND, ctypes.c_int, ctypes.c_ssize_t]
        self.user.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        self.user.CallWindowProcW.argtypes = [
            w.LPVOID,
            w.HWND,
            w.UINT,
            w.WPARAM,
            w.LPARAM,
        ]
        self.user.CallWindowProcW.restype = ctypes.c_ssize_t
        for name, args, result in (
            ("ShowWindow", [w.HWND, ctypes.c_int], w.BOOL),
            ("SetPropW", [w.HWND, w.LPCWSTR, w.HANDLE], w.BOOL),
            ("GetPropW", [w.HWND, w.LPCWSTR], w.HANDLE),
            ("RemovePropW", [w.HWND, w.LPCWSTR], w.HANDLE),
            ("SetForegroundWindow", [w.HWND], w.BOOL),
            ("GetForegroundWindow", [], w.HWND),
            ("SetFocus", [w.HWND], w.HWND),
            ("GetFocus", [], w.HWND),
            ("DestroyWindow", [w.HWND], w.BOOL),
            ("SetWindowTextW", [w.HWND, w.LPCWSTR], w.BOOL),
            ("SetWindowPos", [w.HWND, w.HWND] + [ctypes.c_int] * 4 + [w.UINT], w.BOOL),
            ("GetWindowTextW", [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            ("PeekMessageW", [w.LPVOID, w.HWND, w.UINT, w.UINT, w.UINT], w.BOOL),
            ("TranslateMessage", [w.LPVOID], w.BOOL),
            ("DispatchMessageW", [w.LPVOID], ctypes.c_ssize_t),
            (
                "MsgWaitForMultipleObjectsEx",
                [w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.DWORD],
                w.DWORD,
            ),
        ):
            function = getattr(self.user, name)
            function.argtypes = args
            function.restype = result
        self.callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM
        )
        self.callback = self.callback_type(self.wndproc)

        class WindowClass(ctypes.Structure):
            _fields_ = [
                ("style", w.UINT),
                ("proc", self.callback_type),
                ("class_extra", ctypes.c_int),
                ("window_extra", ctypes.c_int),
                ("instance", w.HINSTANCE),
                ("icon", w.HANDLE),
                ("cursor", w.HANDLE),
                ("background", w.HANDLE),
                ("menu", w.LPCWSTR),
                ("name", w.LPCWSTR),
            ]

        self.user.RegisterClassW.argtypes = [w.LPVOID]
        self.user.RegisterClassW.restype = w.WORD
        self.user.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
        self.user.DefWindowProcW.restype = ctypes.c_ssize_t
        self.kernel = ctypes.WinDLL("kernel32")
        self.kernel.GetModuleHandleW.argtypes = [w.LPCWSTR]
        self.kernel.GetModuleHandleW.restype = w.HMODULE
        self.instance = self.kernel.GetModuleHandleW(None)
        wc = WindowClass(
            0,
            self.callback,
            0,
            0,
            self.instance,
            None,
            None,
            None,
            None,
            "AstraMutationFixture",
        )
        if not self.user.RegisterClassW(ctypes.byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.create()

    def create(self):
        self.ready = False
        self.hwnd = int(
            self.user.CreateWindowExW(
                0x40000,  # WS_EX_APPWINDOW: this owned fixture has a taskbar entry.
                "AstraMutationFixture",
                f"Astra mutation fixture {os.getpid()}",
                0x80C00000,
                100,
                100,
                400,
                280,
                None,
                None,
                self.instance,
                None,
            )
        )
        if not self.hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self.receiver = GuardedWin32Receiver(self.hwnd, lambda: self.count)
        self.handles = {}
        for cid in (101, 201, 203, 204, 301, 302):
            self.add(cid)
        self._handoff_property_name = (
            f"AstraHandoff:{os.getpid()}:{uuid.uuid4().hex}"
        )
        self._handoff_root_marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        self._handoff_control_markers = {}
        if not self.user.SetPropW(
            self.hwnd,
            self._handoff_property_name,
            self._handoff_root_marker,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        for cid, hwnd in self.handles.items():
            marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
            if not self.user.SetPropW(hwnd, self._handoff_property_name, marker):
                raise ctypes.WinError(ctypes.get_last_error())
            self._handoff_control_markers[str(cid)] = marker
        self.ready = True
        self.user.ShowWindow(self.hwnd, 4)

    def add(self, cid):
        cls = "EDIT" if cid == 101 else "BUTTON" if cid in (201, 203, 204) else "STATIC"
        title = (
            ""
            if cid == 101
            else "Action"
            if cid == 201
            else "Duplicate"
            if cid in (203, 204)
            else str(self.count)
            if cid == 301
            else "ready"
        )
        index = (101, 201, 203, 204, 301, 302).index(cid)
        hwnd = self.user.CreateWindowExW(
            0,
            cls,
            title,
            0x50010000,
            15,
            15 + index * 32,
            250,
            25,
            self.hwnd,
            cid,
            None,
            None,
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        self.handles[cid] = int(hwnd)
        self.receiver.register_control(int(hwnd))

    def wndproc(self, hwnd, msg, wp, lp):
        if msg in (0x6, 0x1C):  # WM_ACTIVATE / WM_ACTIVATEAPP; observation only.
            self.activation_events.append(
                {
                    "time_monotonic": time.monotonic(),
                    "message": msg,
                    "window_hwnd": int(hwnd),
                    "state": int(wp),
                    "other": int(lp),
                    "foreground_hwnd": int(self.user.GetForegroundWindow() or 0),
                    "physical_count": self.count,
                }
            )
            del self.activation_events[:-128]
        if msg == 0x111 and self.ready:
            cid = wp & 0xFFFF
            notification = (wp >> 16) & 0xFFFF
            if (cid in (201, 203, 204) and notification == 0) or (
                cid == 101 and notification == 0x300
            ):
                self.count += 1
                action = "click" if cid != 101 else "type_into"
                self.events.append(
                    {
                        "pid": os.getpid(),
                        "window_hwnd": int(hwnd),
                        "control_hwnd": int(lp),
                        "control_id": str(cid),
                        "window_cookie": self.receiver.cookie,
                        "control_cookie": self.receiver.controls[str(cid)]["cookie"],
                        "action": action,
                    }
                )
                self.user.SetWindowTextW(self.handles[301], str(self.count))
                self.user.SetWindowTextW(
                    self.handles[302],
                    f"clicked:{cid}" if action == "click" else "typed:101",
                )
                return 0
        return self.user.DefWindowProcW(hwnd, msg, wp, lp)

    def text(self, cid):
        buffer = ctypes.create_unicode_buffer(4097)
        self.user.GetWindowTextW(self.handles[cid], buffer, len(buffer))
        return buffer.value

    def _set_edit_mode(self, *, readonly=False, password=False):
        """Change only the owned fixture edit style; never used for recovery."""
        hwnd = self.handles[101]
        style = int(self.user.GetWindowLongPtrW(hwnd, -16)) & 0xFFFFFFFF
        style = (style | 0x0800) if readonly else (style & ~0x0800)
        style = (style | 0x0020) if password else (style & ~0x0020)
        self.user.SetWindowLongPtrW(hwnd, -16, ctypes.c_ssize_t(style))
        # Tell USER32/UIA about the live style without changing focus.
        self.user.SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020,
        )

    def state(self):
        return {
            "count": self.count,
            "events": list(self.events),
            "activation_events": list(self.activation_events),
            "text": self.text(101),
            "foreground": int(self.user.GetForegroundWindow() or 0),
            "focus": int(self.user.GetFocus() or 0),
            "snapshot": self.receiver.snapshot(),
        }

    def _clear_handoff_properties(self):
        name = getattr(self, "_handoff_property_name", None)
        if not name:
            return
        try:
            handles = [
                getattr(self, "hwnd", 0),
                *getattr(self, "handles", {}).values(),
            ]
            for hwnd in handles:
                if hwnd:
                    self.user.RemovePropW(hwnd, name)
        finally:
            self._handoff_property_name = None

    def _verified_identity(self, control_id=None):
        snapshot = self.receiver.snapshot()
        process = _process_identity(os.getpid())
        if (
            not process.get("alive")
            or snapshot.get("pid") != os.getpid()
            or snapshot.get("hwnd") != self.hwnd
            or snapshot.get("created_filetime")
            != process.get("created_filetime")
        ):
            raise RuntimeError("PROCESS_IDENTITY_UNKNOWN")
        top = _window_identity(
            self.user,
            self.hwnd,
            property_name=self._handoff_property_name,
            property_marker=self._handoff_root_marker,
        )
        control = None
        selected_control = None
        if control_id is not None:
            selected_control = snapshot.get("controls", {}).get(str(control_id))
            if not selected_control:
                raise RuntimeError("CONTROL_IDENTITY_UNKNOWN")
            control = _window_identity(
                self.user,
                selected_control.get("hwnd"),
                top_hwnd=self.hwnd,
                property_name=self._handoff_property_name,
                property_marker=self._handoff_control_markers.get(str(control_id)),
            )
        desktop = _desktop_identity(self.user, top.get("owner_thread_id"))
        if (
            not top.get("is_window")
            or top.get("owner_pid") != os.getpid()
            or top.get("owner_thread_id") == "UNKNOWN"
            or top.get("is_top_level") is not True
            or top.get("ancestor_hwnd") != self.hwnd
            or top.get("cookie_valid") is not True
            or control_id is not None
            and (
                not control
                or not control.get("is_window")
                or control.get("owner_pid") != os.getpid()
                or control.get("is_descendant") is not True
                or control.get("cookie_valid") is not True
            )
            or desktop.get("session_id") != process.get("session_id")
            or desktop.get("interactive") is not True
        ):
            raise RuntimeError("NATIVE_IDENTITY_UNKNOWN")
        result = {
            "pid": process["pid"],
            "created_filetime": process["created_filetime"],
            "session_id": process["session_id"],
            "hwnd": self.hwnd,
            "top_owner_pid": top["owner_pid"],
            "top_owner_thread_id": top["owner_thread_id"],
            "top_ancestor_hwnd": top["ancestor_hwnd"],
            "top_is_top_level": top["is_top_level"],
            "window_cookie": snapshot.get("window_cookie"),
            "window_property_name": self._handoff_property_name,
            "window_property_marker": int(self._handoff_root_marker),
            "desktop": desktop,
            "channel_token": self.channel_token,
        }
        if selected_control is not None:
            result.update(
                {
                    "control_id": str(control_id),
                    "control_hwnd": int(selected_control["hwnd"]),
                    "control_cookie": selected_control.get("cookie"),
                    "control_owner_pid": control["owner_pid"],
                    "control_owner_thread_id": control["owner_thread_id"],
                    "control_property_marker": int(
                        self._handoff_control_markers[str(control_id)]
                    ),
                }
            )
        result["identity_digest"] = _identity_digest(result)
        return result

    def _install_foreground_test_double(self, config):
        double = getattr(self, "_foreground_test_double", None)
        if double is None:
            double = _ForegroundTestDouble(
                config,
                event_sink=self.foreground_event_sink,
            )
            self._foreground_test_double = double
            for api_name in _ForegroundTestDouble._APIS:
                setattr(
                    self.user,
                    api_name,
                    _ForegroundTestDoubleCall(double, api_name),
                )
        else:
            double.configure(config)
        return double.snapshot()

    def _foreground_test_double_state(self):
        double = getattr(self, "_foreground_test_double", None)
        return (
            double.snapshot()
            if double is not None
            else {"installed": False, "events": [], "call_counts": {}}
        )

    def command(self, name, args):
        if not hasattr(self, "_handoff_registry"):
            self._handoff_registry = {}
        if not hasattr(self, "_focus_handoffs"):
            self._focus_handoffs = set()
        if not hasattr(self, "_target_handoff_registry"):
            self._target_handoff_registry = {}
        if name == "install_foreground_test_double":
            return self._install_foreground_test_double(args or {})
        if name == "configure_foreground_test_double":
            double = getattr(self, "_foreground_test_double", None)
            if double is None:
                return {
                    "installed": False,
                    "failure": "FOREGROUND_TEST_DOUBLE_NOT_INSTALLED",
                }
            return double.configure(args or {})
        if name == "foreground_test_double_state":
            return self._foreground_test_double_state()
        if name == "snapshot":
            return self.receiver.snapshot()
        if name == "state":
            return self.state()
        if name == "verified_identity":
            try:
                return {
                    "identity": self._verified_identity(
                        args.get("control_id") if args else None
                    ),
                    "native_evidence": True,
                }
            except Exception as error:
                return {
                    "identity": None,
                    "native_evidence": False,
                    "failure": str(error),
                }
        if name == "register_verified_handoff":
            handoff_id = args.get("handoff_id")
            identity = args.get("target_identity")
            channel_token = args.get("target_channel_token")
            if not isinstance(handoff_id, str) or not handoff_id:
                return {
                    "registered": False,
                    "failure": "HANDOFF_ID_INVALID",
                }
            if (
                not isinstance(identity, dict)
                or channel_token != identity.get("channel_token")
            ):
                return {
                    "registered": False,
                    "failure": "TARGET_CHANNEL_BINDING_MISMATCH",
                    "handoff_id": handoff_id,
                }
            if handoff_id in self._handoff_registry:
                return {
                    "registered": False,
                    "failure": "DUPLICATE_HANDOFF",
                    "handoff_id": handoff_id,
                }
            valid, failure, observed = _validate_registered_identity(
                self.user,
                identity,
                own_pid=os.getpid(),
            )
            if not valid:
                return {
                    "registered": False,
                    "failure": failure,
                    "handoff_id": handoff_id,
                    "observed": observed,
                }
            digest = _identity_digest(identity)
            self._handoff_registry[handoff_id] = {
                "target_identity": dict(identity),
                "target_identity_digest": digest,
                "target_channel_token": channel_token,
                "grant_count": 0,
            }
            return {
                "registered": True,
                "handoff_id": handoff_id,
                "target_identity_digest": digest,
                "target_identity": dict(identity),
                "target_channel_token": channel_token,
            }
        if name == "prepare_verified_handoff":
            handoff_id = args.get("handoff_id")
            expected_digest = args.get("target_identity_digest")
            control_id = int(args.get("control_id", 201))
            if not isinstance(handoff_id, str) or not handoff_id:
                return {"bound": False, "failure": "HANDOFF_ID_INVALID"}
            if handoff_id in self._target_handoff_registry:
                return {"bound": False, "failure": "DUPLICATE_HANDOFF"}
            try:
                identity = self._verified_identity(control_id)
            except Exception as error:
                return {
                    "bound": False,
                    "failure": str(error),
                    "target_identity_digest": None,
                    "target_channel_token": self.channel_token,
                }
            if identity.get("identity_digest") != expected_digest:
                return {
                    "bound": False,
                    "failure": "TARGET_IDENTITY_MISMATCH",
                    "target_identity_digest": identity.get("identity_digest"),
                    "target_channel_token": self.channel_token,
                }
            self._target_handoff_registry[handoff_id] = {
                "target_identity_digest": identity["identity_digest"],
                "target_channel_token": self.channel_token,
            }
            return {
                "bound": True,
                "handoff_id": handoff_id,
                "target_identity_digest": identity["identity_digest"],
                "target_channel_token": self.channel_token,
            }
        if name == "dispatch":
            return self.receiver.dispatch(args)
        if name == "focus":
            self.user.ShowWindow(self.hwnd, 1)
            timeline = [
                _foreground_timing_snapshot(
                    self.user,
                    "helper_set_foreground_window_before",
                )
            ]
            ctypes.set_last_error(0)
            acquired_raw = self.user.SetForegroundWindow(self.hwnd)
            focus_error = ctypes.get_last_error() if not acquired_raw else None
            result_event = dict(timeline[0])
            result_event.update(
                event="helper_set_foreground_window_result",
                monotonic_timestamp=time.monotonic(),
                api_bool=bool(acquired_raw),
                last_error=focus_error,
            )
            result_event["observation_limitations"] = list(
                result_event["observation_limitations"]
            ) + ["foreground_fields_are_pre_call_observation"]
            timeline.append(result_event)
            self.user.SetFocus(self.handles[int(args.get("control_id", 201))])
            state = self.state()
            final_event = _foreground_timing_snapshot(
                self.user,
                "helper_set_focus_final",
            )
            final_event["focus_hwnd"] = int(state["focus"] or 0)
            timeline.append(final_event)
            state["foreground_request_accepted"] = bool(acquired_raw)
            state["foreground_timeline"] = timeline
            return state
        if name == "focus_from_verified_guardian":
            control_id = int(args.get("control_id", 201))
            handoff_id = args.get("handoff_id")
            expected_digest = args.get("target_identity_digest")
            expected_channel_token = args.get("target_channel_token")
            if not isinstance(handoff_id, str) or not handoff_id:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "HANDOFF_ID_INVALID",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                }
            try:
                identity = self._verified_identity(control_id)
            except Exception as error:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": (
                        "DESKTOP_IDENTITY_UNKNOWN"
                        if "DESKTOP" in str(error)
                        else "TARGET_IDENTITY_MISMATCH"
                    ),
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                    "identity_error": str(error),
                }
            if expected_digest != identity.get("identity_digest"):
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_IDENTITY_MISMATCH",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                }
            binding = self._target_handoff_registry.get(handoff_id)
            if (
                not isinstance(binding, dict)
                or binding.get("target_identity_digest") != expected_digest
                or binding.get("target_channel_token") != self.channel_token
                or expected_channel_token != self.channel_token
            ):
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "HANDOFF_NOT_REGISTERED",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                }
            control_hwnd = int(identity["control_hwnd"])

            # SW_SHOWNOACTIVATE keeps this opt-in path from adding a second
            # foreground-changing request before SetForegroundWindow.
            try:
                current = self._verified_identity(control_id)
            except Exception as error:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_IDENTITY_CHANGED",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                    "identity_error": str(error),
                }
            if current.get("identity_digest") != expected_digest:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_IDENTITY_CHANGED",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                }
            if handoff_id in self._focus_handoffs:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "DUPLICATE_FOCUS_REQUEST",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": [],
                    "count": self.count,
                    "events": list(self.events),
                }
            self._focus_handoffs.add(handoff_id)
            self.user.ShowWindow(self.hwnd, 4)
            timeline = [
                _foreground_timing_snapshot(
                    self.user,
                    "verified_target_set_foreground_window_before",
                )
            ]
            ctypes.set_last_error(0)
            acquired_raw = self.user.SetForegroundWindow(self.hwnd)
            foreground_error = ctypes.get_last_error() if not acquired_raw else None
            result_event = dict(timeline[0])
            result_event.update(
                event="verified_target_set_foreground_window_result",
                monotonic_timestamp=time.monotonic(),
                api_bool=bool(acquired_raw),
                last_error=foreground_error,
            )
            result_event["observation_limitations"] = list(
                result_event["observation_limitations"]
            ) + ["foreground_fields_are_pre_call_observation"]
            timeline.append(result_event)

            if not acquired_raw:
                state = self.state()
                final_event = _foreground_timing_snapshot(
                    self.user,
                    "verified_target_set_foreground_window_final",
                )
                final_event["focus_hwnd"] = int(state.get("focus") or 0)
                timeline.append(final_event)
                return {
                    **state,
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_FOREGROUND_REJECTED",
                    "foreground_request_accepted": False,
                    "focus_attempted": False,
                    "foreground_timeline": timeline,
                    "foreground_error": foreground_error,
                }

            try:
                current = self._verified_identity(control_id)
            except Exception as error:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_IDENTITY_CHANGED",
                    "foreground_request_accepted": True,
                    "focus_attempted": False,
                    "foreground_timeline": timeline,
                    "count": self.count,
                    "events": list(self.events),
                    "identity_error": str(error),
                }
            if current.get("identity_digest") != expected_digest:
                return {
                    "state": "S4_TARGET_FOCUS_RESULT",
                    "failure": "TARGET_IDENTITY_CHANGED",
                    "foreground_request_accepted": True,
                    "focus_attempted": False,
                    "foreground_timeline": timeline,
                    "count": self.count,
                    "events": list(self.events),
                }
            ctypes.set_last_error(0)
            focus_raw = self.user.SetFocus(control_hwnd)
            focus_error = ctypes.get_last_error() if not focus_raw else None
            focus_event = dict(timeline[-1])
            focus_event.update(
                event="verified_target_set_focus_result",
                monotonic_timestamp=time.monotonic(),
                api_bool=bool(focus_raw),
                last_error=focus_error,
                focus_hwnd=control_hwnd,
            )
            timeline.append(focus_event)
            state = self.state()
            final_event = _foreground_timing_snapshot(
                self.user,
                "verified_target_focus_final",
            )
            final_event["focus_hwnd"] = int(state.get("focus") or 0)
            timeline.append(final_event)
            focus_failure = None
            if not focus_raw:
                focus_failure = "TARGET_FOCUS_REJECTED"
            elif state.get("foreground") != self.hwnd:
                focus_failure = "TARGET_FOREGROUND_MISMATCH"
            elif state.get("focus") != control_hwnd:
                focus_failure = "TARGET_FOCUS_REJECTED"
            return {
                **state,
                "state": "S4_TARGET_FOCUS_RESULT",
                "failure": focus_failure,
                "foreground_request_accepted": True,
                "focus_attempted": True,
                "focus_request_accepted": focus_failure is None,
                "focus_return": int(focus_raw or 0),
                "focus_error": focus_error,
                "foreground_timeline": timeline,
            }
        if name == "grant_foreground_verified":
            handoff_id = args.get("handoff_id")
            expected_guardian_pid = args.get("guardian_pid")
            expected_guardian_hwnd = args.get("guardian_hwnd")
            expected_session = args.get("guardian_session_id", "UNKNOWN")
            registered = self._handoff_registry.get(handoff_id)
            if not registered:
                return {
                    "state": "S3_GRANT_RESULT",
                    "failure": "HANDOFF_NOT_REGISTERED",
                    "grant_attempted": False,
                    "granted": None,
                    "requested_pid": None,
                    "native_bool": None,
                    "immediate_last_error": None,
                    "last_error": None,
                    "last_error_capture": "not_attempted",
                    "grant_call_count": 0,
                    "guardian_identity": {},
                    "target_identity": {},
                    "ordering": [],
                    "timeline": [],
                }
            if registered["grant_count"]:
                return {
                    "state": "S3_GRANT_RESULT",
                    "failure": "DUPLICATE_GRANT",
                    "grant_attempted": False,
                    "granted": None,
                    "requested_pid": None,
                    "native_bool": None,
                    "immediate_last_error": None,
                    "last_error": None,
                    "last_error_capture": "not_attempted",
                    "grant_call_count": 0,
                    "guardian_identity": {},
                    "target_identity": {},
                    "ordering": [],
                    "timeline": [],
                }
            target_identity = registered["target_identity"]
            target_pid = target_identity.get("pid")
            if not _valid_pid(target_pid, own_pid=os.getpid()):
                return {
                    "state": "S3_GRANT_RESULT",
                    "failure": "INVALID_TARGET_PID",
                    "grant_attempted": False,
                    "granted": None,
                    "requested_pid": None,
                    "native_bool": None,
                    "immediate_last_error": None,
                    "last_error": None,
                    "last_error_capture": "not_attempted",
                    "grant_call_count": 0,
                    "guardian_identity": {},
                    "target_identity": {},
                    "ordering": [],
                    "timeline": [],
                }
            if (
                expected_guardian_pid != os.getpid()
                or expected_guardian_hwnd != self.hwnd
                or expected_session == "UNKNOWN"
            ):
                expected_guardian_pid = None
            else:
                expected_guardian_pid = int(expected_guardian_pid)
            pre_snapshot = _foreground_timing_snapshot(
                self.user,
                "verified_guardian_grant_before",
            )
            actual_session = _process_session_id(os.getpid())
            target_valid, target_failure, target_observed = (
                _validate_registered_identity(
                    self.user,
                    target_identity,
                    own_pid=os.getpid(),
                )
            )
            # Re-read guardian ownership after all target checks and directly
            # before the single AllowSetForegroundWindow call.
            identity = _foreground_identity(self.user)
            guardian_process = _process_identity(os.getpid())
            guardian_desktop = _desktop_identity(
                self.user,
                identity.get("thread_id"),
                session_id=actual_session,
            )
            identity["created_filetime"] = guardian_process.get(
                "created_filetime", "UNKNOWN"
            )
            identity["desktop"] = guardian_desktop
            identity["channel_token"] = getattr(
                self, "channel_token", "legacy-application"
            )
            guardian_basic = bool(
                expected_guardian_pid == os.getpid()
                and expected_guardian_hwnd == self.hwnd
                and expected_session != "UNKNOWN"
                and actual_session == expected_session
                and identity["hwnd"] == self.hwnd
                and identity["pid"] == os.getpid()
                and identity["session_id"] == expected_session
                and identity["is_window"]
                and guardian_process.get("alive")
            )
            desktop_matches = bool(
                guardian_desktop.get("interactive") is True
                and _desktop_matches(
                    target_identity.get("desktop"), guardian_desktop
                )
            )
            identity_matches = bool(
                guardian_basic
                and desktop_matches
                and target_valid
                and _valid_pid(target_pid, own_pid=os.getpid())
            )
            if not identity_matches:
                result_event = dict(pre_snapshot)
                result_event.update(
                    event="verified_guardian_ownership_changed",
                    monotonic_timestamp=time.monotonic(),
                    api_bool=None,
                    last_error=None,
                )
                result_event["observation_limitations"] = list(
                    result_event.get("observation_limitations", [])
                ) + ["grant_not_attempted"]
                return {
                    "state": "S3_GRANT_RESULT",
                    "failure": (
                        "GUARDIAN_OWNERSHIP_CHANGED"
                        if not guardian_basic
                        else "DESKTOP_IDENTITY_UNKNOWN"
                        if not desktop_matches
                        else target_failure or "TARGET_IDENTITY_MISMATCH"
                    ),
                    "grant_attempted": False,
                    "granted": None,
                    "requested_pid": None,
                    "native_bool": None,
                    "immediate_last_error": None,
                    "last_error": None,
                    "last_error_capture": "not_attempted",
                    "guardian_identity": identity,
                    "target_identity": target_observed,
                    "grant_call_count": 0,
                    "ordering": ["guardian_identity_reverified"],
                    "timeline": [pre_snapshot, result_event],
                }
            registered["grant_count"] = 1
            grant = _grant_foreground(
                self.user,
                target_pid,
                event_prefix="verified_guardian_allow_set_foreground_window",
                pre_snapshot=pre_snapshot,
                own_pid=os.getpid(),
            )
            return {
                **grant,
                "state": "S3_GRANT_RESULT",
                "failure": None if grant["granted"] else "GRANT_REJECTED",
                "grant_attempted": True,
                "requested_pid": target_pid,
                "guardian_identity": identity,
                "target_identity": target_identity,
                "grant_call_count": 1,
                "ordering": [
                    "guardian_identity_reverified",
                    "target_identity_verified",
                    "foreground_identity_reverified",
                    "grant_call",
                    "last_error_captured"
                    if not grant["granted"]
                    else "grant_returned",
                ],
            }
        if name == "grant_foreground":
            target_identity = args.get("target_identity")
            target_pid = args.get("pid")
            if not _valid_pid(target_pid, own_pid=os.getpid()):
                return {
                    "granted": False,
                    "native_bool": None,
                    "last_error": None,
                    "immediate_last_error": None,
                    "last_error_capture": "not_attempted",
                    "requested_pid": None,
                    "grant_attempted": False,
                    "grant_call_count": 0,
                    "failure": "INVALID_TARGET_PID",
                    "timeline": [],
                }
            if (
                not isinstance(target_identity, dict)
                or target_identity.get("pid") != target_pid
            ):
                return {
                    "granted": False,
                    "native_bool": None,
                    "last_error": None,
                    "immediate_last_error": None,
                    "last_error_capture": "not_attempted",
                    "requested_pid": None,
                    "grant_attempted": False,
                    "grant_call_count": 0,
                    "failure": "LEGACY_TARGET_IDENTITY_REQUIRED",
                    "timeline": [],
                }
            valid, failure, observed = _validate_registered_identity(
                self.user,
                target_identity,
                own_pid=os.getpid(),
            )
            if not valid:
                return {
                    "granted": False,
                    "native_bool": None,
                    "last_error": None,
                    "immediate_last_error": None,
                    "last_error_capture": "not_attempted",
                    "requested_pid": None,
                    "grant_attempted": False,
                    "grant_call_count": 0,
                    "failure": failure or "LEGACY_TARGET_IDENTITY_MISMATCH",
                    "observed": observed,
                    "timeline": [],
                }
            return _grant_foreground(
                self.user,
                target_pid,
                event_prefix="helper_allow_set_foreground_window",
                own_pid=os.getpid(),
            )
        if name == "title":
            self.user.SetWindowTextW(self.hwnd, args["title"])
            return self.state()
        if name == "reset":
            # Setup before the measured action interval; never action recovery.
            self.ready = False
            self.count = 0
            self.events.clear()
            self._set_edit_mode()
            self.user.SetWindowTextW(self.handles[101], "")
            self.user.SetWindowTextW(self.handles[301], "0")
            self.user.SetWindowTextW(self.handles[302], "ready")
            self.ready = True
            return self.state()
        if name == "edit_mode":
            self._set_edit_mode(
                readonly=bool(args.get("readonly", False)),
                password=bool(args.get("password", False)),
            )
            return self.state()
        if name == "show_front":
            # Test setup only: expose our own window without foreground activation.
            self.user.ShowWindow(self.hwnd, 4)  # SW_SHOWNOACTIVATE
            if not self.user.SetWindowPos(self.hwnd, -1, 0, 0, 0, 0, 0x0013):
                raise ctypes.WinError(ctypes.get_last_error())
            return self.state()
        if name == "replace":
            cid = int(args.get("control_id", 201))
            old_hwnd = self.handles[cid]
            self.user.RemovePropW(old_hwnd, self._handoff_property_name)
            self.receiver.unregister_control(str(cid))
            self.user.DestroyWindow(old_hwnd)
            self.add(cid)
            marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
            if not self.user.SetPropW(
                self.handles[cid], self._handoff_property_name, marker
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            self._handoff_control_markers[str(cid)] = marker
            return self.state()
        if name == "recreate":
            self.ready = False
            self._clear_handoff_properties()
            self.user.DestroyWindow(self.hwnd)
            self.create()
            return self.state()
        raise ValueError("Unknown fixture command")


def run(connection, foreground_event_sink=None, channel_token=None):
    app = None
    try:
        app = Application(
            foreground_event_sink=foreground_event_sink,
            channel_token=channel_token,
        )
        connection.send_bytes(
            json.dumps(
                {
                    "ready": True,
                    "pid": os.getpid(),
                    "hwnd": app.hwnd,
                    "channel_token": app.channel_token,
                }
            ).encode()
        )
        msg = w.MSG()
        while True:
            while app.user.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                app.user.TranslateMessage(ctypes.byref(msg))
                app.user.DispatchMessageW(ctypes.byref(msg))
            if not connection.poll(0):
                # Respond promptly to synchronous UIA/MSAA messages while waiting
                # for controller IPC. The wait never dispatches an action itself.
                app.user.MsgWaitForMultipleObjectsEx(0, None, 10, 0x04FF, 0x0004)
                continue
            request = json.loads(connection.recv_bytes(2 * 1024 * 1024))
            if request["command"] == "close":
                break
            try:
                result = app.command(request["command"], request.get("args", {}))
                connection.send_bytes(json.dumps({"result": result}).encode())
            except Exception as error:
                connection.send_bytes(
                    json.dumps(
                        {"error": type(error).__name__ + ": " + str(error)}
                    ).encode()
                )
    finally:
        if app:
            app.ready = False
            app._clear_handoff_properties()
            app.user.DestroyWindow(app.hwnd)
        connection.close()
        if foreground_event_sink is not None:
            foreground_event_sink.close()


class FixtureProcess:
    guardian = None
    prewarmed_observer = None
    live = []

    def __init__(self):
        context = multiprocessing.get_context("spawn")
        self._channel_token = uuid.uuid4().hex
        self.connection, child = context.Pipe()
        self._event_connection, event_child = context.Pipe(duplex=False)
        self.process = context.Process(
            target=run,
            args=(child, event_child, self._channel_token),
        )
        try:
            self.process.start()
        except Exception:
            try:
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(3)
                    if self.process.is_alive():
                        kill = getattr(self.process, "kill", None)
                        if callable(kill):
                            kill()
                            self.process.join(3)
            finally:
                self.connection.close()
                self._event_connection.close()
            raise
        finally:
            child.close()
            event_child.close()
        try:
            if not self.connection.poll(15):
                raise RuntimeError("Fixture startup deadline")
            ready = json.loads(self.connection.recv_bytes())
            self.pid = int(ready["pid"])
            self.hwnd = int(ready["hwnd"])
            if ready.get("channel_token") != self._channel_token:
                raise RuntimeError("Fixture channel binding mismatch")
        except Exception:
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(3)
                if self.process.is_alive():
                    kill = getattr(self.process, "kill", None)
                    if callable(kill):
                        kill()
                        self.process.join(3)
            self.connection.close()
            self._event_connection.close()
            raise
        self._lock = threading.RLock()
        self._close_lock = threading.RLock()
        self.before_dispatch = None
        self.lose_ack = False
        self._skip_foreground_restore = False
        self._handoff_cleanup_required = False
        self._foreground_restore_attempted = False
        self._foreground_events = []
        self._cleanup_errors = []
        self.live.append(self)

    def rpc(self, command, args=None):
        with self._lock:
            self.connection.send_bytes(
                json.dumps({"command": command, "args": args or {}}).encode()
            )
            if not self.connection.poll(10):
                raise TimeoutError("Fixture request deadline")
            response = json.loads(self.connection.recv_bytes(2 * 1024 * 1024))
            if "error" in response:
                raise RuntimeError(response["error"])
            return response["result"]

    def _drain_foreground_events(self):
        connection = getattr(self, "_event_connection", None)
        if connection is None:
            return []
        events = []
        while True:
            try:
                if not connection.poll(0):
                    break
                events.append(json.loads(connection.recv_bytes(2 * 1024 * 1024)))
            except (EOFError, OSError, ValueError, json.JSONDecodeError):
                break
        self._foreground_events.extend(events)
        return events

    @property
    def foreground_events(self):
        self._drain_foreground_events()
        return list(getattr(self, "_foreground_events", []))

    def snapshot(self):
        return self.rpc("snapshot")

    def state(self):
        return self.rpc("state")

    def dispatch(self, request):
        if self.before_dispatch:
            self.before_dispatch()
        result = self.rpc("dispatch", request)
        if self.lose_ack:
            raise OSError("Controlled acknowledgement loss")
        return result

    def focus(self, cid=201):
        user = ctypes.WinDLL("user32", use_last_error=True)
        runner_grant = _grant_foreground(
            user,
            self.pid,
            event_prefix="runner_allow_set_foreground_window",
        )
        granted = runner_grant["granted"]
        user.GetForegroundWindow.restype = w.HWND
        foreground = int(user.GetForegroundWindow() or 0)
        delegated_grant = None
        grant_source_pid = os.getpid()
        for source in self.live:
            if (
                source is not self
                and source.hwnd == foreground
                and source.process.is_alive()
            ):
                identity_response = self.rpc(
                    "verified_identity",
                    {"control_id": int(cid)},
                )
                if (
                    not isinstance(identity_response, dict)
                    or identity_response.get("native_evidence") is not True
                    or not isinstance(identity_response.get("identity"), dict)
                ):
                    raise RuntimeError("LEGACY_TARGET_IDENTITY_UNKNOWN")
                delegated_grant = source.rpc(
                    "grant_foreground",
                    {
                        "pid": self.pid,
                        "target_identity": identity_response["identity"],
                    },
                )
                granted = delegated_grant["granted"]
                grant_source_pid = source.pid
                break
        state = self.rpc("focus", {"control_id": cid})
        diagnostics = _foreground_context(user, self.pid, foreground, self.live)
        diagnostics.update(
            runner_grant=runner_grant,
            delegated_grant=delegated_grant,
            grant_source_pid=grant_source_pid,
            timeline=(
                runner_grant["timeline"]
                + (delegated_grant or {}).get("timeline", [])
                + state.get("foreground_timeline", [])
            ),
        )
        state["scoped_foreground_grant"] = granted
        state["foreground_grant_diagnostics"] = diagnostics
        assert state["foreground"] == self.hwnd, (
            f"Test-owned fixture foreground setup failed: {state}"
        )
        assert state["focus"] == state["snapshot"]["controls"][str(cid)]["hwnd"]
        return state

    def focus_from_verified_guardian(
        self,
        guardian,
        control_id=201,
        observation_provider=None,
    ):
        """Opt-in test-owned handoff; identity and grant authority stay native."""
        self.guardian = guardian
        self._handoff_cleanup_required = True
        state_history = ["S0_FIXTURES_READY"]
        timeline = []
        result = {
            "state": "S0_FIXTURES_READY",
            "state_history": state_history,
            "success": False,
            "failure": None,
            "timeline": timeline,
            "scoped_foreground_grant": False,
            "foreground_request_accepted": False,
            "mutation_counts": {"guardian": 0, "target": 0},
            "dispatch_count": 0,
            "retry_count": 0,
            "authorization": False,
            "mutation_intent": None,
            "agent_tool_calls": 0,
            "mutation_intent_created": False,
            "unknown_outcome_created": False,
            "cleanup_policy": "NO_FOREGROUND_RESTORE",
        }

        def stop(state, failure, **extra):
            result.update(state=state, failure=failure, **extra)
            result["timeline"] = timeline
            return result

        if not callable(observation_provider):
            return stop("S0_FIXTURES_READY", "OBSERVATION_PROVIDER_REQUIRED")
        if guardian is self:
            return stop("S0_FIXTURES_READY", "GUARDIAN_TARGET_NOT_DISTINCT")

        def observe(phase):
            try:
                observation = observation_provider(phase, guardian, self)
            except Exception as error:
                return None, stop(
                    state_history[-1],
                    "OBSERVATION_UNAVAILABLE",
                    observation_error=f"{type(error).__name__}: {error}",
                )
            if not isinstance(observation, dict):
                return None, stop(
                    state_history[-1],
                    "OBSERVATION_UNAVAILABLE",
                    observation_error="provider must return a mapping",
                )
            foreground = observation.get("foreground") or {}
            timeline.append(
                {
                    "event": phase,
                    "source_role": "runner_observer",
                    "authority": "diagnostic_only",
                    "process_pid": os.getpid(),
                    "process_thread_id": threading.get_native_id(),
                    "monotonic_timestamp": observation.get(
                        "monotonic_timestamp", time.monotonic()
                    ),
                    "foreground_hwnd": foreground.get("hwnd", "UNKNOWN"),
                    "foreground_pid": foreground.get("pid", "UNKNOWN"),
                    "foreground_session_id": foreground.get(
                        "session_id", "UNKNOWN"
                    ),
                    "foreground_is_window": foreground.get(
                        "is_window", "UNKNOWN"
                    ),
                    "foreground_thread_id": foreground.get(
                        "thread_id", "UNKNOWN"
                    ),
                    "last_input_tick": observation.get(
                        "last_input_tick", "UNKNOWN"
                    ),
                    "current_tick": observation.get("current_tick", "UNKNOWN"),
                    "foreground_lock_timeout": observation.get(
                        "foreground_lock_timeout", "UNKNOWN"
                    ),
                    "api_bool": None,
                    "last_error": None,
                    "observation_limitations": [
                        "cross_process_snapshot_not_atomic",
                        "last_input_recipient_not_observed",
                        "provider_values_are_non_authoritative",
                    ],
                }
            )
            return observation, None

        def identity_from(fixture, selected_control=None):
            response = fixture.rpc(
                "verified_identity",
                (
                    {"control_id": int(selected_control)}
                    if selected_control is not None
                    else {}
                ),
            )
            if (
                not isinstance(response, dict)
                or response.get("native_evidence") is not True
                or not isinstance(response.get("identity"), dict)
            ):
                raise RuntimeError(
                    response.get("failure", "NATIVE_IDENTITY_UNKNOWN")
                    if isinstance(response, dict)
                    else "NATIVE_IDENTITY_UNKNOWN"
                )
            return response["identity"]

        try:
            guardian_identity = identity_from(guardian)
            target_identity = identity_from(self, control_id)
            guardian_state = guardian.state()
            target_state = self.state()
        except Exception as error:
            return stop(
                "S0_FIXTURES_READY",
                "SETUP_INVALID",
                setup_error=f"{type(error).__name__}: {error}",
            )

        result["mutation_counts"] = {
            "guardian": int(guardian_state.get("count", 0)),
            "target": int(target_state.get("count", 0)),
        }
        result["dispatch_count"] = int(target_state.get("dispatch_count", 0))
        if (
            guardian_identity.get("pid") == target_identity.get("pid")
            or guardian_identity.get("hwnd") == target_identity.get("hwnd")
            or not _valid_pid(
                target_identity.get("pid"),
                own_pid=guardian_identity.get("pid"),
            )
            or not _valid_pid(guardian_identity.get("pid"))
            or guardian_identity.get("session_id")
            != target_identity.get("session_id")
            or result["mutation_counts"] != {"guardian": 0, "target": 0}
            or guardian_state.get("events")
            or target_state.get("events")
            or guardian_state.get("dispatch_count", 0)
            or target_state.get("dispatch_count", 0)
            or guardian_state.get("retry_count", 0)
            or target_state.get("retry_count", 0)
            or guardian_state.get("mutation_intent")
            or target_state.get("mutation_intent")
            or guardian_state.get("unknown_outcome_created", False)
            or target_state.get("unknown_outcome_created", False)
        ):
            return stop("S0_FIXTURES_READY", "SETUP_INVALID")

        fixtures, failure = observe("fixtures_ready")
        if failure:
            return failure

        handoff_id = uuid.uuid4().hex
        target_binding = None
        try:
            target_binding = self.rpc(
                "prepare_verified_handoff",
                {
                    "handoff_id": handoff_id,
                    "target_identity_digest": target_identity["identity_digest"],
                    "control_id": int(control_id),
                },
            )
        except Exception as error:
            return stop(
                "S0_FIXTURES_READY",
                "HANDOFF_REGISTRATION_FAILED",
                rpc_error=f"{type(error).__name__}: {error}",
            )
        if (
            not isinstance(target_binding, dict)
            or target_binding.get("bound") is not True
            or target_binding.get("target_identity_digest")
            != target_identity.get("identity_digest")
            or target_binding.get("target_channel_token")
            != target_identity.get("channel_token")
        ):
            return stop(
                "S0_FIXTURES_READY",
                target_binding.get("failure", "HANDOFF_REGISTRATION_FAILED")
                if isinstance(target_binding, dict)
                else "HANDOFF_REGISTRATION_FAILED",
            )
        try:
            registration = guardian.rpc(
                "register_verified_handoff",
                {
                    "handoff_id": handoff_id,
                    "target_identity": target_identity,
                    "target_channel_token": target_binding[
                        "target_channel_token"
                    ],
                },
            )
        except Exception as error:
            return stop(
                "S0_FIXTURES_READY",
                "HANDOFF_REGISTRATION_FAILED",
                rpc_error=f"{type(error).__name__}: {error}",
            )
        if (
            not isinstance(registration, dict)
            or registration.get("registered") is not True
            or registration.get("target_identity_digest")
            != target_identity.get("identity_digest")
        ):
            return stop(
                "S0_FIXTURES_READY",
                registration.get("failure", "HANDOFF_REGISTRATION_FAILED")
                if isinstance(registration, dict)
                else "HANDOFF_REGISTRATION_FAILED",
            )
        target_identity_digest = registration["target_identity_digest"]
        result["handoff_id"] = handoff_id
        result["target_identity_digest"] = target_identity_digest
        result["target_channel_token"] = target_binding["target_channel_token"]

        state_history.append("S1_AWAIT_USER_ACTIVATION")
        activated, failure = observe("await_user_activation")
        if failure:
            return failure
        if activated.get("activation_observed") is not True:
            return stop("S1_AWAIT_USER_ACTIVATION", "USER_ACTIVATION_NOT_OBSERVED")

        state_history.append("S2_GUARDIAN_VERIFIED")
        _, failure = observe("before_guardian_grant")
        if failure:
            return failure

        state_history.append("S3_GRANT_RESULT")
        try:
            grant = guardian.rpc(
                "grant_foreground_verified",
                {
                    "handoff_id": handoff_id,
                    "guardian_pid": guardian_identity["pid"],
                    "guardian_hwnd": guardian_identity["hwnd"],
                    "guardian_session_id": guardian_identity["session_id"],
                },
            )
        except Exception as error:
            return stop(
                "S3_GRANT_RESULT",
                "GRANT_RPC_FAILED",
                rpc_error=f"{type(error).__name__}: {error}",
            )
        if not isinstance(grant, dict):
            return stop("S3_GRANT_RESULT", "GRANT_EVIDENCE_INVALID")
        timeline.extend(grant.get("timeline", []))
        result["foreground_grant_diagnostics"] = {
            "runner_grant": None,
            "guardian_grant": grant,
            "timeline": timeline,
        }
        if grant.get("grant_attempted") is False:
            no_attempt_valid, no_attempt_failure = (
                _validate_no_attempt_grant_evidence(grant)
            )
            if not no_attempt_valid:
                return stop("S3_GRANT_RESULT", "GRANT_EVIDENCE_INVALID")
            return stop("S3_GRANT_RESULT", no_attempt_failure)
        if grant.get("native_bool") is False:
            rejected_valid, rejected_failure = _validate_grant_evidence(
                grant,
                target_identity,
                guardian_identity["pid"],
                guardian_identity["hwnd"],
                guardian_session_id=guardian_identity["session_id"],
                guardian_created_filetime=guardian_identity["created_filetime"],
                guardian_desktop=guardian_identity["desktop"],
                target_identity_digest=target_identity_digest,
                expect_success=False,
            )
            if not rejected_valid:
                return stop("S3_GRANT_RESULT", rejected_failure)
            return stop(
                "S3_GRANT_RESULT",
                "GRANT_REJECTED",
                scoped_foreground_grant=False,
            )
        evidence_ok, evidence_failure = _validate_grant_evidence(
            grant,
            target_identity,
            guardian_identity["pid"],
            guardian_identity["hwnd"],
            guardian_session_id=guardian_identity["session_id"],
            guardian_created_filetime=guardian_identity["created_filetime"],
            guardian_desktop=guardian_identity["desktop"],
            target_identity_digest=target_identity_digest,
        )
        if not evidence_ok:
            return stop("S3_GRANT_RESULT", evidence_failure)
        result["scoped_foreground_grant"] = True

        state_history.append("S4_TARGET_FOCUS_RESULT")
        try:
            focus = self.rpc(
                "focus_from_verified_guardian",
                {
                    "handoff_id": handoff_id,
                    "target_identity_digest": target_identity_digest,
                    "target_channel_token": target_binding[
                        "target_channel_token"
                    ],
                    "control_id": int(control_id),
                },
            )
        except Exception as error:
            return stop(
                "S4_TARGET_FOCUS_RESULT",
                "TARGET_FOCUS_RPC_FAILED",
                rpc_error=f"{type(error).__name__}: {error}",
            )
        if not isinstance(focus, dict):
            return stop("S4_TARGET_FOCUS_RESULT", "TARGET_FOCUS_EVIDENCE_INVALID")
        timeline.extend(focus.get("foreground_timeline", []))
        result["mutation_counts"]["target"] = int(focus.get("count", 0))
        result["dispatch_count"] = int(focus.get("dispatch_count", 0))
        if focus.get("failure") is not None:
            return stop("S4_TARGET_FOCUS_RESULT", focus["failure"])
        if focus.get("foreground_request_accepted") is not True:
            return stop("S4_TARGET_FOCUS_RESULT", "TARGET_FOREGROUND_REJECTED")
        if focus.get("focus_attempted") is not True:
            return stop("S4_TARGET_FOCUS_RESULT", "TARGET_FOCUS_REJECTED")

        state_history.append("S5_TARGET_VERIFIED")
        _, failure = observe("target_verified")
        if failure:
            return failure
        verified, verification_failure, verification_evidence = (
            _independent_target_verification(target_identity)
        )
        if not verified:
            return stop(
                "S5_TARGET_VERIFIED",
                verification_failure,
                verification_evidence=verification_evidence,
            )
        if (
            focus.get("foreground") != target_identity["hwnd"]
            or focus.get("focus") != target_identity["control_hwnd"]
            or focus.get("count", 0) != 0
            or focus.get("events")
            or focus.get("dispatch_count", 0)
            or focus.get("retry_count", 0)
            or focus.get("mutation_intent")
            or focus.get("unknown_outcome_created", False)
        ):
            return stop("S5_TARGET_VERIFIED", "TARGET_VERIFICATION_FAILED")

        state_history.append("S6_PROBE_COMPLETED")
        result.update(
            state="S6_PROBE_COMPLETED",
            success=True,
            foreground_request_accepted=True,
            final_target=target_identity,
            target_focus=target_identity["control_hwnd"],
            independent_verification=verification_evidence,
        )
        return result

    def _close_locked(self):
        if getattr(self, "_cleanup_complete", False):
            return
        cleanup_errors = []
        guardian = getattr(self, "guardian", None)
        try:
            if (
                guardian is not None
                and guardian is not self
                and guardian.process.is_alive()
                and self.process.is_alive()
                and not getattr(self, "_skip_foreground_restore", False)
                and not getattr(self, "_handoff_cleanup_required", False)
                and not getattr(self, "_foreground_restore_attempted", False)
            ):
                self._foreground_restore_attempted = True
                user = ctypes.WinDLL("user32")
                user.GetForegroundWindow.restype = w.HWND
                if user.GetForegroundWindow() == self.hwnd:
                    guardian_identity = guardian.rpc("verified_identity")
                    if (
                        not isinstance(guardian_identity, dict)
                        or guardian_identity.get("native_evidence") is not True
                        or not isinstance(guardian_identity.get("identity"), dict)
                    ):
                        raise RuntimeError("LEGACY_GUARDIAN_IDENTITY_UNKNOWN")
                    self.rpc(
                        "grant_foreground",
                        {
                            "pid": guardian.pid,
                            "target_identity": guardian_identity["identity"],
                        },
                    )
                    guardian.rpc("focus", {"control_id": 201})
        except Exception as error:
            cleanup_errors.append(error)

        try:
            if self.process.is_alive():
                if not getattr(self.connection, "closed", False):
                    try:
                        self.connection.send_bytes(b'{"command":"close"}')
                    except OSError:
                        pass
                self.process.join(3)
                if self.process.is_alive():
                    self.process.terminate()
                    self.process.join(3)
        except Exception as error:
            cleanup_errors.append(error)

        self._drain_foreground_events()
        try:
            self.connection.close()
        except Exception as error:
            cleanup_errors.append(error)
        event_connection = getattr(self, "_event_connection", None)
        if event_connection is not None:
            try:
                event_connection.close()
            except Exception as error:
                cleanup_errors.append(error)

        if self.process.is_alive():
            cleanup_errors.append(AssertionError("Fixture process leaked"))
        else:
            self._cleanup_complete = True
            if self in self.live:
                self.live.remove(self)
        self._cleanup_errors = cleanup_errors
        if cleanup_errors:
            raise cleanup_errors[0]

    def close(self):
        lock = getattr(self, "_close_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._close_lock = lock
        with lock:
            self._close_locked()

    def close_without_foreground_restore(self):
        """Opt-in cleanup for guardian handoff; never changes foreground state."""
        lock = getattr(self, "_close_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._close_lock = lock
        with lock:
            self._skip_foreground_restore = True
            self._close_locked()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if getattr(self, "_handoff_cleanup_required", False):
            self.close_without_foreground_restore()
        else:
            self.close()
