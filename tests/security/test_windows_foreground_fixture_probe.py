"""Non-mutating foreground probe for the test-owned Win32 fixture."""

import ctypes
import json
import os
from ctypes import wintypes as w

import pytest

from tests.security.windows_mutation_fixture import FixtureProcess


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Win32 fixture")


def _user32():
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.GetForegroundWindow.restype = w.HWND
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    user.IsWindow.argtypes = [w.HWND]
    user.IsWindow.restype = w.BOOL
    user.GetWindowTextLengthW.argtypes = [w.HWND]
    user.GetWindowTextLengthW.restype = ctypes.c_int
    user.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.GetWindowTextW.restype = ctypes.c_int
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.GetClassNameW.restype = ctypes.c_int
    return user


def _session_id(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ProcessIdToSessionId.argtypes = [w.DWORD, ctypes.POINTER(w.DWORD)]
    kernel.ProcessIdToSessionId.restype = w.BOOL
    session = w.DWORD()
    if not kernel.ProcessIdToSessionId(pid, ctypes.byref(session)):
        return None
    return int(session.value)


def _window_state(user, hwnd=None):
    hwnd = int(hwnd if hwnd is not None else user.GetForegroundWindow() or 0)
    pid = w.DWORD()
    user.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid))
    length = user.GetWindowTextLengthW(w.HWND(hwnd))
    title = ctypes.create_unicode_buffer(length + 1)
    user.GetWindowTextW(w.HWND(hwnd), title, len(title))
    class_name = ctypes.create_unicode_buffer(256)
    user.GetClassNameW(w.HWND(hwnd), class_name, len(class_name))
    return {
        "hwnd": hwnd,
        "pid": int(pid.value),
        "session_id": _session_id(int(pid.value)) if pid.value else None,
        "title": title.value,
        "class_name": class_name.value,
        "is_window": bool(user.IsWindow(w.HWND(hwnd))),
    }


def test_windows_foreground_fixture_probe():
    """Exercise only helper creation, focus establishment, verification, and close."""
    user = _user32()
    with FixtureProcess() as application:
        snapshot = application.snapshot()
        control_hwnd = int(snapshot["controls"]["201"]["hwnd"])
        pre = {
            "runner": {
                "pid": os.getpid(),
                "session_id": _session_id(os.getpid()),
            },
            "helper": {
                "pid": application.pid,
                "session_id": _session_id(application.pid),
                "top_hwnd": application.hwnd,
                "control_hwnd": control_hwnd,
                "top_is_window": bool(user.IsWindow(w.HWND(application.hwnd))),
                "control_is_window": bool(user.IsWindow(w.HWND(control_hwnd))),
                "alive": application.process.is_alive(),
            },
            "foreground": _window_state(user),
        }
        print("FOREGROUND_PROBE_PRE " + json.dumps(pre, sort_keys=True))

        # Reuse the fixture's one-shot focus path; no action/session is involved.
        state = application.focus(201)
        post_foreground = _window_state(user, state["foreground"])
        post = {
            "foreground_grant_diagnostics": state["foreground_grant_diagnostics"],
            "foreground_request_accepted": state["foreground_request_accepted"],
            "scoped_foreground_grant": state["scoped_foreground_grant"],
            "actual_foreground": post_foreground,
            "actual_focus_hwnd": state["focus"],
            "helper_alive": application.process.is_alive(),
            "top_is_window": bool(user.IsWindow(w.HWND(application.hwnd))),
            "control_is_window": bool(user.IsWindow(w.HWND(control_hwnd))),
        }
        print("FOREGROUND_PROBE_POST " + json.dumps(post, sort_keys=True))

        assert state["foreground"] == application.hwnd
        assert state["focus"] == control_hwnd
        assert state["foreground_request_accepted"] is True
        assert state["scoped_foreground_grant"] is True
        assert application.process.is_alive()
        assert user.IsWindow(w.HWND(application.hwnd))
        assert user.IsWindow(w.HWND(control_hwnd))
