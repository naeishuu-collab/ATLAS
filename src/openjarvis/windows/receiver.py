"""Compare-and-dispatch for explicitly bound Windows receivers.

The cooperative receiver runs inside a consenting application.  The native
adapter below is limited to one explicitly supplied process/window/control
binding and accepts no discovered HWND through a mutation request.
"""

from __future__ import annotations

import ctypes
import os
import uuid
from ctypes import wintypes as w

from openjarvis.windows.identity import IdentityError

_GWLP_STYLE = -16
_ES_PASSWORD = 0x0020
_ES_READONLY = 0x0800


class GuardedWin32Receiver:
    def __init__(self, hwnd: int, revision):
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetCurrentThreadId.restype = w.DWORD
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessTimes.argtypes = [w.HANDLE] + [w.LPVOID] * 4
        self.kernel.GetProcessTimes.restype = w.BOOL
        self.owner = self.kernel.GetCurrentThreadId()
        self.hwnd = hwnd
        self.pid = os.getpid()
        self.cookie = uuid.uuid4().hex
        self._property_name = "AstraLifetime:" + uuid.uuid4().hex
        self._root_marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        self._markers = {}
        self.revision = revision
        self.controls = {}
        for name, args, result in (
            ("GetWindowThreadProcessId", [w.HWND, w.LPVOID], w.DWORD),
            ("GetClassNameW", [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int),
            ("GetDlgCtrlID", [w.HWND], ctypes.c_int),
            ("IsChild", [w.HWND, w.HWND], w.BOOL),
            ("IsWindowVisible", [w.HWND], w.BOOL),
            ("IsWindowEnabled", [w.HWND], w.BOOL),
            ("GetForegroundWindow", [], w.HWND),
            ("GetFocus", [], w.HWND),
            ("GetWindowLongPtrW", [w.HWND, ctypes.c_int], ctypes.c_ssize_t),
            ("SetPropW", [w.HWND, w.LPCWSTR, w.HANDLE], w.BOOL),
            ("GetPropW", [w.HWND, w.LPCWSTR], w.HANDLE),
            ("RemovePropW", [w.HWND, w.LPCWSTR], w.HANDLE),
            ("GetWindowRect", [w.HWND, w.LPVOID], w.BOOL),
            ("MonitorFromRect", [w.LPVOID, w.DWORD], w.HANDLE),
            ("SendMessageW", [w.HWND, w.UINT, w.WPARAM, w.LPARAM], ctypes.c_ssize_t),
        ):
            function = getattr(self.user, name)
            function.argtypes, function.restype = args, result
        times = [w.FILETIME() for _ in range(4)]
        if not self.kernel.GetProcessTimes(
            self.kernel.GetCurrentProcess(), *(ctypes.byref(t) for t in times)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.created = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
        self.root_class = self._class(hwnd)
        if not self._belongs(hwnd):
            raise IdentityError("Receiver window owner mismatch")
        if not self.user.SetPropW(hwnd, self._property_name, self._root_marker):
            raise ctypes.WinError(ctypes.get_last_error())

    def _owned(self):
        if self.kernel.GetCurrentThreadId() != self.owner:
            raise IdentityError("Receiver must run on its GUI owner thread")

    def _class(self, hwnd):
        buffer = ctypes.create_unicode_buffer(256)
        if not self.user.GetClassNameW(hwnd, buffer, len(buffer)):
            raise IdentityError("Stale native window")
        return buffer.value

    def _belongs(self, hwnd):
        pid = w.DWORD()
        thread = self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return thread == self.owner and pid.value == self.pid

    def _style(self, hwnd):
        # Only the low 32 bits contain the Win32 style flags on both 32- and
        # 64-bit processes.  Reading this on the owner thread closes a late
        # readonly/password capability change before WM_SETTEXT is sent.
        return int(self.user.GetWindowLongPtrW(hwnd, _GWLP_STYLE)) & 0xFFFFFFFF

    def register_control(self, hwnd: int):
        self._owned()
        control_id = str(self.user.GetDlgCtrlID(hwnd))
        if (
            control_id in self.controls
            or not self._belongs(hwnd)
            or not self.user.IsChild(self.hwnd, hwnd)
        ):
            raise IdentityError("Invalid or duplicate receiver control registration")
        self.controls[control_id] = {
            "hwnd": hwnd,
            "cookie": uuid.uuid4().hex,
            "class_name": self._class(hwnd),
        }
        marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        if not self.user.SetPropW(hwnd, self._property_name, marker):
            self.controls.pop(control_id)
            raise ctypes.WinError(ctypes.get_last_error())
        self._markers[control_id] = marker

    def unregister_control(self, control_id: str):
        self._owned()
        control = self.controls.pop(control_id)
        self.user.RemovePropW(control["hwnd"], self._property_name)
        self._markers.pop(control_id)

    def snapshot(self):
        self._owned()
        if self.user.GetPropW(self.hwnd, self._property_name) != self._root_marker:
            raise IdentityError("Stale receiver window lifetime")
        return {
            "pid": self.pid,
            "created_filetime": self.created,
            "hwnd": self.hwnd,
            "window_cookie": self.cookie,
            "revision": self.revision(),
            "controls": {k: dict(v) for k, v in self.controls.items()},
        }

    def dispatch(self, request: dict):
        self._owned()

        def reject(code):
            return {"dispatched": False, "failure": code}

        window = request.get("window", {})
        process = window.get("process", {})
        if (
            process.get("pid") != self.pid
            or process.get("created_filetime") != self.created
        ):
            return reject("IDENTITY_MISMATCH")
        if (
            window.get("hwnd") != self.hwnd
            or window.get("thread_id") != self.owner
            or window.get("class_name") != self.root_class
            or request.get("window_cookie") != self.cookie
            or not self._belongs(self.hwnd)
            or self.user.GetPropW(self.hwnd, self._property_name) != self._root_marker
        ):
            return reject("STALE_TARGET")
        control_id = request.get("control_id")
        control = self.controls.get(control_id)
        if not control or request.get("control") != control:
            return reject("STALE_TARGET")
        hwnd = control["hwnd"]
        if (
            not self._belongs(hwnd)
            or not self.user.IsChild(self.hwnd, hwnd)
            or self._class(hwnd) != control["class_name"]
            or self.user.GetPropW(hwnd, self._property_name)
            != self._markers[control_id]
            or str(self.user.GetDlgCtrlID(hwnd)) != control_id
        ):
            return reject("IDENTITY_MISMATCH")
        if request.get("revision") != self.revision():
            return reject("STALE_TARGET")
        if self.user.GetForegroundWindow() != self.hwnd:
            return reject("WRONG_FOREGROUND")
        for target in (self.hwnd, hwnd):
            rectangle = w.RECT()
            if (
                not self.user.IsWindowVisible(target)
                or not self.user.IsWindowEnabled(target)
                or not self.user.GetWindowRect(target, ctypes.byref(rectangle))
                or not self.user.MonitorFromRect(ctypes.byref(rectangle), 0)
            ):
                return reject("PRECONDITION_FAILURE")
        action = request.get("action")
        if action == "click" and control["class_name"] == "Button":
            # No message pumping between the cookie/revision checks and this
            # direct synchronous same-GUI-thread dispatch to the registered child.
            self.user.SendMessageW(hwnd, 0x00F5, 0, 0)  # BM_CLICK, exactly once
        elif action == "type_into" and control["class_name"] == "Edit":
            live_style = self._style(hwnd)
            if live_style & (_ES_PASSWORD | _ES_READONLY):
                return reject("UNSUPPORTED_CONTROL")
            if self.user.GetFocus() != hwnd:
                return reject("FOCUS_FAILURE")
            value = request.get("value")
            if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                return reject("PRECONDITION_FAILURE")
            buffer = ctypes.create_unicode_buffer(value)
            self.user.SendMessageW(
                hwnd, 0x000C, 0, ctypes.addressof(buffer)
            )  # WM_SETTEXT once
        else:
            return reject("UNSUPPORTED_ACTION")
        return {"dispatched": True}


class NativeBoundWin32Receiver:
    """Dispatch one exact edit control in one explicitly bound process.

    This adapter is intentionally narrower than a generic Windows automation
    layer.  The caller supplies the already-owned root and child HWNDs plus
    the exact executable/class identities.  No window/control discovery or
    semantic fallback occurs here.  UIA observation remains the independent
    target resolver and post-dispatch verifier.
    """

    def __init__(
        self,
        *,
        hwnd: int,
        control_hwnd: int,
        executable: str,
        window_class: str,
        control_class: str = "Edit",
        timeout_ms: int = 5000,
    ):
        if (
            type(hwnd) is not int
            or type(control_hwnd) is not int
            or hwnd <= 0
            or control_hwnd <= 0
            or not executable
            or not window_class
            or control_class != "Edit"
            or not 100 <= timeout_ms <= 30_000
        ):
            raise IdentityError("Invalid native receiver binding")
        if os.name != "nt":
            raise IdentityError("Native Windows receiver is unavailable")
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._signature(
            self.user.GetWindowThreadProcessId,
            [w.HWND, w.LPVOID],
            w.DWORD,
        )
        self._signature(self.user.IsWindow, [w.HWND], w.BOOL)
        self._signature(self.user.IsChild, [w.HWND, w.HWND], w.BOOL)
        self._signature(self.user.GetDlgCtrlID, [w.HWND], ctypes.c_int)
        self._signature(
            self.user.GetClassNameW,
            [w.HWND, w.LPWSTR, ctypes.c_int],
            ctypes.c_int,
        )
        self._signature(self.user.GetForegroundWindow, [], w.HWND)
        self._signature(self.user.GetGUIThreadInfo, [w.DWORD, w.LPVOID], w.BOOL)
        self._signature(self.user.IsWindowVisible, [w.HWND], w.BOOL)
        self._signature(self.user.IsWindowEnabled, [w.HWND], w.BOOL)
        self._signature(
            self.user.GetWindowLongPtrW,
            [w.HWND, ctypes.c_int],
            ctypes.c_ssize_t,
        )
        self._signature(self.user.GetWindowRect, [w.HWND, w.LPVOID], w.BOOL)
        self._signature(self.user.MonitorFromRect, [w.LPVOID, w.DWORD], w.HANDLE)
        self._signature(
            self.user.SetPropW,
            [w.HWND, w.LPCWSTR, w.HANDLE],
            w.BOOL,
        )
        self._signature(self.user.GetPropW, [w.HWND, w.LPCWSTR], w.HANDLE)
        self._signature(self.user.RemovePropW, [w.HWND, w.LPCWSTR], w.HANDLE)
        self._signature(
            self.user.SendMessageTimeoutW,
            [w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT, w.LPVOID],
            w.LPARAM,
        )
        self._signature(
            self.kernel.OpenProcess,
            [w.DWORD, w.BOOL, w.DWORD],
            w.HANDLE,
        )
        self._signature(self.kernel.CloseHandle, [w.HANDLE], w.BOOL)
        self._signature(
            self.kernel.GetProcessTimes,
            [w.HANDLE] + [w.LPVOID] * 4,
            w.BOOL,
        )
        self._signature(
            self.kernel.QueryFullProcessImageNameW,
            [w.HANDLE, w.DWORD, w.LPWSTR, w.LPVOID],
            w.BOOL,
        )
        self.hwnd = hwnd
        self.control_hwnd = control_hwnd
        self.expected_executable = os.path.normcase(os.path.abspath(executable))
        self.expected_window_class = window_class
        self.expected_control_class = control_class
        self.timeout_ms = timeout_ms
        self._property_name = "AstraNativeLifetime:" + uuid.uuid4().hex
        self._window_marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        self._control_marker = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        self._closed = False
        self._revision = 0
        self._dispatch_count = 0
        self.pid, self.created, executable_path = self._window_process(hwnd)
        if executable_path != self.expected_executable:
            raise IdentityError(
                "Bound executable identity mismatch: "
                f"expected={self.expected_executable!r} actual={executable_path!r}"
            )
        self.thread_id = self._thread_for(hwnd)
        if self._class(hwnd) != self.expected_window_class:
            raise IdentityError("Bound window class mismatch")
        if (
            self._thread_for(control_hwnd) != self.thread_id
            or not self.user.IsChild(hwnd, control_hwnd)
            or self._class(control_hwnd) != self.expected_control_class
        ):
            raise IdentityError("Bound control hierarchy mismatch")
        self.control_id = str(int(self.user.GetDlgCtrlID(control_hwnd)))
        if not self.user.SetPropW(hwnd, self._property_name, self._window_marker):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.user.SetPropW(
            control_hwnd,
            self._property_name,
            self._control_marker,
        ):
            self.user.RemovePropW(hwnd, self._property_name)
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def _signature(function, arguments, result):
        function.argtypes, function.restype = arguments, result

    def _class(self, hwnd: int) -> str:
        buffer = ctypes.create_unicode_buffer(256)
        if not self.user.GetClassNameW(hwnd, buffer, len(buffer)):
            raise IdentityError("Stale native window")
        return buffer.value

    def _thread_for(self, hwnd: int) -> int:
        pid = w.DWORD()
        thread = int(self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)))
        if not thread or not pid.value:
            raise IdentityError("Native window process identity unavailable")
        return thread

    def _process(self, pid: int) -> tuple[int, int, str]:
        handle = self.kernel.OpenProcess(0x101000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            times = [w.FILETIME() for _ in range(4)]
            if not self.kernel.GetProcessTimes(
                handle,
                *(ctypes.byref(time) for time in times),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_unicode_buffer(32768)
            length = w.DWORD(len(buffer))
            if not self.kernel.QueryFullProcessImageNameW(
                handle,
                0,
                buffer,
                ctypes.byref(length),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            created = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
            return pid, created, os.path.normcase(os.path.abspath(buffer.value))
        finally:
            self.kernel.CloseHandle(handle)

    def _window_process(self, hwnd: int) -> tuple[int, int, str]:
        if not self.user.IsWindow(hwnd):
            raise IdentityError("Bound window does not exist")
        pid = w.DWORD()
        if not self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
            raise IdentityError("Bound window process identity unavailable")
        return self._process(int(pid.value))

    def _descriptor(self) -> dict:
        return {
            "hwnd": self.control_hwnd,
            "cookie": self._control_marker,
            "class_name": self.expected_control_class,
            "control_id": self.control_id,
        }

    def _assert_live(self) -> None:
        if self._closed or not self.user.IsWindow(self.hwnd):
            raise IdentityError("Stale native receiver window")
        pid, created, executable = self._window_process(self.hwnd)
        if (
            pid != self.pid
            or created != self.created
            or executable != self.expected_executable
            or self._thread_for(self.hwnd) != self.thread_id
            or self._class(self.hwnd) != self.expected_window_class
            or self.user.GetPropW(self.hwnd, self._property_name) != self._window_marker
            or not self.user.IsWindow(self.control_hwnd)
            or self._thread_for(self.control_hwnd) != self.thread_id
            or not self.user.IsChild(self.hwnd, self.control_hwnd)
            or self._class(self.control_hwnd) != self.expected_control_class
            or self.user.GetPropW(self.control_hwnd, self._property_name)
            != self._control_marker
        ):
            raise IdentityError("Native process/window/control identity mismatch")

    def _foreground_focus(self) -> tuple[int, int]:
        class _GuiThreadInfo(ctypes.Structure):
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

        info = _GuiThreadInfo()
        info.cbSize = ctypes.sizeof(info)
        if not self.user.GetGUIThreadInfo(self.thread_id, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(self.user.GetForegroundWindow() or 0), int(info.hwndFocus or 0)

    def _visible_enabled(self, hwnd: int) -> bool:
        rectangle = w.RECT()
        return bool(
            self.user.IsWindowVisible(hwnd)
            and self.user.IsWindowEnabled(hwnd)
            and self.user.GetWindowRect(hwnd, ctypes.byref(rectangle))
            and self.user.MonitorFromRect(ctypes.byref(rectangle), 0)
        )

    def snapshot(self) -> dict:
        self._assert_live()
        return {
            "pid": self.pid,
            "created_filetime": self.created,
            "hwnd": self.hwnd,
            "window_cookie": self._window_marker,
            "revision": self._revision,
            "controls": {
                "": self._descriptor(),
                self.control_id: self._descriptor(),
            },
        }

    def dispatch(self, request: dict) -> dict:
        self._assert_live()

        def reject(code):
            return {"dispatched": False, "failure": code}

        window = request.get("window", {})
        process = window.get("process", {})
        if (
            request.get("action") != "type_into"
            or process.get("pid") != self.pid
            or process.get("created_filetime") != self.created
            or os.path.normcase(process.get("executable", ""))
            != self.expected_executable
            or window.get("hwnd") != self.hwnd
            or window.get("thread_id") != self.thread_id
            or window.get("class_name") != self.expected_window_class
            or request.get("window_cookie") != self._window_marker
            or request.get("revision") != self._revision
        ):
            return reject("STALE_TARGET")
        control_id = request.get("control_id")
        if (
            control_id not in {"", self.control_id}
            or request.get("control") != self._descriptor()
        ):
            return reject("STALE_TARGET")
        foreground, focus = self._foreground_focus()
        if foreground != self.hwnd:
            return reject("WRONG_FOREGROUND")
        if focus != self.control_hwnd:
            return reject("FOCUS_FAILURE")
        if not self._visible_enabled(self.hwnd) or not self._visible_enabled(
            self.control_hwnd
        ):
            return reject("PRECONDITION_FAILURE")
        style = int(self.user.GetWindowLongPtrW(self.control_hwnd, -16)) & 0xFFFFFFFF
        if style & (0x0020 | 0x0800):
            return reject("UNSUPPORTED_CONTROL")
        value = request.get("value")
        if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
            return reject("PRECONDITION_FAILURE")

        self._dispatch_count += 1
        buffer = ctypes.create_unicode_buffer(value)
        result = w.LPARAM()
        sent = self.user.SendMessageTimeoutW(
            self.control_hwnd,
            0x000C,
            0,
            ctypes.cast(buffer, ctypes.c_void_p).value,
            0x0002 | 0x0001,
            self.timeout_ms,
            ctypes.byref(result),
        )
        if not sent:
            raise TimeoutError("Native WM_SETTEXT outcome is unknown")
        self._revision += 1
        return {
            "dispatched": True,
            "dispatch_count": self._dispatch_count,
        }

    def close(self):
        if self._closed:
            return
        for hwnd, marker in (
            (self.hwnd, self._window_marker),
            (self.control_hwnd, self._control_marker),
        ):
            if (
                self.user.IsWindow(hwnd)
                and self.user.GetPropW(hwnd, self._property_name) == marker
            ):
                self.user.RemovePropW(hwnd, self._property_name)
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
