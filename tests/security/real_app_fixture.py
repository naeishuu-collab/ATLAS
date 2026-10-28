"""A disposable, non-cooperative Win32 editor used only by real-app tests."""

from __future__ import annotations

import ctypes
import json
import multiprocessing
import os
import threading
import uuid
from ctypes import wintypes as w

_WM_SETTEXT = 0x000C
_GWLP_WNDPROC = -4
_WS_CHILD_VISIBLE = 0x50000000
_WS_CHILD_VISIBLE_EDIT = 0x50010080


class _Application:
    def __init__(self):
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._signature(
            self.user.CreateWindowExW,
            [
                w.DWORD,
                w.LPCWSTR,
                w.LPCWSTR,
                w.DWORD,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                w.HWND,
                w.HMENU,
                w.HINSTANCE,
                w.LPVOID,
            ],
            w.HWND,
        )
        self._signature(self.user.DestroyWindow, [w.HWND], w.BOOL)
        self._signature(
            self.user.DefWindowProcW,
            [w.HWND, w.UINT, w.WPARAM, w.LPARAM],
            ctypes.c_ssize_t,
        )
        self._signature(self.user.ShowWindow, [w.HWND, ctypes.c_int], w.BOOL)
        self._signature(self.user.UpdateWindow, [w.HWND], w.BOOL)
        self._signature(self.user.SetForegroundWindow, [w.HWND], w.BOOL)
        self._signature(self.user.BringWindowToTop, [w.HWND], w.BOOL)
        self._signature(self.user.SetActiveWindow, [w.HWND], w.HWND)
        self._signature(self.user.SetFocus, [w.HWND], w.HWND)
        self._signature(self.user.GetForegroundWindow, [], w.HWND)
        self._signature(self.user.GetFocus, [], w.HWND)
        self._signature(self.user.GetWindowThreadProcessId, [w.HWND, w.LPVOID], w.DWORD)
        self._signature(self.user.AttachThreadInput, [w.DWORD, w.DWORD, w.BOOL], w.BOOL)
        self._signature(self.user.AllowSetForegroundWindow, [w.DWORD], w.BOOL)
        self._signature(self.kernel.GetCurrentThreadId, [], w.DWORD)
        self._signature(
            self.user.GetWindowTextW, [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int
        )
        self._signature(
            self.user.SetWindowLongPtrW,
            [w.HWND, ctypes.c_int, ctypes.c_ssize_t],
            ctypes.c_ssize_t,
        )
        self._signature(
            self.user.CallWindowProcW,
            [ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM],
            ctypes.c_ssize_t,
        )
        self._signature(self.user.RegisterClassW, [w.LPVOID], w.WORD)
        self._signature(self.user.UnregisterClassW, [w.LPCWSTR, w.HINSTANCE], w.BOOL)
        self._signature(self.kernel.GetModuleHandleW, [w.LPCWSTR], w.HINSTANCE)
        self._signature(
            self.kernel.GetModuleFileNameW,
            [w.HANDLE, w.LPWSTR, w.DWORD],
            w.DWORD,
        )
        self._signature(
            self.user.PeekMessageW, [w.LPVOID, w.HWND, w.UINT, w.UINT, w.UINT], w.BOOL
        )
        self._signature(self.user.TranslateMessage, [w.LPVOID], w.BOOL)
        self._signature(self.user.DispatchMessageW, [w.LPVOID], ctypes.c_ssize_t)
        self._signature(
            self.user.MsgWaitForMultipleObjectsEx,
            [w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.DWORD],
            w.DWORD,
        )
        self._signature(self.user.GetDlgCtrlID, [w.HWND], ctypes.c_int)
        self.expected_control_dispatch_count = 0
        self.wrong_target_dispatch_count = 0
        self.last_dispatch_control_hwnd = 0
        self.ready = False
        self.class_name = "AstraRealApp_" + uuid.uuid4().hex
        self.title = "ASTRA_REAL_APP_" + uuid.uuid4().hex
        self.instance = self.kernel.GetModuleHandleW(None)
        self._window_callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t,
            w.HWND,
            w.UINT,
            w.WPARAM,
            w.LPARAM,
        )
        self._window_callback = self._window_callback_type(self._window_proc)

        class _WindowClass(ctypes.Structure):
            _fields_ = [
                ("style", w.UINT),
                ("lpfnWndProc", self._window_callback_type),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", w.HINSTANCE),
                ("hIcon", w.HANDLE),
                ("hCursor", w.HANDLE),
                ("hbrBackground", w.HANDLE),
                ("lpszMenuName", w.LPCWSTR),
                ("lpszClassName", w.LPCWSTR),
            ]

        self._window_class = _WindowClass(
            0,
            self._window_callback,
            0,
            0,
            self.instance,
            None,
            None,
            None,
            None,
            self.class_name,
        )
        if not self.user.RegisterClassW(ctypes.byref(self._window_class)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.hwnd = self._create_root()
        self.edit_hwnd = 0
        self.duplicate_hwnd = 0
        self._edit_callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t,
            w.HWND,
            w.UINT,
            w.WPARAM,
            w.LPARAM,
        )
        self._edit_callback = self._edit_callback_type(self._edit_proc)
        self._old_edit_procs = {}
        self._create_edit()
        self.ready = True
        self.user.ShowWindow(self.hwnd, 5)
        self.user.UpdateWindow(self.hwnd)
        self.user.SetForegroundWindow(self.hwnd)
        self.user.SetFocus(self.edit_hwnd)

    @staticmethod
    def _signature(function, arguments, result):
        function.argtypes, function.restype = arguments, result

    def _create_root(self):
        hwnd = int(
            self.user.CreateWindowExW(
                0x00040000,
                self.class_name,
                self.title,
                0x10CF0000,
                120,
                120,
                520,
                180,
                None,
                None,
                self.instance,
                None,
            )
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        return hwnd

    def _create_edit(
        self,
        *,
        control_id=7101,
        y=30,
        track=True,
        class_name="EDIT",
        style=_WS_CHILD_VISIBLE_EDIT,
    ):
        hwnd = int(
            self.user.CreateWindowExW(
                0,
                class_name,
                "",
                style,
                20,
                y,
                460,
                32,
                self.hwnd,
                control_id,
                self.instance,
                None,
            )
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        if not track:
            return hwnd
        self.edit_hwnd = hwnd
        self._subclass_edit(hwnd)
        return hwnd

    def _subclass_edit(self, hwnd):
        self._old_edit_procs[hwnd] = int(
            self.user.SetWindowLongPtrW(
                hwnd,
                _GWLP_WNDPROC,
                ctypes.cast(self._edit_callback, ctypes.c_void_p).value,
            )
        )
        if not self._old_edit_procs[hwnd]:
            raise ctypes.WinError(ctypes.get_last_error())

    def add_duplicate(self):
        if self.duplicate_hwnd:
            return self.state()
        self.duplicate_hwnd = self._create_edit(
            control_id=7102,
            y=78,
            track=False,
        )
        self._subclass_edit(self.duplicate_hwnd)
        return self.state()

    def _window_proc(self, hwnd, message, wparam, lparam):
        return self.user.DefWindowProcW(hwnd, message, wparam, lparam)

    def _edit_proc(self, hwnd, message, wparam, lparam):
        if message == _WM_SETTEXT and self.ready:
            hwnd = int(hwnd)
            if hwnd == self.edit_hwnd:
                self.expected_control_dispatch_count += 1
            elif hwnd == self.duplicate_hwnd:
                self.wrong_target_dispatch_count += 1
            else:
                return self.user.CallWindowProcW(
                    self._old_edit_procs[int(hwnd)],
                    hwnd,
                    message,
                    wparam,
                    lparam,
                )
            self.last_dispatch_control_hwnd = hwnd
        return self.user.CallWindowProcW(
            self._old_edit_procs[int(hwnd)],
            hwnd,
            message,
            wparam,
            lparam,
        )

    def state(self):
        def read_text(hwnd):
            buffer = ctypes.create_unicode_buffer(4097)
            self.user.GetWindowTextW(hwnd, buffer, len(buffer))
            return buffer.value

        decoy_hwnd = int(self.duplicate_hwnd or 0)
        return {
            "pid": os.getpid(),
            "hwnd": self.hwnd,
            "control_hwnd": self.edit_hwnd,
            "text": read_text(self.edit_hwnd),
            "dispatch_count": self.expected_control_dispatch_count,
            "expected_control_dispatch_count": self.expected_control_dispatch_count,
            "wrong_target_dispatch_count": self.wrong_target_dispatch_count,
            "last_dispatch_control_hwnd": self.last_dispatch_control_hwnd,
            "decoy_control_hwnd": decoy_hwnd,
            "decoy_text": read_text(decoy_hwnd) if decoy_hwnd else "",
            "foreground": int(self.user.GetForegroundWindow() or 0),
            "focus": int(self.user.GetFocus() or 0),
        }

    def executable_path(self):
        buffer = ctypes.create_unicode_buffer(32768)
        length = self.kernel.GetModuleFileNameW(None, buffer, len(buffer))
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        return os.path.normcase(os.path.abspath(buffer.value))

    def focus(self):
        self.user.ShowWindow(self.hwnd, 5)
        foreground = self.user.GetForegroundWindow()
        foreground_pid = w.DWORD()
        foreground_thread = int(
            self.user.GetWindowThreadProcessId(
                foreground,
                ctypes.byref(foreground_pid),
            )
            if foreground
            else 0
        )
        current_thread = int(self.kernel.GetCurrentThreadId())
        # Test setup only: temporarily share input to request foreground for
        # this disposable app. The production receiver still verifies the
        # live foreground and focus immediately before dispatch.
        attached = bool(
            foreground_thread
            and foreground_thread != current_thread
            and self.user.AttachThreadInput(
                current_thread,
                foreground_thread,
                True,
            )
        )
        try:
            self.user.BringWindowToTop(self.hwnd)
            self.user.SetActiveWindow(self.hwnd)
            foreground_request_accepted = bool(self.user.SetForegroundWindow(self.hwnd))
            self.user.SetFocus(self.edit_hwnd)
        finally:
            if attached:
                self.user.AttachThreadInput(current_thread, foreground_thread, False)
        result = self.state()
        result["foreground_request_accepted"] = foreground_request_accepted
        return result

    def replace(self):
        self.ready = False
        self.user.DestroyWindow(self.edit_hwnd)
        self._old_edit_procs.pop(self.edit_hwnd, None)
        self._create_edit()
        self.ready = True
        return self.state()

    def recreate(self):
        self.ready = False
        self.user.DestroyWindow(self.hwnd)
        self._old_edit_procs.clear()
        self.duplicate_hwnd = 0
        self.hwnd = self._create_root()
        self._create_edit()
        self.ready = True
        self.user.ShowWindow(self.hwnd, 5)
        self.user.UpdateWindow(self.hwnd)
        return self.state()

    def close(self):
        self.ready = False
        if self.hwnd:
            self.user.DestroyWindow(self.hwnd)
            self.hwnd = 0
        self._old_edit_procs.clear()
        self.user.UnregisterClassW(self.class_name, self.instance)

    def command(self, name, args):
        if name == "close":
            return None
        if name == "state":
            return self.state()
        if name == "focus":
            return self.focus()
        if name == "grant_foreground":
            return {
                "granted": bool(self.user.AllowSetForegroundWindow(int(args["pid"])))
            }
        if name == "replace":
            return self.replace()
        if name == "recreate":
            return self.recreate()
        if name == "duplicate":
            return self.add_duplicate()
        raise ValueError(f"Unknown real app command: {name}")


def _run(connection):
    app = None
    try:
        app = _Application()
        connection.send_bytes(
            json.dumps(
                {
                    "ready": True,
                    "pid": os.getpid(),
                    "hwnd": app.hwnd,
                    "control_hwnd": app.edit_hwnd,
                    "executable": app.executable_path(),
                    "window_class": app.class_name,
                }
            ).encode()
        )
        message = w.MSG()
        while True:
            while app.user.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
                app.user.TranslateMessage(ctypes.byref(message))
                app.user.DispatchMessageW(ctypes.byref(message))
            if not connection.poll(0):
                app.user.MsgWaitForMultipleObjectsEx(0, None, 10, 0x04FF, 0x0004)
                continue
            request = json.loads(connection.recv_bytes(1024 * 1024))
            if request["command"] == "close":
                break
            try:
                result = app.command(request["command"], request.get("args", {}))
                connection.send_bytes(json.dumps({"result": result}).encode())
            except Exception as error:
                connection.send_bytes(
                    json.dumps({"error": f"{type(error).__name__}: {error}"}).encode()
                )
    finally:
        if app is not None:
            app.close()
        connection.close()


class RealAppProcess:
    live: list["RealAppProcess"] = []

    def __init__(self):
        context = multiprocessing.get_context("spawn")
        self.connection, child = context.Pipe()
        self.process = context.Process(target=_run, args=(child,))
        self.process.start()
        child.close()
        if not self.connection.poll(15):
            raise TimeoutError("Real app startup deadline")
        ready = json.loads(self.connection.recv_bytes())
        if ready.get("ready") is not True:
            raise RuntimeError("Real app did not become ready")
        self.pid = int(ready["pid"])
        self.hwnd = int(ready["hwnd"])
        self.control_hwnd = int(ready["control_hwnd"])
        self.decoy_control_hwnd = 0
        self.executable = ready["executable"]
        self.window_class = ready["window_class"]
        self._lock = threading.RLock()
        self.live.append(self)

    def rpc(self, command, args=None):
        with self._lock:
            self.connection.send_bytes(
                json.dumps({"command": command, "args": args or {}}).encode()
            )
            if not self.connection.poll(15):
                raise TimeoutError("Real app request deadline")
            response = json.loads(self.connection.recv_bytes(1024 * 1024))
            if "error" in response:
                raise RuntimeError(response["error"])
            return response.get("result")

    def state(self):
        return self.rpc("state")

    def add_duplicate(self):
        state = self.rpc("duplicate")
        self.decoy_control_hwnd = int(state["decoy_control_hwnd"])
        return state

    def focus(self):
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.GetForegroundWindow.restype = w.HWND
        user.AllowSetForegroundWindow.argtypes = [w.DWORD]
        user.AllowSetForegroundWindow.restype = w.BOOL
        foreground = int(user.GetForegroundWindow() or 0)
        user.AllowSetForegroundWindow(self.pid)
        for other in self.live:
            if (
                other is not self
                and other.process.is_alive()
                and other.hwnd == foreground
            ):
                other.rpc("grant_foreground", {"pid": self.pid})
        state = self.rpc("focus")
        if state["foreground"] != self.hwnd or state["focus"] != self.control_hwnd:
            raise AssertionError(f"Real app foreground setup failed: {state}")
        return state

    def close(self):
        if self.connection.closed:
            return
        try:
            self.connection.send_bytes(json.dumps({"command": "close"}).encode())
            self.process.join(5)
        finally:
            self.connection.close()
            if self.process.is_alive():
                raise RuntimeError("Real app did not stop after cooperative close")
            if self in self.live:
                self.live.remove(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
