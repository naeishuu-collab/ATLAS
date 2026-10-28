"""Off-desktop, nonactivating test windows on their own pumping GUI thread."""

import ctypes
import os
import queue
import threading
from ctypes import wintypes as w


class FixtureWindow:
    def __init__(self):
        self._queue = queue.Queue()
        self._ready = threading.Event()
        self._error = None
        self.hwnd = 0
        self.controls = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        assert self._ready.wait(10), "Fixture GUI thread did not start"
        if self._error:
            raise self._error

    def _run(self):
        try:
            self.user = ctypes.WinDLL("user32", use_last_error=True)
            create = self.user.CreateWindowExW
            create.argtypes = [
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
            ]
            create.restype = w.HWND
            self.user.DestroyWindow.argtypes = [w.HWND]
            self.user.DestroyWindow.restype = w.BOOL
            self.user.PeekMessageW.argtypes = [w.LPVOID, w.HWND, w.UINT, w.UINT, w.UINT]
            self.user.PeekMessageW.restype = w.BOOL
            self.user.TranslateMessage.argtypes = [w.LPVOID]
            self.user.DispatchMessageW.argtypes = [w.LPVOID]
            self.user.DispatchMessageW.restype = ctypes.c_ssize_t
            self.hwnd = self._create_root()
            self.controls = [self._create_button(i) for i in (201, 202)]
            self.user.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
            self.user.ShowWindow.restype = w.BOOL
            self.user.ShowWindow(self.hwnd, 4)  # SW_SHOWNOACTIVATE
        except Exception as error:
            self._error = error
            self._ready.set()
            return
        self._ready.set()
        message = w.MSG()
        try:
            while True:
                while self.user.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
                    self.user.TranslateMessage(ctypes.byref(message))
                    self.user.DispatchMessageW(ctypes.byref(message))
                try:
                    function, done, output = self._queue.get(timeout=0.01)
                except queue.Empty:
                    continue
                if function is None:
                    done.set()
                    break
                try:
                    output.append(function())
                except Exception as error:
                    output.append(error)
                done.set()
        finally:
            if self.hwnd:
                self.user.DestroyWindow(self.hwnd)

    def _create_root(self):
        hwnd = self.user.CreateWindowExW(
            0x08000080,  # NOACTIVATE | TOOLWINDOW: never steal focus/taskbar space
            "#32770",
            f"Astra fixture {os.getpid()}",
            0x80C00000,
            30000,
            30000,
            300,
            180,
            None,
            None,
            None,
            None,
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(hwnd)

    def _create_button(self, control_id):
        hwnd = self.user.CreateWindowExW(
            0,
            "BUTTON",
            "Save",
            0x50000000,
            10,
            control_id - 180,
            100,
            25,
            self.hwnd,
            control_id,
            None,
            None,
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(hwnd)

    def call(self, function):
        done = threading.Event()
        output = []
        self._queue.put((function, done, output))
        assert done.wait(10), "Fixture GUI command did not complete"
        if isinstance(output[0], Exception):
            raise output[0]
        return output[0]

    def replace_button(self):
        def replace():
            assert self.user.DestroyWindow(self.controls[0])
            self.controls[0] = self._create_button(201)
            return self.controls[0]

        return self.call(replace)

    def recreate_window(self):
        def recreate():
            assert self.user.DestroyWindow(self.hwnd)
            self.hwnd = self._create_root()
            self.controls = [self._create_button(i) for i in (201, 202)]
            self.user.ShowWindow(self.hwnd, 4)
            return self.hwnd

        return self.call(recreate)

    def close(self):
        done = threading.Event()
        self._queue.put((None, done, []))
        self._thread.join(10)
        assert not self._thread.is_alive(), "Fixture GUI thread leaked"
