"""Owner-thread Windows/UIA reads. No input, invoke, focus or setter APIs."""

from __future__ import annotations

import ctypes
import os
import threading
import uuid
from collections import deque
from ctypes import wintypes as w
from pathlib import Path

from openjarvis.windows.identity import (
    ControlIdentity,
    IdentityError,
    ProcessIdentity,
    WindowIdentity,
)


class NativeBackend:
    """Use only inside the observation worker's windowless COM MTA thread."""

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows UI Automation is unavailable on this platform")
        self._owner = threading.get_ident()
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.ole = ctypes.OleDLL("ole32")
        self.ole.CoInitializeEx.argtypes = [w.LPVOID, w.DWORD]
        self.ole.CoInitializeEx.restype = ctypes.c_long
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None
        # Explicit MTA initialization; importing comtypes on this thread cannot
        # switch the apartment. This backend thread owns no application windows.
        self.ole.CoInitializeEx(None, 0)
        self._processes: dict[int, int] = {}
        self._tracked_hwnds: set[int] = set()
        self._tracked_pid = 0
        self._epoch = uuid.uuid4().hex
        self._hook = None
        self._root = None
        self._structure_handler = None
        self._structure_object = None
        self.walker = None
        self.uia = None
        self._closed = False
        self._signature(self.kernel.OpenProcess, [w.DWORD, w.BOOL, w.DWORD], w.HANDLE)
        self._signature(self.kernel.CloseHandle, [w.HANDLE], w.BOOL)
        self._signature(self.kernel.WaitForSingleObject, [w.HANDLE, w.DWORD], w.DWORD)
        self._signature(
            self.kernel.GetProcessTimes, [w.HANDLE] + [w.LPVOID] * 4, w.BOOL
        )
        self._signature(
            self.kernel.QueryFullProcessImageNameW,
            [w.HANDLE, w.DWORD, w.LPWSTR, w.LPVOID],
            w.BOOL,
        )
        self._signature(self.user.IsWindow, [w.HWND], w.BOOL)
        self._signature(
            self.user.GetWindowLongPtrW,
            [w.HWND, ctypes.c_int],
            ctypes.c_ssize_t,
        )
        self._signature(self.user.IsChild, [w.HWND, w.HWND], w.BOOL)
        self._signature(self.user.IsWindowVisible, [w.HWND], w.BOOL)
        self._signature(self.user.IsWindowEnabled, [w.HWND], w.BOOL)
        self._signature(self.user.IsIconic, [w.HWND], w.BOOL)
        self._signature(self.user.GetWindowRect, [w.HWND, w.LPVOID], w.BOOL)
        self._signature(self.user.MonitorFromRect, [w.LPVOID, w.DWORD], w.HANDLE)
        self._signature(self.user.GetWindowThreadProcessId, [w.HWND, w.LPVOID], w.DWORD)
        self._signature(
            self.user.GetClassNameW, [w.HWND, w.LPWSTR, ctypes.c_int], ctypes.c_int
        )
        self._signature(self.user.GetForegroundWindow, [], w.HWND)
        self._signature(
            self.user.PeekMessageW, [w.LPVOID, w.HWND, w.UINT, w.UINT, w.UINT], w.BOOL
        )
        self._signature(self.user.TranslateMessage, [w.LPVOID], w.BOOL)
        self._signature(self.user.DispatchMessageW, [w.LPVOID], ctypes.c_ssize_t)
        self._signature(self.user.UnhookWinEvent, [w.HANDLE], w.BOOL)
        callback_type = ctypes.WINFUNCTYPE(
            None,
            w.HANDLE,
            w.DWORD,
            w.HWND,
            w.LONG,
            w.LONG,
            w.DWORD,
            w.DWORD,
        )
        self._callback = callback_type(self._on_event)
        self._signature(
            self.user.SetWinEventHook,
            [w.DWORD, w.DWORD, w.HMODULE, callback_type, w.DWORD, w.DWORD, w.DWORD],
            w.HANDLE,
        )
        try:
            import comtypes.client

            module = comtypes.client.GetModule(
                str(
                    Path(os.environ["SystemRoot"]) / "System32/UIAutomationCore.dll",
                )
            )
            self.uia = comtypes.client.CreateObject(
                module.CUIAutomation,
                interface=module.IUIAutomation,
            )
            self._module = module
            # Raw view retains non-control ancestors and hidden descendants;
            # enabled/offscreen preconditions are checked separately.
            self.walker = self.uia.RawViewWalker
            backend = self

            class StructureHandler(comtypes.COMObject):
                _com_interfaces_ = [module.IUIAutomationStructureChangedEventHandler]

                def HandleStructureChangedEvent(
                    self,
                    this,
                    sender,
                    change_type,
                    runtime_id,
                ):
                    # UIA calls this on a non-UI COM thread. No element reads or
                    # retargeting occur here; only conservative invalidation.
                    backend._epoch = uuid.uuid4().hex
                    return 0

            self._structure_object = StructureHandler()
            self._structure_handler = self._structure_object.QueryInterface(
                module.IUIAutomationStructureChangedEventHandler,
            )
            self._hook = self.user.SetWinEventHook(
                0x8000,
                0x8001,
                None,
                self._callback,
                0,
                0,
                0,
            )  # Out-of-context create/destroy events; never inject a DLL.
            if not self._hook:
                raise ctypes.WinError(ctypes.get_last_error())
        except Exception:
            self.close()
            raise

    @staticmethod
    def _signature(function, arguments, result):
        function.argtypes, function.restype = arguments, result

    def _owned(self):
        if threading.get_ident() != self._owner or self._closed:
            raise IdentityError("UIA owner thread/session mismatch")

    def _on_event(self, hook, event, hwnd, object_id, child_id, thread, timestamp):
        if object_id != 0 or child_id != 0 or not hwnd:
            return
        try:
            pid = w.DWORD()
            self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if int(hwnd) in self._tracked_hwnds or pid.value == self._tracked_pid:
                self._epoch = uuid.uuid4().hex
        except Exception:
            # ctypes callbacks cannot propagate failures to the calling loop.
            # Conservatively invalidate instead of keeping a trusted epoch.
            self._epoch = uuid.uuid4().hex

    def pump(self):
        self._owned()
        message = w.MSG()
        while self.user.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
            self.user.TranslateMessage(ctypes.byref(message))
            self.user.DispatchMessageW(ctypes.byref(message))

    def _process(self, pid: int) -> ProcessIdentity:
        handle = self._processes.get(pid)
        if handle is None:
            handle = self.kernel.OpenProcess(0x101000, False, pid)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            self._processes[pid] = handle
        # A retained terminated process is never replaced by opening its PID.
        if self.kernel.WaitForSingleObject(handle, 0) != 258:
            raise IdentityError("Observed process terminated or cannot be checked")
        times = [w.FILETIME() for _ in range(4)]
        if not self.kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
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
        return ProcessIdentity(pid, created, os.path.normcase(buffer.value))

    def window(self, hwnd: int) -> WindowIdentity:
        self._owned()
        self.pump()
        if not self.user.IsWindow(hwnd):
            raise IdentityError("Window does not exist")
        pid = w.DWORD()
        thread = self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not thread or not pid.value:
            raise IdentityError("Window process identity unavailable")
        process = self._process(pid.value)
        self._tracked_pid = pid.value
        self._tracked_hwnds.add(hwnd)
        name = ctypes.create_unicode_buffer(256)
        if not self.user.GetClassNameW(hwnd, name, len(name)):
            raise ctypes.WinError(ctypes.get_last_error())
        after_pid = w.DWORD()
        if self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(after_pid)) != thread:
            raise IdentityError("Window thread changed during observation")
        if after_pid.value != pid.value:
            raise IdentityError("Window process changed during observation")
        return WindowIdentity(process, hwnd, thread, name.value, self._epoch)

    def foreground(self) -> int:
        self._owned()
        return int(self.user.GetForegroundWindow() or 0)

    def begin_observation(self):
        self._owned()
        if self._root is not None:
            self.uia.RemoveStructureChangedEventHandler(
                self._root,
                self._structure_handler,
            )
            self._root = None
        for handle in self._processes.values():
            self.kernel.CloseHandle(handle)
        self._processes.clear()
        self._tracked_hwnds.clear()
        self._tracked_pid = 0
        self._epoch = uuid.uuid4().hex
        self.pump()

    def enumerate(self, hwnd: int, limit: int) -> list[object]:
        self._owned()
        root = self.uia.ElementFromHandle(hwnd)
        if not root:
            raise IdentityError("UIA window root unavailable")
        if self._root is None:
            self.uia.AddStructureChangedEventHandler(
                root,
                7,
                None,
                self._structure_handler,
            )
            self._root = root
        result = []
        pending = deque([(root, 0)])
        while pending:
            element, depth = pending.popleft()
            if depth > 32 or len(result) >= limit:
                raise IdentityError(
                    "UIA enumeration limit exceeded; observation incomplete"
                )
            result.append(element)
            child = self.walker.GetFirstChildElement(element)
            siblings = set()
            while child:
                runtime_id = tuple(child.GetRuntimeId())
                if runtime_id in siblings or len(pending) + len(result) >= limit:
                    raise IdentityError("UIA enumeration cycle or limit exceeded")
                siblings.add(runtime_id)
                pending.append((child, depth + 1))
                child = self.walker.GetNextSiblingElement(child)
        return result

    def control(self, element: object, hwnd: int):
        self._owned()
        root = self.uia.ElementFromHandle(hwnd)
        runtime_id = tuple(element.GetRuntimeId())
        ancestry = []
        parent = element
        for _ in range(33):
            if not parent:
                raise IdentityError("UIA control is outside the observed window")
            ancestry.append(tuple(parent.GetRuntimeId()))
            if self.uia.CompareElements(parent, root):
                break
            parent = self.walker.GetParentElement(parent)
        else:
            raise IdentityError("UIA hierarchy limit exceeded")
        native_hwnd = int(element.CurrentNativeWindowHandle or 0)
        if native_hwnd:
            pid = w.DWORD()
            if (
                not self.user.IsWindow(native_hwnd)
                or not self.user.GetWindowThreadProcessId(
                    native_hwnd, ctypes.byref(pid)
                )
                or pid.value != self._tracked_pid
                or (native_hwnd != hwnd and not self.user.IsChild(hwnd, native_hwnd))
            ):
                raise IdentityError("UIA native HWND/process/hierarchy mismatch")
            self._tracked_hwnds.add(native_hwnd)
        identity = ControlIdentity(
            runtime_id,
            int(element.CurrentProcessId),
            native_hwnd,
            element.CurrentAutomationId or "",
            int(element.CurrentControlType),
            element.CurrentClassName or "",
            element.CurrentFrameworkId or "",
            tuple(reversed(ancestry)),
        )
        name = element.CurrentName or ""
        if any(
            len(text) > 4096
            for text in (
                name,
                identity.automation_id,
                identity.class_name,
                identity.framework,
            )
        ):
            raise IdentityError("UIA property size limit exceeded")
        root_rect = w.RECT()
        if not self.user.GetWindowRect(hwnd, ctypes.byref(root_rect)):
            raise ctypes.WinError(ctypes.get_last_error())
        rectangle = element.CurrentBoundingRectangle
        control_rect = w.RECT(
            rectangle.left,
            rectangle.top,
            rectangle.right,
            rectangle.bottom,
        )
        on_monitor = (
            root_rect.right > root_rect.left
            and root_rect.bottom > root_rect.top
            and control_rect.right > control_rect.left
            and control_rect.bottom > control_rect.top
            and self.user.MonitorFromRect(ctypes.byref(root_rect), 0)
            and self.user.MonitorFromRect(ctypes.byref(control_rect), 0)
        )
        enabled = bool(element.CurrentIsEnabled) and bool(
            self.user.IsWindowEnabled(hwnd)
        )
        if native_hwnd:
            enabled = enabled and bool(self.user.IsWindowEnabled(native_hwnd))
        offscreen = (
            bool(element.CurrentIsOffscreen)
            or not on_monitor
            or not self.user.IsWindowVisible(hwnd)
            or bool(self.user.IsIconic(hwnd))
        )
        return identity, name, enabled, bool(offscreen)

    def same_element(self, retained: object, current: object) -> bool:
        self._owned()
        return bool(self.uia.CompareElements(retained, current))

    def value_capability(self, element: object) -> bool:
        """Prove that a value can be read back before authorizing typing.

        Password controls are deliberately excluded because ``value`` refuses
        to read them.  Requiring the pattern and a bounded current value here
        prevents a type action from creating an unverifiable mutation.
        """
        self._owned()
        if element.CurrentIsPassword:
            return False
        native_hwnd = int(element.CurrentNativeWindowHandle or 0)
        if native_hwnd:
            style = int(self.user.GetWindowLongPtrW(native_hwnd, -16)) & 0xFFFFFFFF
            if style & 0x0020:  # ES_PASSWORD; UIA may lag a live style update.
                return False
        try:
            pattern = element.GetCurrentPattern(10002).QueryInterface(
                self._module.IUIAutomationValuePattern
            )
            value = pattern.CurrentValue
        except Exception:
            return False
        return isinstance(value, str) and len(value) <= 4096

    def value(self, element: object) -> str:
        """Read a value, never invoke its setter; refuse password controls."""
        self._owned()
        if element.CurrentIsPassword:
            raise IdentityError("Password control verification is unsupported")
        pattern = element.GetCurrentPattern(10002).QueryInterface(
            self._module.IUIAutomationValuePattern
        )
        value = pattern.CurrentValue
        if not isinstance(value, str) or len(value) > 4096:
            raise IdentityError("Control value verification limit exceeded")
        return value

    def close(self):
        if self._closed:
            return
        if threading.get_ident() != self._owner:
            raise IdentityError("UIA cleanup must run on its owner thread")
        if self._hook:
            self.user.UnhookWinEvent(self._hook)
        if self._root is not None:
            self.uia.RemoveStructureChangedEventHandler(
                self._root,
                self._structure_handler,
            )
            self._root = None
        self._structure_handler = None
        self._structure_object = None
        self.walker = None
        self.uia = None
        for handle in self._processes.values():
            self.kernel.CloseHandle(handle)
        self._processes.clear()
        self._closed = True
        self.ole.CoUninitialize()
