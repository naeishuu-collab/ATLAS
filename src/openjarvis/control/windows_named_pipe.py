"""Bounded, ACL-protected Windows named-pipe messages with peer PID checks."""

from __future__ import annotations

import ctypes
import json
import os
import struct
import threading
import time
from ctypes import wintypes as w
from functools import cache
from typing import Any, Mapping

from openjarvis.control.windows_peer import process_identity

_MAX_MESSAGE = 131072
_ERROR_PIPE_CONNECTED = 535
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PIPE_BUSY = 231
_ERROR_NO_DATA = 232
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_PIPE_READ_TIMEOUT = 5.0


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", w.DWORD),
        ("descriptor", w.LPVOID),
        ("inherit", w.BOOL),
    ]


@cache
def _apis() -> tuple[Any, Any]:
    if os.name != "nt":
        raise PermissionError("Windows named-pipe IPC is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    signatures = (
        (
            kernel.CreateNamedPipeW,
            [
                w.LPCWSTR,
                w.DWORD,
                w.DWORD,
                w.DWORD,
                w.DWORD,
                w.DWORD,
                w.DWORD,
                ctypes.POINTER(_SecurityAttributes),
            ],
            w.HANDLE,
        ),
        (kernel.ConnectNamedPipe, [w.HANDLE, w.LPVOID], w.BOOL),
        (kernel.DisconnectNamedPipe, [w.HANDLE], w.BOOL),
        (
            kernel.CreateFileW,
            [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE],
            w.HANDLE,
        ),
        (kernel.WaitNamedPipeW, [w.LPCWSTR, w.DWORD], w.BOOL),
        (
            kernel.SetNamedPipeHandleState,
            [w.HANDLE, ctypes.POINTER(w.DWORD), ctypes.c_void_p, ctypes.c_void_p],
            w.BOOL,
        ),
        (
            kernel.PeekNamedPipe,
            [
                w.HANDLE,
                w.LPVOID,
                w.DWORD,
                ctypes.POINTER(w.DWORD),
                ctypes.POINTER(w.DWORD),
                ctypes.POINTER(w.DWORD),
            ],
            w.BOOL,
        ),
        (
            kernel.ReadFile,
            [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID],
            w.BOOL,
        ),
        (
            kernel.WriteFile,
            [w.HANDLE, w.LPCVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID],
            w.BOOL,
        ),
        (kernel.CloseHandle, [w.HANDLE], w.BOOL),
        (kernel.CancelIoEx, [w.HANDLE, w.LPVOID], w.BOOL),
        (
            kernel.GetNamedPipeClientProcessId,
            [w.HANDLE, ctypes.POINTER(w.ULONG)],
            w.BOOL,
        ),
        (
            kernel.GetNamedPipeServerProcessId,
            [w.HANDLE, ctypes.POINTER(w.ULONG)],
            w.BOOL,
        ),
        (kernel.LocalFree, [w.LPVOID], w.LPVOID),
        (
            advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW,
            [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)],
            w.BOOL,
        ),
    )
    for fn, args, result in signatures:
        fn.argtypes = args
        fn.restype = result
    return kernel, advapi


def _check(ok: Any) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _validate_name(name: str) -> str:
    prefix = "\\\\.\\pipe\\"
    suffix = name[len(prefix) :] if isinstance(name, str) else ""
    if (
        not isinstance(name, str)
        or not name.startswith(prefix)
        or len(name) > 240
        or not suffix
        or not suffix.isascii()
        or any(not (char.isalnum() or char in "-_.") for char in suffix)
    ):
        raise ValueError("Windows named-pipe name invalid")
    return name


def process_identity_matches(
    actual: Mapping[str, Any], expected: Mapping[str, Any]
) -> bool:
    """Compare every OS identity field used at the local IPC boundary."""
    return all(
        actual.get(name) == expected.get(name)
        for name in ("pid", "created_filetime", "user_sid", "integrity_rid")
    )


class NamedPipeHandle:
    def __init__(self, handle: Any) -> None:
        self.handle = handle
        self._closed = False
        self._close_attempted = False
        self._close_unconfirmed = False
        self._close_lock = threading.Lock()
        kernel, _ = _apis()
        mode = w.DWORD(0x00000001)  # PIPE_NOWAIT bounds hostile partial messages.
        try:
            _check(
                kernel.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None)
            )
        except Exception as setup_error:
            self._close_attempted = True
            try:
                closed = kernel.CloseHandle(handle)
            except Exception as close_error:
                self._close_unconfirmed = True
                error = OSError("named-pipe handle close was not confirmed")
                error.handle = handle
                error.close_unconfirmed = True
                raise error from close_error
            if not closed:
                self._close_unconfirmed = True
                error = ctypes.WinError(ctypes.get_last_error())
                error.handle = handle
                error.close_unconfirmed = True
                raise error from setup_error
            self.handle = None
            self._closed = True
            raise

    def _read_exact(self, count: int) -> bytes:
        kernel, _ = _apis()
        chunks = bytearray()
        deadline = time.monotonic() + _PIPE_READ_TIMEOUT
        while len(chunks) < count:
            available = w.DWORD()
            _check(
                kernel.PeekNamedPipe(
                    self.handle, None, 0, None, ctypes.byref(available), None
                )
            )
            if available.value == 0:
                if time.monotonic() >= deadline:
                    raise TimeoutError("named-pipe read timed out")
                time.sleep(0.005)
                continue
            buffer = ctypes.create_string_buffer(
                min(count - len(chunks), available.value)
            )
            read = w.DWORD()
            if not kernel.ReadFile(
                self.handle, buffer, len(buffer), ctypes.byref(read), None
            ):
                if ctypes.get_last_error() == _ERROR_NO_DATA:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("named-pipe read timed out")
                    continue
                _check(False)
            if read.value == 0:
                raise EOFError("named-pipe peer closed")
            chunks.extend(buffer.raw[: read.value])
        return bytes(chunks)

    def receive(self) -> dict[str, Any]:
        size = struct.unpack("<I", self._read_exact(4))[0]
        if not 0 < size <= _MAX_MESSAGE:
            raise PermissionError("named-pipe message size invalid")
        try:
            value = json.loads(self._read_exact(size))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError("named-pipe message invalid") from exc
        if not isinstance(value, dict):
            raise PermissionError("named-pipe message invalid")
        return value

    def send(self, value: Mapping[str, Any]) -> None:
        try:
            raw = json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        except (TypeError, ValueError) as exc:
            raise PermissionError("named-pipe message invalid") from exc
        if not raw or len(raw) > _MAX_MESSAGE:
            raise PermissionError("named-pipe message size invalid")
        kernel, _ = _apis()
        remaining = memoryview(struct.pack("<I", len(raw)) + raw)
        while remaining:
            buffer = ctypes.create_string_buffer(bytes(remaining))
            written = w.DWORD()
            _check(
                kernel.WriteFile(
                    self.handle, buffer, len(buffer), ctypes.byref(written), None
                )
            )
            if written.value == 0:
                raise OSError("named-pipe write failed")
            remaining = remaining[written.value :]

    def client_identity(self) -> dict[str, int | str]:
        kernel, _ = _apis()
        pid = w.ULONG()
        _check(kernel.GetNamedPipeClientProcessId(self.handle, ctypes.byref(pid)))
        return process_identity(int(pid.value))

    def server_identity(self) -> dict[str, int | str]:
        kernel, _ = _apis()
        pid = w.ULONG()
        _check(kernel.GetNamedPipeServerProcessId(self.handle, ctypes.byref(pid)))
        return process_identity(int(pid.value))

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            if self._close_attempted:
                raise OSError("named-pipe handle close is unconfirmed")
            self._close_attempted = True
            kernel, _ = _apis()
            try:
                closed = kernel.CloseHandle(self.handle)
            except Exception as exc:
                self._close_unconfirmed = True
                raise OSError("named-pipe handle close was not confirmed") from exc
            if not closed:
                self._close_unconfirmed = True
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = None
            self._closed = True

    def __enter__(self) -> NamedPipeHandle:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class NamedPipeServer:
    """Create one non-inheritable instance, ACLed to its owner and SYSTEM."""

    def __init__(self, name: str) -> None:
        self.name = _validate_name(name)
        self._closed = False
        self._close_attempted = False
        self._close_unconfirmed = False
        self._cancel_attempted = False
        self._state_lock = threading.Lock()
        self._handle: Any = None
        kernel, advapi = _apis()
        sid = process_identity(os.getpid())["user_sid"]
        descriptor = w.LPVOID()
        _check(
            advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"D:P(A;;GA;;;SY)(A;;GA;;;{sid})",
                1,
                ctypes.byref(descriptor),
                None,
            )
        )
        attrs = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), descriptor, False
        )
        try:
            handle = kernel.CreateNamedPipeW(
                self.name,
                0x00000003 | 0x00080000,  # PIPE_ACCESS_DUPLEX | FIRST_INSTANCE
                0x00000000 | 0x00000000 | 0x00000000 | 0x00000008,
                1,
                _MAX_MESSAGE + 4,
                _MAX_MESSAGE + 4,
                0,
                ctypes.byref(attrs),
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise ctypes.WinError(ctypes.get_last_error())
            self._handle = handle
        finally:
            kernel.LocalFree(descriptor)

    def accept(self) -> NamedPipeHandle:
        with self._state_lock:
            if self._closed or self._close_attempted or self._handle is None:
                raise OSError("named-pipe server is closed")
            handle = self._handle
        kernel, _ = _apis()
        if not kernel.ConnectNamedPipe(handle, None):
            error = ctypes.get_last_error()
            if error != _ERROR_PIPE_CONNECTED:
                raise ctypes.WinError(error)
        with self._state_lock:
            if self._closed or self._close_attempted or self._handle != handle:
                raise OSError("named-pipe server closed during accept")
            try:
                connection = NamedPipeHandle(handle)
            except Exception as exc:
                if getattr(exc, "close_unconfirmed", False):
                    self._close_attempted = True
                    self._close_unconfirmed = True
                else:
                    # The constructor closed this acquired handle on failure.
                    self._handle = None
                raise
            self._handle = None
            return connection

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            if self._close_unconfirmed or self._close_attempted:
                raise OSError("named-pipe server close is unconfirmed")
            if self._handle is None:
                self._closed = True
                return
            handle = self._handle
            self._close_attempted = True
            self._cancel_attempted = True
        kernel, _ = _apis()
        try:
            cancelled = kernel.CancelIoEx(handle, None)
        except Exception as exc:
            with self._state_lock:
                self._close_unconfirmed = True
            raise OSError("named-pipe pending I/O cancellation failed") from exc
        if not cancelled:
            error = ctypes.get_last_error()
            if error != 1168:  # ERROR_NOT_FOUND: no pending I/O to cancel.
                with self._state_lock:
                    self._close_unconfirmed = True
                raise ctypes.WinError(error)
        try:
            closed = kernel.CloseHandle(handle)
        except Exception as exc:
            with self._state_lock:
                self._close_unconfirmed = True
            raise OSError("named-pipe server close was not confirmed") from exc
        if not closed:
            with self._state_lock:
                self._close_unconfirmed = True
            raise ctypes.WinError(ctypes.get_last_error())
        with self._state_lock:
            self._handle = None
            self._closed = True


def connect_named_pipe(
    name: str,
    *,
    expected_server_pid: int,
    expected_server_created_filetime: int,
    timeout: float = 5.0,
) -> NamedPipeHandle:
    """Connect and pin the server to its Host-owned PID and creation time."""
    name = _validate_name(name)
    if (
        type(expected_server_pid) is not int
        or expected_server_pid <= 0
        or type(expected_server_created_filetime) is not int
        or expected_server_created_filetime <= 0
        or not 0 < timeout <= 30
    ):
        raise ValueError("Windows named-pipe server identity invalid")
    kernel, _ = _apis()
    deadline = time.monotonic() + timeout
    while True:
        handle = kernel.CreateFileW(name, 0xC0000000, 0, None, 3, 0x00000080, None)
        if handle != _INVALID_HANDLE_VALUE:
            connection = NamedPipeHandle(handle)
            try:
                actual = connection.server_identity()
                caller = process_identity(os.getpid())
                expected = {
                    "pid": expected_server_pid,
                    "created_filetime": expected_server_created_filetime,
                    "user_sid": caller["user_sid"],
                    "integrity_rid": caller["integrity_rid"],
                }
                if not process_identity_matches(actual, expected):
                    raise PermissionError("Windows named-pipe server identity mismatch")
                return connection
            except Exception:
                connection.close()
                raise
        error = ctypes.get_last_error()
        remaining = deadline - time.monotonic()
        if error not in (_ERROR_FILE_NOT_FOUND, _ERROR_PIPE_BUSY) or remaining <= 0:
            raise PermissionError("Windows named-pipe host unavailable") from None
        kernel.WaitNamedPipeW(name, max(1, min(100, int(remaining * 1000))))


def pipe_client_identity(handle: NamedPipeHandle) -> dict[str, int | str]:
    return handle.client_identity()


__all__ = [
    "NamedPipeHandle",
    "NamedPipeServer",
    "connect_named_pipe",
    "pipe_client_identity",
    "process_identity_matches",
]
