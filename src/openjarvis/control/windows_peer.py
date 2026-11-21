"""Bind a loopback TCP peer to its Windows process and token identity."""

from __future__ import annotations

import ctypes
import os
import socket
import struct
from ctypes import wintypes as w
from functools import lru_cache
from typing import Any

_WAIT_TIMEOUT = 0x00000102


def _wait_result_is_running(result: int) -> bool:
    return result == _WAIT_TIMEOUT


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", w.LPVOID), ("attributes", w.DWORD)]


class _TcpRowOwnerPid(ctypes.Structure):
    _fields_ = [
        ("state", w.DWORD),
        ("local_addr", w.DWORD),
        ("local_port", w.DWORD),
        ("remote_addr", w.DWORD),
        ("remote_port", w.DWORD),
        ("pid", w.DWORD),
    ]


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("size", w.DWORD),
        ("usage", w.DWORD),
        ("process_id", w.DWORD),
        ("default_heap_id", ctypes.c_size_t),
        ("module_id", w.DWORD),
        ("threads", w.DWORD),
        ("parent_process_id", w.DWORD),
        ("base_priority", w.LONG),
        ("flags", w.DWORD),
        ("executable", w.WCHAR * 260),
    ]


@lru_cache(maxsize=1)
def _apis() -> tuple[Any, Any, Any]:
    if os.name != "nt":
        raise PermissionError("Windows TCP peer identity is unavailable")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
    for function, args, result in (
        (kernel.OpenProcess, [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
        (kernel.CloseHandle, [w.HANDLE], w.BOOL),
        (kernel.LocalFree, [w.LPVOID], w.LPVOID),
        (kernel.GetProcessTimes, [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4, w.BOOL),
        (kernel.WaitForSingleObject, [w.HANDLE, w.DWORD], w.DWORD),
        (kernel.CreateToolhelp32Snapshot, [w.DWORD, w.DWORD], w.HANDLE),
        (kernel.Process32FirstW, [w.HANDLE, ctypes.POINTER(_ProcessEntry32W)], w.BOOL),
        (kernel.Process32NextW, [w.HANDLE, ctypes.POINTER(_ProcessEntry32W)], w.BOOL),
        (
            security.OpenProcessToken,
            [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)],
            w.BOOL,
        ),
        (
            security.GetTokenInformation,
            [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)],
            w.BOOL,
        ),
        (security.ConvertSidToStringSidW, [w.LPVOID, ctypes.POINTER(w.LPWSTR)], w.BOOL),
        (security.GetSidSubAuthorityCount, [w.LPVOID], ctypes.POINTER(w.BYTE)),
        (security.GetSidSubAuthority, [w.LPVOID, w.DWORD], ctypes.POINTER(w.DWORD)),
        (
            iphlp.GetExtendedTcpTable,
            [w.LPVOID, ctypes.POINTER(w.DWORD), w.BOOL, w.ULONG, ctypes.c_int, w.ULONG],
            w.DWORD,
        ),
    ):
        function.argtypes = args
        function.restype = result
    return kernel, security, iphlp


def _check(ok: Any) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())


def _close_handle(kernel: Any, handle: Any, label: str) -> None:
    try:
        closed = kernel.CloseHandle(handle)
    except Exception as exc:
        raise PermissionError(f"Windows {label} handle close failed") from exc
    if not closed:
        raise PermissionError(f"Windows {label} handle close was not confirmed")


def _token_buffer(security: Any, token: Any, information_class: int) -> Any:
    size = w.DWORD()
    security.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
    if not 0 < size.value <= 65536:
        raise PermissionError("Windows process token information unavailable")
    data = ctypes.create_string_buffer(size.value)
    _check(
        security.GetTokenInformation(
            token, information_class, data, size, ctypes.byref(size)
        )
    )
    return data


def process_identity(pid: int) -> dict[str, int | str]:
    """Return PID, creation time, token SID and integrity RID; fail closed."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        raise PermissionError("Windows process identity is invalid")
    kernel, security, _ = _apis()
    process = kernel.OpenProcess(0x00101000, False, pid)  # QUERY_LIMITED | SYNCHRONIZE
    if not process:
        raise PermissionError("Windows process identity unavailable")
    token = w.HANDLE()
    try:
        _check(security.OpenProcessToken(process, 0x0008, ctypes.byref(token)))
        times = [w.FILETIME() for _ in range(4)]
        _check(kernel.GetProcessTimes(process, *(ctypes.byref(item) for item in times)))
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        user = _token_buffer(security, token, 1)
        user_sid = ctypes.cast(user, ctypes.POINTER(_SidAndAttributes)).contents.sid
        sid_text = w.LPWSTR()
        _check(security.ConvertSidToStringSidW(user_sid, ctypes.byref(sid_text)))
        try:
            sid = sid_text.value
        finally:
            kernel.LocalFree(sid_text)
        integrity = _token_buffer(security, token, 25)
        integrity_sid = ctypes.cast(
            integrity, ctypes.POINTER(_SidAndAttributes)
        ).contents.sid
        count = security.GetSidSubAuthorityCount(integrity_sid)
        if not count or count.contents.value == 0:
            raise PermissionError("Windows process integrity unavailable")
        level = security.GetSidSubAuthority(integrity_sid, count.contents.value - 1)
        if not level:
            raise PermissionError("Windows process integrity unavailable")
        if not _wait_result_is_running(kernel.WaitForSingleObject(process, 0)):
            raise PermissionError("Windows peer exited during authentication")
        return {
            "pid": pid,
            "created_filetime": created,
            "user_sid": sid,
            "integrity_rid": level.contents.value,
        }
    finally:
        close_errors = []
        if token.value:
            try:
                _close_handle(kernel, token, "process token")
            except PermissionError as exc:
                close_errors.append(exc)
        try:
            _close_handle(kernel, process, "process identity")
        except PermissionError as exc:
            close_errors.append(exc)
        if close_errors:
            raise PermissionError(
                "Windows process identity handles were not fully released"
            ) from close_errors[0]


def _tcp_peer_pid(connection: socket.socket) -> int:
    if os.name != "nt" or connection.family != socket.AF_INET:
        raise PermissionError("Windows IPv4 peer identity is unavailable")
    _, _, iphlp = _apis()
    local, remote = connection.getsockname(), connection.getpeername()
    if local[0] != "127.0.0.1" or remote[0] != "127.0.0.1":
        raise PermissionError("Supervisor connection is not loopback")
    function = iphlp.GetExtendedTcpTable
    for _ in range(3):
        size = w.DWORD()
        code = function(None, ctypes.byref(size), False, 2, 5, 0)
        if code not in (0, 122):
            raise PermissionError("Windows TCP peer table unavailable")
        table = ctypes.create_string_buffer(size.value)
        code = function(table, ctypes.byref(size), False, 2, 5, 0)
        if code == 122:
            continue
        if code != 0:
            raise PermissionError("Windows TCP peer table unavailable")
        count = ctypes.cast(table, ctypes.POINTER(w.DWORD)).contents.value
        if count > (size.value - ctypes.sizeof(w.DWORD)) // ctypes.sizeof(
            _TcpRowOwnerPid
        ):
            raise PermissionError("Windows TCP peer table is malformed")
        matches = []
        for index in range(count):
            row = _TcpRowOwnerPid.from_buffer(
                table, ctypes.sizeof(w.DWORD) + index * ctypes.sizeof(_TcpRowOwnerPid)
            )
            local_addr = socket.inet_ntoa(struct.pack("=I", row.local_addr))
            remote_addr = socket.inet_ntoa(struct.pack("=I", row.remote_addr))
            local_port = socket.ntohs(row.local_port & 0xFFFF)
            remote_port = socket.ntohs(row.remote_port & 0xFFFF)
            if (
                row.state == 5
                and local_addr == remote[0]
                and local_port == remote[1]
                and remote_addr == local[0]
                and remote_port == local[1]
            ):
                matches.append(row.pid)
        if len(matches) == 1:
            return matches[0]
        raise PermissionError("Windows TCP peer process unavailable")
    raise PermissionError("Windows TCP peer process unavailable")


def tcp_peer_process_identity(connection: socket.socket) -> dict[str, int | str]:
    return process_identity(_tcp_peer_pid(connection))


def parent_process_id(pid: int) -> int:
    """Return a live process's parent PID from a bounded OS snapshot."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        raise PermissionError("Windows process parent is unavailable")
    kernel, _, _ = _apis()
    snapshot = kernel.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise PermissionError("Windows process snapshot unavailable")
    try:
        row = _ProcessEntry32W()
        row.size = ctypes.sizeof(row)
        if not kernel.Process32FirstW(snapshot, ctypes.byref(row)):
            raise PermissionError("Windows process snapshot unavailable")
        while True:
            if row.process_id == pid:
                return int(row.parent_process_id)
            if not kernel.Process32NextW(snapshot, ctypes.byref(row)):
                break
        raise PermissionError("Windows process parent unavailable")
    finally:
        _close_handle(kernel, snapshot, "process snapshot")


def is_process_descendant(
    pid: int,
    ancestor: dict[str, int | str],
    *,
    max_depth: int = 16,
) -> bool:
    """Pin a peer to a Host-launched process tree, checking each PID's age."""
    if (
        type(max_depth) is not int
        or not 1 <= max_depth <= 64
        or type(pid) is not int
        or pid <= 0
        or type(ancestor.get("pid")) is not int
    ):
        return False
    try:
        expected = process_identity(int(ancestor["pid"]))
        if expected != ancestor:
            return False
        current_pid = pid
        current_identity = process_identity(current_pid)
        seen = {current_pid}
        for _ in range(max_depth):
            if current_pid == expected["pid"]:
                return current_identity == expected
            parent_pid = parent_process_id(current_pid)
            if parent_pid <= 0 or parent_pid in seen:
                return False
            parent_identity = process_identity(parent_pid)
            # A reused parent PID cannot have been created after its child.
            if (
                parent_identity["created_filetime"]
                > current_identity["created_filetime"]
            ):
                return False
            if parent_pid == expected["pid"]:
                return parent_identity == expected
            if (
                parent_identity["user_sid"] != expected["user_sid"]
                or parent_identity["integrity_rid"] != expected["integrity_rid"]
            ):
                return False
            seen.add(parent_pid)
            current_pid = parent_pid
            current_identity = parent_identity
        return False
    except Exception:
        return False
