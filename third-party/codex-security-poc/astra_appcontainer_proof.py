"""Standalone Windows AppContainer isolation proof harness.

This file intentionally does not import OpenJarvis or connect to RLMWorker.
It stages a temporary Python runtime, creates temporary AppContainer profiles,
and exercises only temporary files, processes, ACLs, and named pipes.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid


if os.name != "nt":
    raise SystemExit("This proof harness requires Windows.")


# Win32 constants used by the harness.
ERROR_ACCESS_DENIED = 5
ERROR_BROKEN_PIPE = 109
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_PIPE_CONNECTED = 535
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
INFINITE = 0xFFFFFFFF
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
CRASH_EXIT_CODE = 0xC0DE

TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_IS_APP_CONTAINER = 29
TOKEN_CAPABILITIES = 30
TOKEN_APP_CONTAINER_SID = 31

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

LOW_INTEGRITY_RID = 0x1000
MEDIUM_INTEGRITY_RID = 0x2000
HIGH_INTEGRITY_RID = 0x3000
SYSTEM_INTEGRITY_RID = 0x4000

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SDDL_REVISION_1 = 1


HANDLE = wintypes.HANDLE
LPVOID = ctypes.c_void_p


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_USER_STRUCT(ctypes.Structure):
    _fields_ = [("User", SID_AND_ATTRIBUTES)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class TOKEN_APPCONTAINER_INFORMATION(ctypes.Structure):
    _fields_ = [("TokenAppContainer", LPVOID)]


class TOKEN_GROUPS_ONE(ctypes.Structure):
    _fields_ = [
        ("GroupCount", wintypes.DWORD),
        ("Groups", SID_AND_ATTRIBUTES * 1),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", LPVOID),
        ("Capabilities", LPVOID),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", LPVOID),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)

kernel32.GetCurrentProcess.restype = HANDLE
kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [LPVOID]
kernel32.LocalFree.restype = LPVOID
kernel32.GetLastError.restype = wintypes.DWORD
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = HANDLE
kernel32.TerminateProcess.argtypes = [HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.ResumeThread.argtypes = [HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    LPVOID,
    LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    LPVOID,
    wintypes.LPCWSTR,
    LPVOID,
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.InitializeProcThreadAttributeList.argtypes = [
    LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
kernel32.UpdateProcThreadAttribute.argtypes = [
    LPVOID,
    wintypes.DWORD,
    ctypes.c_size_t,
    LPVOID,
    ctypes.c_size_t,
    LPVOID,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
kernel32.DeleteProcThreadAttributeList.argtypes = [LPVOID]
kernel32.DeleteProcThreadAttributeList.restype = None
kernel32.CreateNamedPipeW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
]
kernel32.CreateNamedPipeW.restype = HANDLE
kernel32.ConnectNamedPipe.argtypes = [HANDLE, LPVOID]
kernel32.ConnectNamedPipe.restype = wintypes.BOOL
kernel32.DisconnectNamedPipe.argtypes = [HANDLE]
kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    HANDLE,
    LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    HANDLE,
    LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    LPVOID,
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.PeekNamedPipe.argtypes = [
    HANDLE,
    LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.PeekNamedPipe.restype = wintypes.BOOL
kernel32.CreateJobObjectW.argtypes = [LPVOID, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = HANDLE
kernel32.SetInformationJobObject.argtypes = [
    HANDLE,
    wintypes.INT,
    LPVOID,
    wintypes.DWORD,
]
kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
kernel32.TerminateJobObject.argtypes = [HANDLE, wintypes.UINT]
kernel32.TerminateJobObject.restype = wintypes.BOOL
kernel32.IsProcessInJob.argtypes = [HANDLE, HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.IsProcessInJob.restype = wintypes.BOOL

advapi32.OpenProcessToken.argtypes = [HANDLE, wintypes.DWORD, ctypes.POINTER(HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    HANDLE,
    wintypes.INT,
    LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(LPVOID),
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
    wintypes.BOOL
)
advapi32.GetSidSubAuthorityCount.argtypes = [LPVOID]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthority.argtypes = [LPVOID, wintypes.DWORD]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
advapi32.GetSecurityDescriptorDacl.argtypes = [
    LPVOID,
    ctypes.POINTER(wintypes.BOOL),
    ctypes.POINTER(LPVOID),
    ctypes.POINTER(wintypes.BOOL),
]
advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
advapi32.SetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    LPVOID,
    LPVOID,
    LPVOID,
    LPVOID,
]
advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
advapi32.FreeSid.argtypes = [LPVOID]
advapi32.FreeSid.restype = LPVOID

userenv.CreateAppContainerProfile.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(LPVOID),
]
userenv.CreateAppContainerProfile.restype = ctypes.c_long
userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
userenv.DeleteAppContainerProfile.restype = ctypes.c_long


class PocError(RuntimeError):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


def error_code(exc: BaseException) -> int | None:
    return getattr(exc, "winerror", None) or getattr(exc, "errno", None)


def win_error(message: str, code: int | None = None) -> PocError:
    if code is None:
        code = ctypes.get_last_error()
    return PocError(f"{message}: winerror={code}", code)


def close_handle(handle: HANDLE | None) -> None:
    if handle and handle_value(handle) not in (0, INVALID_HANDLE_VALUE):
        kernel32.CloseHandle(handle)


def handle_value(handle: HANDLE | int | None) -> int:
    if handle is None:
        return 0
    value = getattr(handle, "value", handle)
    return 0 if value is None else int(value)


def sid_to_string(sid: LPVOID) -> str:
    if not sid:
        raise PocError("null SID")
    out = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(out)):
        raise win_error("ConvertSidToStringSidW failed")
    try:
        return out.value
    finally:
        kernel32.LocalFree(out)


def token_information(token: HANDLE, info_class: int) -> ctypes.Array:
    needed = wintypes.DWORD()
    advapi32.GetTokenInformation(
        token, info_class, None, 0, ctypes.byref(needed)
    )
    first_error = ctypes.get_last_error()
    if needed.value == 0 and first_error != ERROR_INSUFFICIENT_BUFFER:
        raise win_error(
            f"GetTokenInformation({info_class}) size query failed", first_error
        )
    buffer = ctypes.create_string_buffer(max(needed.value, 1))
    if not advapi32.GetTokenInformation(
        token,
        info_class,
        buffer,
        len(buffer),
        ctypes.byref(needed),
    ):
        raise win_error(
            f"GetTokenInformation({info_class}) failed", ctypes.get_last_error()
        )
    return buffer


def group_sids(buffer: ctypes.Array) -> list[str]:
    group_count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    base = ctypes.addressof(buffer) + TOKEN_GROUPS_ONE.Groups.offset
    stride = ctypes.sizeof(SID_AND_ATTRIBUTES)
    result: list[str] = []
    for index in range(group_count):
        entry = SID_AND_ATTRIBUTES.from_buffer_copy(
            buffer, TOKEN_GROUPS_ONE.Groups.offset + index * stride
        )
        result.append(sid_to_string(entry.Sid))
    return result


def token_evidence(token: HANDLE) -> dict[str, object]:
    is_app = ctypes.cast(
        token_information(token, TOKEN_IS_APP_CONTAINER),
        ctypes.POINTER(wintypes.DWORD),
    ).contents.value
    app_info = TOKEN_APPCONTAINER_INFORMATION.from_buffer_copy(
        token_information(token, TOKEN_APP_CONTAINER_SID)
    )
    app_sid = sid_to_string(app_info.TokenAppContainer) if app_info.TokenAppContainer else ""
    label = TOKEN_MANDATORY_LABEL.from_buffer_copy(
        token_information(token, TOKEN_INTEGRITY_LEVEL)
    )
    sid_count = advapi32.GetSidSubAuthorityCount(label.Label.Sid)
    rid = advapi32.GetSidSubAuthority(
        label.Label.Sid, sid_count[0] - 1
    )[0]
    integrity = {
        LOW_INTEGRITY_RID: "low",
        MEDIUM_INTEGRITY_RID: "medium",
        HIGH_INTEGRITY_RID: "high",
        SYSTEM_INTEGRITY_RID: "system",
    }.get(rid, f"rid:{rid}")
    capabilities = group_sids(token_information(token, TOKEN_CAPABILITIES))
    return {
        "appcontainer": bool(is_app),
        "appcontainer_sid": app_sid,
        "integrity": integrity,
        "capabilities": capabilities,
    }


def current_user_sid() -> str:
    token = HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        raise win_error("OpenProcessToken(current) failed")
    try:
        user = TOKEN_USER_STRUCT.from_buffer_copy(
            token_information(token, TOKEN_USER)
        )
        return sid_to_string(user.User.Sid)
    finally:
        close_handle(token)


def process_evidence(process: HANDLE, job: HANDLE | None = None) -> dict[str, object]:
    token = HANDLE()
    if not advapi32.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
        raise win_error("OpenProcessToken(worker) failed")
    try:
        result = token_evidence(token)
        in_job = wintypes.BOOL()
        if not kernel32.IsProcessInJob(process, job, ctypes.byref(in_job)):
            raise win_error("IsProcessInJob failed")
        result["job"] = bool(in_job.value)
        return result
    finally:
        close_handle(token)


def make_security_descriptor(sddl: str) -> tuple[LPVOID, LPVOID]:
    descriptor = LPVOID()
    size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(size),
    ):
        raise win_error("ConvertStringSecurityDescriptor failed")
    present = wintypes.BOOL()
    dacl = LPVOID()
    defaulted = wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorDacl(
        descriptor,
        ctypes.byref(present),
        ctypes.byref(dacl),
        ctypes.byref(defaulted),
    ):
        kernel32.LocalFree(descriptor)
        raise win_error("GetSecurityDescriptorDacl failed")
    return descriptor, dacl


def set_path_acl(path: Path, sddl: str) -> None:
    descriptor, dacl = make_security_descriptor(sddl)
    try:
        result = advapi32.SetNamedSecurityInfoW(
            str(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if result != 0:
            raise win_error("SetNamedSecurityInfoW failed", result)
    finally:
        kernel32.LocalFree(descriptor)


def create_profile(name: str) -> tuple[LPVOID, str]:
    sid = LPVOID()
    hr = userenv.CreateAppContainerProfile(
        name,
        "Astra Proof Harness",
        "Temporary AppContainer isolation proof",
        None,
        0,
        ctypes.byref(sid),
    )
    if hr != 0:
        value = ctypes.c_uint32(hr).value
        raise PocError(f"CreateAppContainerProfile failed: hresult=0x{value:08x}", value)
    return sid, sid_to_string(sid)


def delete_profile(name: str, sid: LPVOID) -> None:
    hr = userenv.DeleteAppContainerProfile(name)
    if hr != 0:
        value = ctypes.c_uint32(hr).value
        raise PocError(f"DeleteAppContainerProfile failed: hresult=0x{value:08x}", value)
    advapi32.FreeSid(sid)


def pipe_name(tag: str) -> str:
    return rf"\\.\pipe\LOCAL\AstraPoc-{tag}-{uuid.uuid4().hex[:10]}"


def create_named_pipe(name: str, host_sid: str, allowed_sids: list[str]) -> HANDLE:
    app_aces = "".join(f"(A;;GRGW;;;{sid})" for sid in allowed_sids)
    sddl = f"D:P(A;;FA;;;{host_sid}){app_aces}"
    descriptor, _ = make_security_descriptor(sddl)
    attributes = SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(attributes)
    attributes.lpSecurityDescriptor = descriptor
    attributes.bInheritHandle = False
    handle = kernel32.CreateNamedPipeW(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE
        | PIPE_READMODE_MESSAGE
        | PIPE_WAIT
        | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        65536,
        65536,
        5000,
        ctypes.byref(attributes),
    )
    kernel32.LocalFree(descriptor)
    if handle_value(handle) in (0, INVALID_HANDLE_VALUE):
        raise win_error("CreateNamedPipeW failed")
    return handle


def connect_named_pipe(handle: HANDLE, result: dict[str, object], event: threading.Event) -> None:
    ok = kernel32.ConnectNamedPipe(handle, None)
    if ok:
        result["ok"] = True
    else:
        code = ctypes.get_last_error()
        result["ok"] = code == ERROR_PIPE_CONNECTED
        result["error"] = code
    event.set()


def pipe_write(handle: HANDLE, message: str) -> None:
    data = (message + "\n").encode("utf-8")
    buffer = ctypes.create_string_buffer(data)
    written = wintypes.DWORD()
    if not kernel32.WriteFile(
        handle, buffer, len(data), ctypes.byref(written), None
    ):
        raise win_error("WriteFile(pipe) failed")
    if written.value != len(data):
        raise PocError("WriteFile(pipe) was short")


def pipe_read(handle: HANDLE, process: HANDLE, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        available = wintypes.DWORD()
        if not kernel32.PeekNamedPipe(
            handle, None, 0, None, ctypes.byref(available), None
        ):
            code = ctypes.get_last_error()
            if code == ERROR_BROKEN_PIPE:
                raise PocError("named pipe closed", code)
            raise win_error("PeekNamedPipe failed", code)
        if available.value:
            buffer = ctypes.create_string_buffer(available.value)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                handle,
                buffer,
                available.value,
                ctypes.byref(read),
                None,
            ):
                raise win_error("ReadFile(pipe) failed")
            return bytes(buffer.raw[: read.value]).decode("utf-8").strip()
        if kernel32.WaitForSingleObject(process, 0) == WAIT_OBJECT_0:
            raise PocError("worker exited before sending pipe data")
        time.sleep(0.01)
    raise PocError("pipe read timeout", WAIT_TIMEOUT)


def create_attribute_list(app_sid: LPVOID) -> tuple[STARTUPINFOEX, ctypes.Array, SECURITY_CAPABILITIES]:
    required = ctypes.c_size_t()
    kernel32.InitializeProcThreadAttributeList(
        None, 1, 0, ctypes.byref(required)
    )
    if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        raise win_error("InitializeProcThreadAttributeList size query failed")
    storage = ctypes.create_string_buffer(required.value)
    if not kernel32.InitializeProcThreadAttributeList(
        storage, 1, 0, ctypes.byref(required)
    ):
        raise win_error("InitializeProcThreadAttributeList failed")
    capabilities = SECURITY_CAPABILITIES(app_sid, None, 0, 0)
    if not kernel32.UpdateProcThreadAttribute(
        storage,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(capabilities),
        ctypes.sizeof(capabilities),
        None,
        None,
    ):
        kernel32.DeleteProcThreadAttributeList(storage)
        raise win_error("UpdateProcThreadAttribute failed")
    startup = STARTUPINFOEX()
    startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
    startup.lpAttributeList = ctypes.cast(storage, LPVOID)
    return startup, storage, capabilities


def build_environment(values: dict[str, str], current_directory: Path) -> ctypes.Array:
    # Custom Unicode blocks need sorted entries and the current-drive entry.
    entries = dict(values)
    entries[f"={current_directory.drive.upper()}"] = str(current_directory)
    block = "".join(
        f"{key}={value}\0"
        for key, value in sorted(entries.items(), key=lambda item: item[0].upper())
    ) + "\0"
    return ctypes.create_unicode_buffer(block)


def create_job() -> HANDLE:
    job = kernel32.CreateJobObjectW(None, None)
    if not job or handle_value(job) in (0, INVALID_HANDLE_VALUE):
        raise win_error("CreateJobObjectW failed")
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    limits.BasicLimitInformation.ActiveProcessLimit = 4
    if not kernel32.SetInformationJobObject(
        job,
        JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        code = ctypes.get_last_error()
        close_handle(job)
        raise win_error("SetInformationJobObject failed", code)
    return job


class LaunchedProcess:
    def __init__(self, process: HANDLE, thread: HANDLE, job: HANDLE):
        self.process = process
        self.thread = thread
        self.job = job

    def resume(self) -> None:
        result = kernel32.ResumeThread(self.thread)
        if result == 0xFFFFFFFF:
            raise win_error("ResumeThread failed")

    def wait(self, timeout_ms: int) -> bool:
        return kernel32.WaitForSingleObject(self.process, timeout_ms) == WAIT_OBJECT_0

    def exit_code(self) -> int:
        result = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(self.process, ctypes.byref(result)):
            raise win_error("GetExitCodeProcess failed")
        return result.value

    def kill(self) -> None:
        if self.job and handle_value(self.job) not in (0, INVALID_HANDLE_VALUE):
            kernel32.TerminateJobObject(self.job, 0xD0)

    def close(self, kill: bool = False) -> None:
        if kill:
            self.kill()
        close_handle(self.thread)
        close_handle(self.process)
        close_handle(self.job)
        self.thread = HANDLE()
        self.process = HANDLE()
        self.job = HANDLE()


def launch_appcontainer(
    app_sid: LPVOID,
    python_exe: Path,
    script: Path,
    args: list[str],
    environment: dict[str, str],
    current_directory: Path,
) -> LaunchedProcess:
    startup, attribute_storage, _ = create_attribute_list(app_sid)
    job = create_job()
    command = subprocess.list2cmdline(
        [str(python_exe), "-S", str(script), *args]
    )
    command_buffer = ctypes.create_unicode_buffer(command)
    env_buffer = build_environment(environment, current_directory)
    process_info = PROCESS_INFORMATION()
    try:
        flags = (
            EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_SUSPENDED
        )
        if not kernel32.CreateProcessW(
            str(python_exe),
            command_buffer,
            None,
            None,
            False,
            flags,
            ctypes.cast(env_buffer, LPVOID),
            str(current_directory),
            ctypes.byref(startup),
            ctypes.byref(process_info),
        ):
            raise win_error("CreateProcessW AppContainer failed")
        launched = LaunchedProcess(
            process_info.hProcess, process_info.hThread, job
        )
        if not kernel32.AssignProcessToJobObject(job, launched.process):
            code = ctypes.get_last_error()
            launched.close(kill=True)
            raise win_error("AssignProcessToJobObject failed", code)
        return launched
    except Exception:
        if process_info.hThread:
            close_handle(process_info.hThread)
        if process_info.hProcess:
            close_handle(process_info.hProcess)
        close_handle(job)
        raise
    finally:
        kernel32.DeleteProcThreadAttributeList(attribute_storage)


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in line.split("|")[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record(
    results: list[dict[str, object]],
    name: str,
    expected: str,
    actual: str,
    status: str,
    evidence: str,
    interpretation: str,
) -> None:
    results.append(
        {
            "test_name": name,
            "expected_behavior": expected,
            "actual_behavior": actual,
            "status": status,
            "windows_evidence": evidence,
            "security_interpretation": interpretation,
        }
    )


def worker_token_evidence() -> dict[str, object]:
    token = HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)
    ):
        raise win_error("worker OpenProcessToken failed")
    try:
        result = token_evidence(token)
        in_job = wintypes.BOOL()
        if not kernel32.IsProcessInJob(
            kernel32.GetCurrentProcess(), None, ctypes.byref(in_job)
        ):
            raise win_error("worker IsProcessInJob failed")
        result["job"] = bool(in_job.value)
        result["pid"] = os.getpid()
        return result
    finally:
        close_handle(token)


def native_read(path: str, access: int = GENERIC_READ) -> tuple[bool, int]:
    handle = kernel32.CreateFileW(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle_value(handle) in (0, INVALID_HANDLE_VALUE):
        return False, ctypes.get_last_error()
    close_handle(handle)
    return True, 0


def python_read(path: str) -> tuple[bool, int]:
    try:
        with open(path, "rb") as handle:
            handle.read()
        return True, 0
    except OSError as exc:
        return False, error_code(exc) or -1


def child_probe(deny_path: str) -> int:
    evidence = worker_token_evidence()
    py_ok, py_error = python_read(deny_path)
    native_ok, native_error = native_read(deny_path)
    expected = (
        evidence["appcontainer"]
        and evidence["integrity"] == "low"
        and evidence["capabilities"] == []
        and evidence["job"]
        and not py_ok
        and py_error == ERROR_ACCESS_DENIED
        and not native_ok
        and native_error == ERROR_ACCESS_DENIED
    )
    return 0 if expected else 1


def worker_create_child(
    python_exe: str,
    script: str,
    deny_path: str,
) -> tuple[bool, int, int]:
    command = subprocess.list2cmdline(
        [python_exe, "-S", script, "--child-probe", deny_path]
    )
    command_buffer = ctypes.create_unicode_buffer(command)
    startup = STARTUPINFO()
    startup.cb = ctypes.sizeof(STARTUPINFO)
    process_info = PROCESS_INFORMATION()
    if not kernel32.CreateProcessW(
        python_exe,
        command_buffer,
        None,
        None,
        False,
        CREATE_UNICODE_ENVIRONMENT,
        None,
        None,
        ctypes.byref(startup),
        ctypes.byref(process_info),
    ):
        return False, -1, ctypes.get_last_error()
    try:
        waited = (
            kernel32.WaitForSingleObject(process_info.hProcess, 5000)
            == WAIT_OBJECT_0
        )
        if not waited:
            kernel32.TerminateProcess(process_info.hProcess, 0xD1)
            return False, -1, WAIT_TIMEOUT
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(
            process_info.hProcess, ctypes.byref(code)
        ):
            return False, -1, ctypes.get_last_error()
        return code.value == 0, code.value, 0
    finally:
        close_handle(process_info.hThread)
        close_handle(process_info.hProcess)


def worker_main(argv: list[str]) -> int:
    values = dict(zip(argv[0::2], argv[1::2]))
    pipe_path = values["--pipe"]
    allow_path = values["--allow"]
    deny_path = values["--deny"]
    python_exe = values["--python"]
    script = values["--script"]
    mode = values.get("--mode", "run")
    pipe = None
    try:
        pipe = open(pipe_path, "r+b", buffering=0)
        evidence = worker_token_evidence()
        pipe.write(
            (
                "TOKEN"
                f"|app={int(evidence['appcontainer'])}"
                f"|sid={evidence['appcontainer_sid']}"
                f"|il={evidence['integrity']}"
                f"|caps={len(evidence['capabilities'])}"
                f"|job={int(evidence['job'])}"
                f"|pid={evidence['pid']}\n"
            ).encode()
        )
        pipe.flush()
        if mode == "crash":
            kernel32.TerminateProcess(kernel32.GetCurrentProcess(), CRASH_EXIT_CODE)
            return 91
        if mode == "hang":
            pipe.write(b"HANG\n")
            pipe.flush()
            while True:
                time.sleep(1)
        command = pipe.readline().decode("utf-8").strip()
        if command != "RUN":
            return 20

        tests = [
            ("python_allow_read", *python_read(allow_path)),
            ("python_deny_read", *python_read(deny_path)),
            ("native_allow_read", *native_read(allow_path)),
            ("native_deny_read", *native_read(deny_path)),
            ("native_allow_write", *native_read(allow_path, GENERIC_WRITE)),
        ]
        for name, ok, code in tests:
            pipe.write(
                f"RESULT|test={name}|ok={int(ok)}|winerr={code}\n".encode()
            )
            pipe.flush()

        child_ok, child_code, child_error = worker_create_child(
            python_exe, script, deny_path
        )
        pipe.write(
            (
                "RESULT|test=child_process"
                f"|ok={int(child_ok)}|winerr={child_error}"
                f"|exit={child_code}\n"
            ).encode()
        )
        pipe.flush()
        pipe.write(b"DONE\n")
        pipe.flush()
        return 0
    except BaseException:
        return 90
    finally:
        if pipe is not None:
            try:
                pipe.close()
            except Exception:
                pass


def pipe_probe(argv: list[str]) -> int:
    pipe_path = argv[0]
    try:
        handle = open(pipe_path, "r+b", buffering=0)
    except OSError as exc:
        return 0 if error_code(exc) == ERROR_ACCESS_DENIED else 20
    else:
        handle.close()
        return 1


def mark_downstream_not_executed(results: list[dict[str, object]], reason: str) -> None:
    existing = {str(item["test_name"]) for item in results}
    for name in (
        "worker_token_verification",
        "named_pipe_ipc",
        "filesystem_allow_python_open",
        "filesystem_deny_python_open",
        "filesystem_allow_win32_createfile",
        "filesystem_deny_win32_createfile",
        "filesystem_native_write_denied",
        "filesystem_write_denied_and_unchanged",
        "child_process_job_isolation",
        "named_pipe_acl_negative",
        "worker_crash_cleanup",
        "job_timeout_cleanup",
    ):
        if name in existing:
            continue
        record(
            results,
            name,
            "proof executes",
            reason,
            "NOT EXECUTED",
            "no process or resource was started for this test",
            "No security conclusion; prerequisite proof was unavailable.",
        )


def run_connected_worker(
    app_sid: LPVOID,
    pipe: HANDLE,
    pipe_path: str,
    python_exe: Path,
    script: Path,
    allow_file: Path,
    deny_file: Path,
    environment: dict[str, str],
    current_directory: Path,
) -> tuple[LaunchedProcess, dict[str, object], list[str], int]:
    process = launch_appcontainer(
        app_sid,
        python_exe,
        script,
        [
            "--worker",
            "--pipe",
            pipe_path,
            "--allow",
            str(allow_file),
            "--deny",
            str(deny_file),
            "--python",
            str(python_exe),
            "--script",
            str(script),
            "--mode",
            "run",
        ],
        environment,
        current_directory,
    )
    try:
        host_evidence = process_evidence(process.process, process.job)
        connection_result: dict[str, object] = {}
        connected = threading.Event()
        connector = threading.Thread(
            target=connect_named_pipe,
            args=(pipe, connection_result, connected),
            daemon=True,
        )
        connector.start()
        process.resume()
        if not connected.wait(10):
            process.close(kill=True)
            raise PocError("ConnectNamedPipe timeout", WAIT_TIMEOUT)
        if not connection_result.get("ok"):
            code = connection_result.get("error")
            process.close(kill=True)
            raise PocError(f"ConnectNamedPipe failed: winerror={code}", code)

        first = pipe_read(pipe, process.process, 10)
        lines = [first]
        if not first.startswith("TOKEN|"):
            process.close(kill=True)
            raise PocError(f"unexpected worker handshake: {first}")
        pipe_write(pipe, "RUN")
        while True:
            line = pipe_read(pipe, process.process, 10)
            lines.append(line)
            if line == "DONE":
                break
        if not process.wait(5000):
            process.close(kill=True)
            raise PocError("worker did not exit after DONE", WAIT_TIMEOUT)
        return process, host_evidence, lines, process.exit_code()
    except BaseException:
        process.close(kill=True)
        raise


def host_main() -> int:
    results: list[dict[str, object]] = []
    root: Path | None = None
    profile_data: list[tuple[str, LPVOID, str]] = []
    current_pipe: HANDLE | None = None
    current_process: LaunchedProcess | None = None
    startup_ok = False
    try:
        host_sid = current_user_sid()
        base = Path(sys.base_prefix)
        source_python = base / "python.exe"
        if not source_python.exists():
            raise PocError(f"base Python executable not found: {source_python}")

        root = Path(tempfile.mkdtemp(prefix="astra-appcontainer-poc-"))
        profile_names = [
            f"AstraPoc.{uuid.uuid4().hex[:12]}",
            f"AstraPoc.{uuid.uuid4().hex[:12]}",
        ]
        for name in profile_names:
            sid_ptr, sid_string = create_profile(name)
            profile_data.append((name, sid_ptr, sid_string))
        sid1 = profile_data[0][2]
        sid2 = profile_data[1][2]

        root_sddl = (
            f"D:P(A;OICI;FA;;;{host_sid})"
            f"(A;OICI;GX;;;{sid1})(A;OICI;GX;;;{sid2})"
        )
        set_path_acl(root, root_sddl)

        runtime = root / "runtime"
        allow_dir = root / "allow"
        deny_dir = root / "deny"
        runtime.mkdir()
        allow_dir.mkdir()
        deny_dir.mkdir()

        set_path_acl(
            runtime,
            f"D:P(A;OICI;FA;;;{host_sid})"
            f"(A;OICI;GRGX;;;{sid1})(A;OICI;GRGX;;;{sid2})",
        )
        set_path_acl(
            allow_dir,
            f"D:P(A;OICI;FA;;;{host_sid})"
            f"(A;OICI;GRGX;;;{sid1})(A;OICI;GRGX;;;{sid2})",
        )
        set_path_acl(deny_dir, f"D:P(A;OICI;FA;;;{host_sid})")

        shutil.copy2(source_python, runtime / "python.exe")
        for name in ("python311.dll", "python3.dll"):
            source = base / name
            if source.exists():
                shutil.copy2(source, runtime / name)
        shutil.copytree(base / "DLLs", runtime / "DLLs")
        shutil.copytree(base / "Lib", runtime / "Lib")

        allow_file = allow_dir / "allowed.txt"
        deny_file = deny_dir / "denied.txt"
        allow_file.write_text("temporary-allowed-data\n", encoding="utf-8")
        deny_file.write_text("temporary-denied-data\n", encoding="utf-8")
        set_path_acl(
            allow_file,
            f"D:P(A;;FA;;;{host_sid})"
            f"(A;;GR;;;{sid1})(A;;GR;;;{sid2})",
        )
        set_path_acl(deny_file, f"D:P(A;;FA;;;{host_sid})")
        before_hash = hash_file(deny_file)

        script = allow_dir / "astra_appcontainer_proof.py"
        shutil.copy2(Path(__file__), script)
        set_path_acl(
            script,
            f"D:P(A;;FA;;;{host_sid})"
            f"(A;;GR;;;{sid1})(A;;GR;;;{sid2})",
        )

        environment = {
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
            "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
            "PATH": str(runtime),
            "PYTHONHOME": str(runtime),
            "PYTHONNOUSERSITE": "1",
        }

        # Main worker proof: the pipe handle is never inherited.
        main_pipe_path = pipe_name("main")
        current_pipe = create_named_pipe(main_pipe_path, host_sid, [sid1])
        (
            current_process,
            host_evidence,
            worker_lines,
            worker_exit,
        ) = run_connected_worker(
            profile_data[0][1],
            current_pipe,
            main_pipe_path,
            runtime / "python.exe",
            script,
            allow_file,
            deny_file,
            environment,
            runtime,
        )
        startup_ok = True
        startup_valid = (
            host_evidence["appcontainer"]
            and host_evidence["appcontainer_sid"] == sid1
            and host_evidence["integrity"] == "low"
            and host_evidence["capabilities"] == []
            and host_evidence["job"]
        )
        record(
            results,
            "appcontainer_process_creation",
            "CreateProcessW creates a low-integrity AppContainer process with the expected SID and zero capabilities",
            f"host observed {host_evidence}",
            "PASS" if startup_valid else "FAIL",
            f"token={host_evidence}",
            "OS token evidence, not a Python restriction.",
        )
        if not startup_valid:
            raise PocError("host-side AppContainer token evidence mismatch")

        token_line = next(
            (line for line in worker_lines if line.startswith("TOKEN|")),
            "",
        )
        token_fields = parse_fields(token_line)
        worker_token_valid = (
            token_fields.get("app") == "1"
            and token_fields.get("sid") == sid1
            and token_fields.get("il") == "low"
            and token_fields.get("caps") == "0"
            and token_fields.get("job") == "1"
        )
        record(
            results,
            "worker_token_verification",
            "Worker reports the expected AppContainer SID, Low IL, zero capabilities, and Job membership",
            token_line,
            "PASS" if worker_token_valid else "FAIL",
            f"sid={token_fields.get('sid')};il={token_fields.get('il')};caps={token_fields.get('caps')};job={token_fields.get('job')}",
            "Worker identity was confirmed at the OS token boundary.",
        )

        record(
            results,
            "named_pipe_ipc",
            "Authorized AppContainer connects through the explicit named pipe without an inherited handle",
            f"worker exchanged {len(worker_lines)} framed lines; exit={worker_exit}",
            "PASS" if worker_exit == 0 else "FAIL",
            "CreateNamedPipeW DACL + bInheritHandle=FALSE + CreateProcessW inheritHandles=FALSE",
            "Only the authorized AppContainer SID was granted pipe access.",
        )

        result_lines: dict[str, dict[str, str]] = {}
        for line in worker_lines:
            if line.startswith("RESULT|"):
                fields = parse_fields(line)
                if "test" in fields:
                    result_lines[fields["test"]] = fields

        expected_results = {
            "python_allow_read": (True, 0, "filesystem_allow_python_open"),
            "python_deny_read": (False, ERROR_ACCESS_DENIED, "filesystem_deny_python_open"),
            "native_allow_read": (True, 0, "filesystem_allow_win32_createfile"),
            "native_deny_read": (False, ERROR_ACCESS_DENIED, "filesystem_deny_win32_createfile"),
            "native_allow_write": (False, ERROR_ACCESS_DENIED, "filesystem_native_write_denied"),
        }
        for test_name, (expected_ok, expected_error, report_name) in expected_results.items():
            fields = result_lines.get(test_name)
            if fields is None:
                record(
                    results,
                    report_name,
                    f"ok={int(expected_ok)}, winerror={expected_error}",
                    "worker result missing",
                    "NOT EXECUTED",
                    "no result frame",
                    "No filesystem conclusion.",
                )
                continue
            actual_ok = fields.get("ok") == "1"
            actual_error = int(fields.get("winerr", "-1"))
            passed = actual_ok == expected_ok and actual_error == expected_error
            record(
                results,
                report_name,
                f"ok={int(expected_ok)}, winerror={expected_error}",
                f"ok={int(actual_ok)}, winerror={actual_error}",
                "PASS" if passed else "FAIL",
                f"worker OS result winerror={actual_error}",
                "The result is an OS access decision; it is not an import restriction.",
            )

        after_hash = hash_file(deny_file)
        unchanged = before_hash == after_hash
        record(
            results,
            "filesystem_write_denied_and_unchanged",
            "Worker write attempt is denied and the temporary denied file hash is unchanged",
            f"hash_unchanged={unchanged}; before={before_hash}; after={after_hash}",
            "PASS"
            if unchanged
            and result_lines.get("native_allow_write", {}).get("winerr") == str(ERROR_ACCESS_DENIED)
            else "FAIL",
            f"before_sha256={before_hash};after_sha256={after_hash}",
            "No mutation of the temporary protected file was observed.",
        )

        child_fields = result_lines.get("child_process", {})
        child_ok = child_fields.get("ok") == "1"
        record(
            results,
            "child_process_job_isolation",
            "Child inherits AppContainer token and Job membership; direct denied-file reads remain ERROR_ACCESS_DENIED",
            f"ok={child_fields.get('ok')};exit={child_fields.get('exit')};winerr={child_fields.get('winerr')}",
            "PASS" if child_ok else "FAIL",
            "child token and job checks were performed inside the child process",
            "Child inheritance was verified independently of Python import restrictions.",
        )
        current_process.close(kill=False)
        current_process = None
        close_handle(current_pipe)
        current_pipe = None

        # Negative named-pipe ACL proof with a different AppContainer SID.
        negative_pipe_path = pipe_name("negative")
        negative_pipe = create_named_pipe(
            negative_pipe_path, host_sid, [sid1]
        )
        negative_process = None
        try:
            negative_process = launch_appcontainer(
                profile_data[1][1],
                runtime / "python.exe",
                script,
                ["--pipe-probe", negative_pipe_path],
                environment,
                runtime,
            )
            negative_process.resume()
            if not negative_process.wait(5000):
                negative_process.close(kill=True)
                raise PocError("unauthorized pipe probe timed out", WAIT_TIMEOUT)
            negative_exit = negative_process.exit_code()
            record(
                results,
                "named_pipe_acl_negative",
                "A different AppContainer SID receives ERROR_ACCESS_DENIED when opening the pipe",
                f"unauthorized probe exit={negative_exit}",
                "PASS" if negative_exit == 0 else "FAIL",
                "pipe DACL allowed sid1 and denied sid2; probe maps winerror=5 to exit=0",
                "Named Pipe ACL enforced an OS-level negative decision.",
            )
        finally:
            if negative_process is not None:
                negative_process.close(kill=True)
            close_handle(negative_pipe)

        # Crash cleanup proof: abnormal worker termination leaves no live process.
        crash_pipe_path = pipe_name("crash")
        crash_pipe = create_named_pipe(crash_pipe_path, host_sid, [sid1])
        crash_process = None
        try:
            crash_process = launch_appcontainer(
                profile_data[0][1],
                runtime / "python.exe",
                script,
                [
                    "--worker",
                    "--pipe",
                    crash_pipe_path,
                    "--allow",
                    str(allow_file),
                    "--deny",
                    str(deny_file),
                    "--python",
                    str(runtime / "python.exe"),
                    "--script",
                    str(script),
                    "--mode",
                    "crash",
                ],
                environment,
                runtime,
            )
            connected = threading.Event()
            connection_result: dict[str, object] = {}
            connector = threading.Thread(
                target=connect_named_pipe,
                args=(crash_pipe, connection_result, connected),
                daemon=True,
            )
            connector.start()
            crash_process.resume()
            if not connected.wait(10) or not connection_result.get("ok"):
                raise PocError("crash worker did not connect")
            crash_line = pipe_read(crash_pipe, crash_process.process, 10)
            terminated = crash_process.wait(5000)
            exit_code = crash_process.exit_code()
            record(
                results,
                "worker_crash_cleanup",
                "An abnormal worker exit is observed and leaves no live worker process",
                f"handshake={crash_line};terminated={terminated};exit={exit_code}",
                "PASS" if crash_line.startswith("TOKEN|") and terminated and exit_code != 0 else "FAIL",
                f"expected_crash_exit={CRASH_EXIT_CODE};actual_exit={exit_code}",
                "Abnormal termination was handled without an unisolated fallback.",
            )
        finally:
            if crash_process is not None:
                crash_process.close(kill=True)
            close_handle(crash_pipe)

        # Job cleanup proof: close the Job handle and require the hanging worker to die.
        hang_pipe_path = pipe_name("hang")
        hang_pipe = create_named_pipe(hang_pipe_path, host_sid, [sid1])
        hang_process = None
        try:
            hang_process = launch_appcontainer(
                profile_data[0][1],
                runtime / "python.exe",
                script,
                [
                    "--worker",
                    "--pipe",
                    hang_pipe_path,
                    "--allow",
                    str(allow_file),
                    "--deny",
                    str(deny_file),
                    "--python",
                    str(runtime / "python.exe"),
                    "--script",
                    str(script),
                    "--mode",
                    "hang",
                ],
                environment,
                runtime,
            )
            connected = threading.Event()
            connection_result: dict[str, object] = {}
            connector = threading.Thread(
                target=connect_named_pipe,
                args=(hang_pipe, connection_result, connected),
                daemon=True,
            )
            connector.start()
            hang_process.resume()
            if not connected.wait(10) or not connection_result.get("ok"):
                raise PocError("hang worker did not connect")
            hang_line = pipe_read(hang_pipe, hang_process.process, 10)
            close_handle(hang_pipe)
            hang_pipe = None
            close_handle(hang_process.job)
            hang_process.job = HANDLE()
            terminated = hang_process.wait(5000)
            record(
                results,
                "job_timeout_cleanup",
                "Closing the dedicated Job terminates the hanging worker within the deadline",
                f"handshake={hang_line};terminated={terminated}",
                "PASS" if hang_line.startswith("TOKEN|") and terminated else "FAIL",
                "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no explicit process fallback",
                "Timeout cleanup is process-tree cleanup, not filesystem isolation.",
            )
        finally:
            if hang_process is not None:
                hang_process.close(kill=True)
            close_handle(hang_pipe)
    except PocError as exc:
        if not startup_ok:
            record(
                results,
                "appcontainer_process_creation",
                "CreateAppContainerProfile and CreateProcessW succeed with zero capabilities",
                "initialization stopped: " + str(exc),
                "FAIL",
                f"winerror_or_hresult={exc.code}",
                "Fail-closed. No restricted-token or unisolated-worker fallback was attempted.",
            )
            mark_downstream_not_executed(results, "AppContainer prerequisite failed")
        else:
            record(
                results,
                "harness_execution",
                "all proof stages complete",
                str(exc),
                "FAIL",
                f"winerror={exc.code}",
                "A proof stage failed; no production path was invoked.",
            )
            mark_downstream_not_executed(results, "previous proof stage failed")
    except BaseException as exc:
        code = error_code(exc)
        if not startup_ok:
            record(
                results,
                "appcontainer_process_creation",
                "PoC initialization succeeds",
                f"unexpected harness failure: {exc}",
                "FAIL",
                f"winerror={code}",
                "Fail-closed. The cause requires review before another run.",
            )
            mark_downstream_not_executed(
                results, "unexpected harness initialization failure"
            )
        else:
            record(
                results,
                "harness_execution",
                "all proof stages complete",
                f"unexpected proof failure: {exc}",
                "FAIL",
                f"winerror={code}",
                "A proof stage failed; no production path was invoked.",
            )
            mark_downstream_not_executed(results, "previous proof stage failed")
    finally:
        if current_process is not None:
            current_process.close(kill=True)
        close_handle(current_pipe)
        cleanup_errors: list[str] = []
        for name, sid_ptr, _ in reversed(profile_data):
            try:
                delete_profile(name, sid_ptr)
            except BaseException as exc:
                cleanup_errors.append(str(exc))
        if root is not None:
            try:
                shutil.rmtree(root)
            except BaseException as exc:
                cleanup_errors.append(f"temporary-root cleanup: {exc}")
        if cleanup_errors:
            record(
                results,
                "temporary_resource_cleanup",
                "all temporary profiles, files, ACLs, pipes, and processes are removed",
                "; ".join(cleanup_errors),
                "FAIL",
                "cleanup error",
                "Do not enable isolation until cleanup is deterministic.",
            )
        else:
            record(
                results,
                "temporary_resource_cleanup",
                "all temporary profiles, files, ACLs, pipes, and processes are removed",
                "temporary resources removed",
                "PASS",
                "profile deletion and temporary directory removal succeeded",
                "No persistent account, system ACL, or production resource was modified.",
            )

    print(json.dumps({"results": results}, ensure_ascii=False, indent=2))
    return 1 if any(item["status"] == "FAIL" for item in results) else 0


def main() -> int:
    if "--worker" in sys.argv:
        return worker_main(sys.argv[sys.argv.index("--worker") + 1 :])
    if "--child-probe" in sys.argv:
        return child_probe(sys.argv[sys.argv.index("--child-probe") + 1])
    if "--pipe-probe" in sys.argv:
        return pipe_probe(sys.argv[sys.argv.index("--pipe-probe") + 1 :])
    return host_main()


if __name__ == "__main__":
    raise SystemExit(main())
