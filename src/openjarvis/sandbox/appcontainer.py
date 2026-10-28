"""Windows AppContainer sandbox primitives for the staged RLMWorker runtime.

Offline, test-driven, fail-closed. Uses only ctypes + the staged tree:

- per-run AppContainer profile create/delete (user32);
- SID helpers (advapi32 ConvertStringSidToSid/ConvertSidToStringSid);
- single RX ACE (OI|CI) provisioning/verification/rollback on the owned
  staged runtime root (advapi32 Get/SetNamedSecurityInfo);
- AppContainer child launch with SECURITY_CAPABILITIES + Job membership
  (userenv CreateAppContainerProfile/DeleteAppContainerProfile,
  kernel32 process/thread-attribute/job APIs);
- token identity proof (TokenIsAppContainer + TokenAppContainerSid);
- anonymous stdio pipes (parent<->child) with PeekNamedPipe poll.

No shell parsing, no broad principals, no WRITE grants, no network.
Not supported platforms raise SandboxError only when invoked.
"""

from __future__ import annotations

import ctypes
import sys
import uuid
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SB_PROFILE_PREFIX = "AstraWorker-"

# Access rights -----------------------------------------------------------
GENERIC_READ = 0x80000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
_GENERIC_RW_BITS = GENERIC_WRITE | 0x10000000  # GENERIC_ALL
_WRITE_BITS = (
    0x0002  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0100  # FILE_WRITE_ATTRIBUTES
    | 0x010000  # DELETE
    | 0x00040000  # WRITE_DAC
    | 0x00080000  # WRITE_OWNER
    | GENERIC_WRITE
    | 0x10000000  # GENERIC_ALL
)
RX_MASK = GENERIC_READ | GENERIC_EXECUTE

# ACE types / flags --------------------------------------------------------
ACCESS_ALLOWED_ACE_TYPE = 0x0
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
INHERITED_ACE = 0x10
SE_DACL_PRESENT = 0x0004
DACL_SECURITY_INFORMATION = 0x00000004
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
SE_FILE_OBJECT = 1

# Process / job / token ----------------------------------------------------
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
# ProcThreadAttributeValue(9, FALSE, TRUE, FALSE). NOTE: this is 9, not
# 14 (14 is CHILD_PROCESS_POLICY); a wrong number fails Update with
# ERROR_BAD_LENGTH (24).
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x20009
TokenIsAppContainer = 29
TokenAppContainerSid = 31
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 258  # decimal; 0x102 (NOT 0x258)
STILL_ACTIVE = 259
ERROR_SUCCESS = 0


class SandboxError(RuntimeError):
    """Fail-closed sandbox failure with machine-readable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _require_windows() -> None:
    if sys.platform != "win32":
        raise SandboxError("UNSUPPORTED_PLATFORM", sys.platform)


def _kernel32():
    _require_windows()
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _advapi32():
    _require_windows()
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _userenv():
    _require_windows()
    return ctypes.WinDLL("userenv", use_last_error=True)


# Structures ---------------------------------------------------------------
PSID = ctypes.c_void_p


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", PSID),
        ("Capabilities", wintypes.LPVOID),
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
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFO),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount",
        "OtherOperationCount", "ReadTransferCount",
        "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


# SID helpers --------------------------------------------------------------
def sid_from_string(sddl: str) -> PSID:
    adv = _advapi32()
    sid = PSID()
    fn = adv.ConvertStringSidToSidW
    fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(PSID)]
    fn.restype = wintypes.BOOL
    if not fn(sddl, ctypes.byref(sid)):
        raise SandboxError(
            "MALFORMED_SID", f"last_error={ctypes.get_last_error()}")
    return sid


def string_from_sid(sid: PSID) -> str:
    adv = _advapi32()
    out = wintypes.LPWSTR()
    fn = adv.ConvertSidToStringSidW
    fn.argtypes = [PSID, ctypes.POINTER(wintypes.LPWSTR)]
    fn.restype = wintypes.BOOL
    if not fn(sid, ctypes.byref(out)):
        raise SandboxError(
            "SID_TO_STRING_FAILED", f"last_error={ctypes.get_last_error()}")
    try:
        return ctypes.wstring_at(out)
    finally:
        _kernel32().LocalFree(out)


def free_sid(sid: PSID) -> None:
    if sid:
        _kernel32().LocalFree(sid)


# DACL snapshot / ACE structures -------------------------------------------
@dataclass
class AceRecord:
    sid: str
    mask: int
    ace_type: int
    flags: int
    inherited: bool


def _read_dacl_raw(path: str) -> Tuple[wintypes.LPVOID, int]:
    adv = _advapi32()
    ppsd = wintypes.LPVOID()
    ppdacl = wintypes.LPVOID()
    fn = adv.GetNamedSecurityInfoW
    fn.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                   ctypes.POINTER(wintypes.LPVOID),
                   ctypes.POINTER(wintypes.LPVOID),
                   ctypes.POINTER(wintypes.LPVOID),
                   ctypes.POINTER(wintypes.LPVOID),
                   ctypes.POINTER(wintypes.LPVOID)]
    fn.restype = wintypes.DWORD
    owner = wintypes.LPVOID()
    group = wintypes.LPVOID()
    sacl = wintypes.LPVOID()
    err = fn(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
             ctypes.byref(owner), ctypes.byref(group),
             ctypes.byref(ppdacl), ctypes.byref(sacl),
             ctypes.byref(ppsd))
    if err != ERROR_SUCCESS:
        raise SandboxError("ACL_READ_FAILED", f"err={err} path={path}")
    return ppsd, ppdacl


def snapshot_dacl(path: Path) -> List[AceRecord]:
    """Read the DACL ACE list of *path* (no mutation)."""
    adv = _advapi32()
    k32 = _kernel32()
    ppsd, ppdacl = _read_dacl_raw(str(path))
    try:
        if not ppdacl:
            return []
        GetAce = adv.GetAce
        GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD,
                           ctypes.POINTER(wintypes.LPVOID)]
        GetAce.restype = wintypes.BOOL
        GetAclInformation = adv.GetAclInformation
        # ACL_SIZE_INFORMATION: DWORD AceCount is the 2nd DWORD.
        size_info = (wintypes.DWORD * 3)()
        GetAclInformation.argtypes = [wintypes.LPVOID, wintypes.LPVOID,
                                      wintypes.DWORD, wintypes.DWORD]
        GetAclInformation.restype = wintypes.BOOL
        if not GetAclInformation(ppdacl, size_info,
                                 ctypes.sizeof(size_info), 2):
            raise SandboxError("ACL_READ_FAILED", "GetAclInformation")
        records: List[AceRecord] = []
        for i in range(size_info[0]):  # ACL_SIZE_INFORMATION.AceCount
            pace = wintypes.LPVOID()
            if not GetAce(ppdacl, i, ctypes.byref(pace)):
                raise SandboxError("ACL_READ_FAILED", f"GetAce {i}")
            base = pace.value
            ace_type = ctypes.c_ubyte.from_address(base).value
            ace_flags = ctypes.c_ubyte.from_address(base + 1).value
            mask = ctypes.c_uint32.from_address(base + 4).value
            sid_ptr = base + 8
            sid = string_from_sid(PSID(sid_ptr))
            records.append(AceRecord(
                sid=sid, mask=mask, ace_type=ace_type, flags=ace_flags,
                inherited=bool(ace_flags & INHERITED_ACE)))
        return records
    finally:
        k32.LocalFree(ppsd)


@dataclass
class AclDelta:
    path: str
    before: List[AceRecord] = field(default_factory=list)
    after: List[AceRecord] = field(default_factory=list)

    def ours(self, sid: str) -> List[AceRecord]:
        return [a for a in self.after if a.sid == sid]


def _set_entries(path: str, sid: PSID, mask: int,
                 inherit_flags: int, mode: int) -> None:
    """Add (mode=GRANT) or revoke (mode=REVOKE) one explicit ACE."""
    adv = _advapi32()

    GRANT_ACCESS = 1
    REVOKE_ACCESS = 4
    TRUSTEE_IS_SID = 0
    TRUSTEE_IS_USER = 1
    NO_MULTIPLE_TRUSTEE = 0

    class TRUSTEE(ctypes.Structure):
        _fields_ = [
            ("pMultipleTrustee", ctypes.c_void_p),
            ("MultipleTrusteeOperation", ctypes.c_int),
            ("TrusteeForm", ctypes.c_int),
            ("TrusteeType", ctypes.c_int),
            ("ptstrName", ctypes.c_void_p),
        ]

    class EXPLICIT_ACCESS(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", ctypes.c_int),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", TRUSTEE),
        ]

    ea = EXPLICIT_ACCESS()
    ea.grfAccessPermissions = mask
    ea.grfAccessMode = GRANT_ACCESS if mode == 1 else REVOKE_ACCESS
    ea.grfInheritance = inherit_flags
    ea.Trustee.pMultipleTrustee = None
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER
    ea.Trustee.ptstrName = ctypes.cast(sid, ctypes.c_void_p).value

    ppsd, ppdacl = _read_dacl_raw(path)
    k32 = _kernel32()
    try:
        new_dacl = wintypes.LPVOID()
        fn = adv.SetEntriesInAclW
        fn.argtypes = [wintypes.ULONG, wintypes.LPVOID,
                       wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID)]
        fn.restype = wintypes.DWORD
        err = fn(1, ctypes.byref(ea), ppdacl, ctypes.byref(new_dacl))
        if err != ERROR_SUCCESS:
            raise SandboxError("ACL_BUILD_FAILED", f"err={err}")
        try:
            sfn = adv.SetNamedSecurityInfoW
            sfn.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.LPVOID,
                            wintypes.LPVOID, wintypes.LPVOID]
            sfn.restype = wintypes.DWORD
            err = sfn(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                      None, None, new_dacl, None)
            if err != ERROR_SUCCESS:
                raise SandboxError("ACL_APPLY_FAILED", f"err={err}")
        finally:
            k32.LocalFree(new_dacl)
    finally:
        k32.LocalFree(ppsd)


def grant_rx(path: Path, sid: PSID) -> AclDelta:
    """Grant SID RX (OI|CI) on the staged runtime root. Fail-closed."""
    delta = AclDelta(path=str(path), before=snapshot_dacl(path))
    _set_entries(str(path), sid, RX_MASK,
                 OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, mode=1)
    delta.after = snapshot_dacl(path)
    return delta


def revoke_sid(path: Path, sid: PSID) -> AclDelta:
    delta = AclDelta(path=str(path), before=snapshot_dacl(path))
    _set_entries(str(path), sid, 0, 0, mode=4)
    delta.after = snapshot_dacl(path)
    return delta


def verify_rx(delta: AclDelta, sid_str: str) -> List[str]:
    """Post-verification of the RX grant. Returns error list (empty = ok).

    Accepts the canonical SetEntriesInAcl directory split: one ACE for
    the container itself (mapped READ mask, no inherit flags) plus one
    INHERIT_ONLY ACE carrying GENERIC_READ|GENERIC_EXECUTE with OI|CI.
    Hard requirements: our SID present, zero WRITE bits anywhere in our
    ACEs, OI|CI propagation present, generic RX present.
    """
    errors: List[str] = []
    ours = [a for a in delta.after if a.sid == sid_str]
    if not ours:
        return ["expected SID ACE absent after provisioning"]
    for ace in ours:
        if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE:
            errors.append(f"unexpected ACE type {ace.ace_type}")
        if ace.mask & _WRITE_BITS:
            errors.append(f"WRITE bits present: mask={ace.mask:#x}")
    if not any(a.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
               for a in ours):
        errors.append("OI|CI propagation missing")
    if not any((a.mask & (GENERIC_READ | GENERIC_EXECUTE))
               == (GENERIC_READ | GENERIC_EXECUTE) for a in ours):
        errors.append("generic RX ACE missing")
    return errors


# Profiles -----------------------------------------------------------------
def create_profile(name: str) -> Tuple[str, bool]:
    """Create (or open existing) AppContainer profile. Returns (sid, created)."""
    userenv = _userenv()
    sid = PSID()
    fn = userenv.CreateAppContainerProfile
    fn.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                   wintypes.LPVOID, wintypes.DWORD,
                   ctypes.POINTER(PSID)]
    fn.restype = ctypes.c_long  # HRESULT
    hr = fn(name, name, name, None, 0, ctypes.byref(sid))
    S_OK = 0
    if hr == S_OK:
        try:
            return string_from_sid(sid), True
        finally:
            free_sid(sid)
    if ctypes.c_uint32(hr).value == 0x800700B7:
        # Open existing profile to derive SID.
        fn2 = userenv.DeriveAppContainerSidFromAppContainerName
        fn2.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(PSID)]
        fn2.restype = ctypes.c_long
        sid2 = PSID()
        hr2 = fn2(name, ctypes.byref(sid2))
        if hr2 != S_OK:
            raise SandboxError("PROFILE_OPEN_FAILED", f"hr={hr2:#x}")
        try:
            return string_from_sid(sid2), False
        finally:
            free_sid(sid2)
    raise SandboxError("PROFILE_CREATE_FAILED", f"hr={hr:#x}")


def delete_profile(name: str) -> bool:
    userenv = _userenv()
    fn = userenv.DeleteAppContainerProfile
    fn.argtypes = [wintypes.LPCWSTR]
    fn.restype = ctypes.c_long
    hr = fn(name)
    if hr == 0:
        return True
    if ctypes.c_uint32(hr).value == 0x800700B7:  # already gone
        return False
    # ERROR_NOT_FOUND 0x80070490 may surface as failure; treat missing as ok.
    if ctypes.c_uint32(hr).value == 0x80070490:
        return False
    raise SandboxError("PROFILE_DELETE_FAILED", f"hr={hr:#x}")


def derive_sid(name: str) -> str:
    userenv = _userenv()
    fn = userenv.DeriveAppContainerSidFromAppContainerName
    fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(PSID)]
    fn.restype = ctypes.c_long
    sid = PSID()
    hr = fn(name, ctypes.byref(sid))
    if hr != 0:
        raise SandboxError("PROFILE_OPEN_FAILED", f"hr={hr:#x}")
    try:
        return string_from_sid(sid)
    finally:
        free_sid(sid)


def random_profile_name() -> str:
    return f"{SB_PROFILE_PREFIX}{uuid.uuid4().hex[:12]}"


# Pipes --------------------------------------------------------------------
@dataclass
class StdioPipes:
    child_stdin_read: int
    parent_stdin_write: int
    parent_stdout_read: int
    child_stdout_write: int
    child_stderr_write: int = -1


def make_stdio_pipes() -> StdioPipes:
    """Two anonymous pipes: parent->child (stdin), child->parent (stdout).

    Child ends are inheritable; parent ends are not.
    """
    k32 = _kernel32()
    sa_inherit = SECURITY_ATTRIBUTES()
    sa_inherit.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa_inherit.bInheritHandle = True
    sa_no = SECURITY_ATTRIBUTES()
    sa_no.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa_no.bInheritHandle = False
    CreatePipe = k32.CreatePipe
    CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE),
                           ctypes.POINTER(wintypes.HANDLE),
                           ctypes.POINTER(SECURITY_ATTRIBUTES),
                           wintypes.DWORD]
    CreatePipe.restype = wintypes.BOOL
    SetHandleInformation = k32.SetHandleInformation
    SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     wintypes.DWORD]
    SetHandleInformation.restype = wintypes.BOOL

    def _pipe():
        r = wintypes.HANDLE()
        w = wintypes.HANDLE()
        if not CreatePipe(ctypes.byref(r), ctypes.byref(w),
                          ctypes.byref(sa_inherit), 0):
            raise SandboxError(
                "PIPE_FAILURE", f"err={ctypes.get_last_error()}")
        return r.value, w.value

    c_in_r, p_in_w = _pipe()   # parent writes, child reads (stdin)
    p_out_r, c_out_w = _pipe()  # child writes, parent reads (stdout)
    # Parent ends must NOT be inherited.
    for h in (p_in_w, p_out_r):
        if not SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0):
            raise SandboxError(
                "PIPE_FAILURE", f"uninisonherit err={ctypes.get_last_error()}")
    return StdioPipes(child_stdin_read=c_in_r, parent_stdin_write=p_in_w,
                      parent_stdout_read=p_out_r, child_stdout_write=c_out_w)


def close_handle(handle: int) -> None:
    if handle and handle != -1:
        _kernel32().CloseHandle(wintypes.HANDLE(handle))


def write_all(handle: int, data: bytes) -> None:
    k32 = _kernel32()
    view = memoryview(data)
    while view:
        written = wintypes.DWORD()
        ok = k32.WriteFile(wintypes.HANDLE(handle), view.tobytes(),
                           len(view), ctypes.byref(written), None)
        if not ok:
            raise SandboxError(
                "PIPE_FAILURE", f"write err={ctypes.get_last_error()}")
        view = view[written.value:]


def read_exact(handle: int, n: int, timeout_ms: int = 30000) -> bytes:
    """Read exactly n bytes (poll with timeout first)."""
    import time as _time
    k32 = _kernel32()
    avail = wintypes.DWORD()
    Peek = k32.PeekNamedPipe
    Peek.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                     wintypes.LPDWORD, wintypes.LPDWORD, wintypes.LPDWORD]
    Peek.restype = wintypes.BOOL
    deadline = _time.monotonic() + timeout_ms / 1000.0
    out = bytearray()
    buf = ctypes.create_string_buffer(65536)
    remaining = n
    while remaining > 0:
        if _time.monotonic() > deadline:
            raise SandboxError("PIPE_TIMEOUT", f"want={n} got={len(out)}")
        if not Peek(wintypes.HANDLE(handle), None, 0, None,
                    ctypes.byref(avail), None):
            err = ctypes.get_last_error()
            if out or err == 109:  # ERROR_BROKEN_PIPE
                if err == 109:
                    raise SandboxError("PIPE_EOF", f"got={len(out)}/{n}")
                raise SandboxError("PIPE_FAILURE", f"peek err={err}")
            raise SandboxError("PIPE_FAILURE", f"peek err={err}")
        if avail.value == 0:
            _time.sleep(0.005)
            continue
        chunk = min(remaining, avail.value, 65536)
        got = wintypes.DWORD()
        if not k32.ReadFile(wintypes.HANDLE(handle), buf, chunk,
                            ctypes.byref(got), None):
            raise SandboxError(
                "PIPE_FAILURE", f"read err={ctypes.get_last_error()}")
        if got.value == 0:
            raise SandboxError("PIPE_EOF", f"got={len(out)}/{n}")
        out += buf.raw[:got.value]
        remaining -= got.value
    return bytes(out)


def poll_pipe(handle: int, timeout_ms: int = 0) -> bool:
    """PeekNamedPipe-based poll (Windows select() cannot poll pipes)."""
    import time as _time
    k32 = _kernel32()
    avail = wintypes.DWORD()
    Peek = k32.PeekNamedPipe
    Peek.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                     wintypes.LPDWORD, wintypes.LPDWORD, wintypes.LPDWORD]
    Peek.restype = wintypes.BOOL
    deadline = _time.monotonic() + timeout_ms / 1000.0
    while True:
        if not Peek(wintypes.HANDLE(handle), None, 0, None,
                    ctypes.byref(avail), None):
            return False  # broken/closed -> not readable
        if avail.value > 0:
            return True
        if _time.monotonic() >= deadline:
            return False
        _time.sleep(0.005)


# Job + launch -------------------------------------------------------------
@dataclass
class LaunchedChild:
    pid: int
    process_handle: int
    thread_handle: int
    job_handle: int
    profile_name: str
    profile_sid: str


def create_kill_job() -> int:
    k32 = _kernel32()
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise SandboxError(
            "PROCESS_CREATION_FAILURE", f"job err={ctypes.get_last_error()}")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
    fn = k32.SetInformationJobObject
    fn.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID,
                   wintypes.DWORD]
    fn.restype = wintypes.BOOL
    if not fn(job, JobObjectExtendedLimitInformation,
              ctypes.byref(info), ctypes.sizeof(info)):
        err = ctypes.get_last_error()
        k32.CloseHandle(job)
        raise SandboxError("PROCESS_CREATION_FAILURE", f"jobinfo err={err}")
    # Verify no breakaway flags are settable by us: query back LimitFlags.
    out = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    need = wintypes.DWORD()
    qfn = k32.QueryInformationJobObject
    qfn.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID,
                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    qfn.restype = wintypes.BOOL
    if qfn(job, JobObjectExtendedLimitInformation, ctypes.byref(out),
           ctypes.sizeof(out), ctypes.byref(need)):
        flags = out.BasicLimitInformation.LimitFlags
        if flags & 0x78000000:  # any BREAKAWAY/SILENT_BREAKAWAY variant bits
            k32.CloseHandle(job)
            raise SandboxError("PROCESS_CREATION_FAILURE",
                               f"unexpected breakaway flags {flags:#x}")
    return job


def launch_appcontainer(command: str, profile_sid: str, pipes: StdioPipes,
                        *, cwd: str, env_block: Optional[bytes],
                        job: int) -> LaunchedChild:
    """CreateProcessW in an AppContainer with stdio pipes + Job membership."""
    k32 = _kernel32()
    sid = sid_from_string(profile_sid)
    try:
        caps = SECURITY_CAPABILITIES()
        caps.AppContainerSid = sid
        caps.Capabilities = None
        caps.CapabilityCount = 0
        caps.Reserved = 0

        size = ctypes.c_size_t()
        InitList = k32.InitializeProcThreadAttributeList
        InitList.argtypes = [wintypes.LPVOID, wintypes.DWORD,
                             wintypes.DWORD,
                             ctypes.POINTER(ctypes.c_size_t)]
        InitList.restype = wintypes.BOOL
        InitList(None, 1, 0, ctypes.byref(size))
        attr_list = ctypes.create_string_buffer(size.value)
        if not InitList(attr_list, 1, 0, ctypes.byref(size)):
            raise SandboxError(
                "PROCESS_CREATION_FAILURE",
                f"attrlist err={ctypes.get_last_error()}")

        Update = k32.UpdateProcThreadAttribute
        Update.argtypes = [wintypes.LPVOID, wintypes.DWORD,
                           ctypes.c_size_t, wintypes.LPVOID,
                           ctypes.c_size_t, wintypes.LPVOID,
                           wintypes.LPVOID]
        Update.restype = wintypes.BOOL
        if not Update(attr_list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                      ctypes.byref(caps), ctypes.sizeof(caps), None, None):
            raise SandboxError(
                "PROCESS_CREATION_FAILURE",
                f"updateattr err={ctypes.get_last_error()}")

        si = STARTUPINFOEX()
        # cb covers the whole STARTUPINFOEX (112), matching the native
        # launcher; sizeof(STARTUPINFO) alone fails CreateProcessW.
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput = pipes.child_stdin_read
        si.StartupInfo.hStdOutput = pipes.child_stdout_write
        si.StartupInfo.hStdError = pipes.child_stdout_write
        si.lpAttributeList = ctypes.cast(attr_list, wintypes.LPVOID).value
        pi = PROCESS_INFORMATION()
        cmd = ctypes.create_unicode_buffer(command)
        ok = k32.CreateProcessW(
            None, cmd, None, None, True,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env_block, cwd,
            ctypes.byref(si.StartupInfo), ctypes.byref(pi))
        # Free attribute list promptly.
        k32.DeleteProcThreadAttributeList(attr_list)
        if not ok:
            raise SandboxError(
                "PROCESS_CREATION_FAILURE",
                f"CreateProcessW err={ctypes.get_last_error()}")
        try:
            if not k32.AssignProcessToJobObject(job, pi.hProcess):
                err = ctypes.get_last_error()
                k32.TerminateProcess(pi.hProcess, 1)
                raise SandboxError("PROCESS_CREATION_FAILURE",
                                   f"job assign err={err}")
        except SandboxError:
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
            raise
        # Parent closes child ends immediately (handle hygiene).
        close_handle(pipes.child_stdin_read)
        close_handle(pipes.child_stdout_write)
        pipes.child_stdin_read = -1
        pipes.child_stdout_write = -1
        return LaunchedChild(pid=pi.dwProcessId,
                             process_handle=int(pi.hProcess),
                             thread_handle=int(pi.hThread),
                             job_handle=job,
                             profile_name="", profile_sid=profile_sid)
    finally:
        free_sid(sid)


def query_process_image(pid_handle: int) -> str:
    k32 = _kernel32()
    buf = ctypes.create_unicode_buffer(1024)
    size = wintypes.DWORD(1024)
    fn = k32.QueryFullProcessImageNameW
    fn.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                   ctypes.POINTER(wintypes.DWORD)]
    fn.restype = wintypes.BOOL
    if not fn(wintypes.HANDLE(pid_handle), 0, buf, ctypes.byref(size)):
        raise SandboxError(
            "IDENTITY_FAILURE", f"image err={ctypes.get_last_error()}")
    return buf.value


@dataclass
class TokenIdentity:
    is_appcontainer: bool
    appcontainer_sid: str


def query_token_identity(process_handle: int) -> TokenIdentity:
    k32 = _kernel32()
    adv = _advapi32()
    token = wintypes.HANDLE()
    OpenProcessToken = adv.OpenProcessToken
    OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
    OpenProcessToken.restype = wintypes.BOOL
    TOKEN_QUERY = 0x0008
    if not OpenProcessToken(wintypes.HANDLE(process_handle), TOKEN_QUERY,
                            ctypes.byref(token)):
        raise SandboxError(
            "IDENTITY_FAILURE", f"token err={ctypes.get_last_error()}")
    try:
        GetTokenInformation = adv.GetTokenInformation
        GetTokenInformation.argtypes = [wintypes.HANDLE, wintypes.INT,
                                        wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
        GetTokenInformation.restype = wintypes.BOOL
        is_ac = wintypes.DWORD()
        need = wintypes.DWORD()
        if not GetTokenInformation(token, TokenIsAppContainer,
                                   ctypes.byref(is_ac),
                                   ctypes.sizeof(is_ac),
                                   ctypes.byref(need)):
            raise SandboxError(
                "IDENTITY_FAILURE", f"isAC err={ctypes.get_last_error()}")
        sid_str = ""
        if is_ac.value:
            buf = ctypes.create_string_buffer(256)
            need2 = wintypes.DWORD(ctypes.sizeof(buf))
            if not GetTokenInformation(token, TokenAppContainerSid, buf,
                                       ctypes.sizeof(buf),
                                       ctypes.byref(need2)):
                raise SandboxError(
                    "IDENTITY_FAILURE", f"acSid err={ctypes.get_last_error()}")
            # TOKEN_APPCONTAINER_INFORMATION: PSID at offset 0.
            psid = ctypes.cast(buf, ctypes.POINTER(wintypes.LPVOID)).contents
            sid_str = string_from_sid(PSID(psid.value))
        return TokenIdentity(is_appcontainer=bool(is_ac.value),
                             appcontainer_sid=sid_str)
    finally:
        k32.CloseHandle(token)


def is_process_in_job(process_handle: int, job_handle: int) -> bool:
    k32 = _kernel32()
    fn = k32.IsProcessInJob
    fn.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                   ctypes.POINTER(wintypes.BOOL)]
    fn.restype = wintypes.BOOL
    result = wintypes.BOOL()
    if not fn(wintypes.HANDLE(process_handle), wintypes.HANDLE(job_handle),
              ctypes.byref(result)):
        # Fallback: any-job query.
        fn2 = k32.IsProcessInJob
        r2 = wintypes.BOOL()
        if not fn2(wintypes.HANDLE(process_handle), None, ctypes.byref(r2)):
            raise SandboxError(
                "IDENTITY_FAILURE", f"jobquery err={ctypes.get_last_error()}")
        return bool(r2.value)
    return bool(result.value)


def wait_process(process_handle: int, timeout_ms: int) -> str:
    k32 = _kernel32()
    rc = k32.WaitForSingleObject(wintypes.HANDLE(process_handle), timeout_ms)
    if rc == WAIT_OBJECT_0:
        return "exited"
    if rc == WAIT_TIMEOUT:
        return "timeout"
    raise SandboxError("PROCESS_CREATION_FAILURE", f"wait rc={rc}")


def terminate_child(child: LaunchedChild) -> None:
    k32 = _kernel32()
    try:
        k32.TerminateProcess(wintypes.HANDLE(child.process_handle), 1)
        # Synchronous teardown: wait for actual exit so mapped DLLs
        # release before callers remove files. Best effort afterwards.
        try:
            wait_process(child.process_handle, 5000)
        except SandboxError:
            pass
    finally:
        close_handle(child.thread_handle)
        close_handle(child.process_handle)
        close_handle(child.job_handle)


def build_env_block(env: Dict[str, str]) -> bytes:
    """NUL-separated, double-NUL-terminated UTF-16LE environment block."""
    blob = "\x00".join(f"{k}={v}" for k, v in env.items()) + "\x00\x00"
    return blob.encode("utf-16-le")
