"""Owner-only Windows DACLs for application data, using pinned file handles.

No machine policy, privileges, trusted principals or system ACLs are changed.
Privileged administrators can still take ownership, as with Unix root.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
from ctypes import wintypes as w
from pathlib import Path


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", w.DWORD),
        ("creation", w.FILETIME),
        ("access", w.FILETIME),
        ("write", w.FILETIME),
        ("volume", w.DWORD),
        ("size_high", w.DWORD),
        ("size_low", w.DWORD),
        ("links", w.DWORD),
        ("index_high", w.DWORD),
        ("index_low", w.DWORD),
    ]


def _api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    signatures = [
        (kernel.GetCurrentProcess, [], w.HANDLE),
        (kernel.CloseHandle, [w.HANDLE], w.BOOL),
        (kernel.LocalFree, [w.LPVOID], w.LPVOID),
        (
            kernel.CreateFileW,
            [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE],
            w.HANDLE,
        ),
        (kernel.CreateDirectoryW, [w.LPCWSTR, w.LPVOID], w.BOOL),
        (
            kernel.GetFileInformationByHandle,
            [w.HANDLE, ctypes.POINTER(_FileInformation)],
            w.BOOL,
        ),
        (security.OpenProcessToken, [w.HANDLE, w.DWORD, w.LPVOID], w.BOOL),
        (
            security.GetTokenInformation,
            [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, w.LPVOID],
            w.BOOL,
        ),
        (security.ConvertSidToStringSidW, [w.LPVOID, w.LPVOID], w.BOOL),
        (
            security.ConvertStringSecurityDescriptorToSecurityDescriptorW,
            [w.LPCWSTR, w.DWORD, w.LPVOID, w.LPVOID],
            w.BOOL,
        ),
        (
            security.GetSecurityDescriptorDacl,
            [w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID],
            w.BOOL,
        ),
        (
            security.GetSecurityInfo,
            [w.HANDLE, ctypes.c_int, w.DWORD] + [w.LPVOID] * 5,
            w.DWORD,
        ),
        (
            security.SetSecurityInfo,
            [w.HANDLE, ctypes.c_int, w.DWORD] + [w.LPVOID] * 4,
            w.DWORD,
        ),
        (security.EqualSid, [w.LPVOID, w.LPVOID], w.BOOL),
        (security.GetSecurityDescriptorControl, [w.LPVOID, w.LPVOID, w.LPVOID], w.BOOL),
    ]
    for function, args, result in signatures:
        function.argtypes = args
        function.restype = result
    return kernel, security


def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _descriptor(kernel, security):
    token = w.HANDLE()
    _check(
        security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, ctypes.byref(token))
    )  # TOKEN_QUERY
    try:
        size = w.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if size.value < ctypes.sizeof(w.LPVOID):
            raise ctypes.WinError(ctypes.get_last_error())
        data = ctypes.create_string_buffer(size.value)
        _check(security.GetTokenInformation(token, 1, data, size, ctypes.byref(size)))
        sid = ctypes.cast(data, ctypes.POINTER(w.LPVOID))[0]
        sid_string = w.LPVOID()
        _check(security.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)))
        try:
            sddl = f"D:P(A;;FA;;;{ctypes.wstring_at(sid_string)})"
        finally:
            kernel.LocalFree(sid_string)
        descriptor = w.LPVOID()
        _check(
            security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None
            )
        )
        try:
            yield descriptor, sid
        finally:
            kernel.LocalFree(descriptor)
    finally:
        kernel.CloseHandle(token)


def _reject_reparse_ancestors(path: Path) -> None:
    # Do not resolve links before inspecting them. This is a precondition check,
    # not a cross-process guarantee against an ancestor rename race.
    for part in (path, *path.parents):
        try:
            attributes = part.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & 0x400:
            raise OSError("Private data path contains a Windows reparse point")


def private_path(
    path: Path,
    *,
    directory: bool,
    create: bool = True,
    exclusive: bool = False,
) -> Path:
    """Create/protect only an owned ordinary file or directory; fail on errors.

    New objects receive their protected DACL at creation, before secret data
    can be written. Existing object DACLs are changed through the same handle
    used to check ownership, type, reparse status and hard-link count. Directory
    ACEs are deliberately non-inheritable: no recursive ACL rewrite occurs.
    """
    path = path.absolute()
    _reject_reparse_ancestors(path)
    kernel, security = _api()
    with _descriptor(kernel, security) as (descriptor, current_sid):
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes),
            descriptor,
            False,
        )
        if directory and create:
            if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                if error != 183:  # ERROR_ALREADY_EXISTS
                    raise ctypes.WinError(error)
        # CREATE_NEW prevents opening a pre-existing permissive file as though
        # it had received the creation descriptor. No delete sharing while held.
        disposition = 1 if exclusive else 3
        # MAXIMUM_ALLOWED suppresses SetSecurityInfo propagation to children.
        # https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
        access = 0x02000000 if directory else 0x60000
        handle = kernel.CreateFileW(
            str(path),
            access,
            3,
            ctypes.byref(attributes),
            disposition,
            0x02200000,
            None,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        )
        if handle == w.HANDLE(-1).value and not directory and create and not exclusive:
            error = ctypes.get_last_error()
            if error == 2:
                handle = kernel.CreateFileW(
                    str(path),
                    access,
                    3,
                    ctypes.byref(attributes),
                    1,
                    0x02200000,
                    None,
                )
                error = ctypes.get_last_error()
            if handle == w.HANDLE(-1).value and error in (80, 183):
                handle = kernel.CreateFileW(
                    str(path),
                    access,
                    3,
                    None,
                    3,
                    0x02200000,
                    None,
                )
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = _FileInformation()
            _check(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)))
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                raise OSError("Private data target type/reparse identity mismatch")
            if not directory and info.links != 1:
                raise OSError("Private data target has multiple hard links")
            owner, original = w.LPVOID(), w.LPVOID()
            error = security.GetSecurityInfo(
                handle,
                1,
                1,
                ctypes.byref(owner),
                None,
                None,
                None,
                ctypes.byref(original),
            )
            if error:
                raise ctypes.WinError(error)
            try:
                if not security.EqualSid(owner, current_sid):
                    raise PermissionError(
                        "Private data target is owned by another user"
                    )
            finally:
                kernel.LocalFree(original)
            present, defaulted, dacl = w.BOOL(), w.BOOL(), w.LPVOID()
            _check(
                security.GetSecurityDescriptorDacl(
                    descriptor,
                    ctypes.byref(present),
                    ctypes.byref(dacl),
                    ctypes.byref(defaulted),
                )
            )
            error = security.SetSecurityInfo(
                handle,
                1,
                0x80000004,
                None,
                None,
                dacl,
                None,
            )  # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
            if error:
                raise ctypes.WinError(error)
            # Verify the security descriptor on the same object before allowing
            # callers to write secrets. Filesystems without DACL support fail.
            actual_dacl, actual_sd = w.LPVOID(), w.LPVOID()
            error = security.GetSecurityInfo(
                handle,
                1,
                4,
                None,
                None,
                ctypes.byref(actual_dacl),
                None,
                ctypes.byref(actual_sd),
            )
            if error:
                raise ctypes.WinError(error)
            try:
                control, revision = w.WORD(), w.DWORD()
                _check(
                    security.GetSecurityDescriptorControl(
                        actual_sd,
                        ctypes.byref(control),
                        ctypes.byref(revision),
                    )
                )
                size = ctypes.cast(dacl, ctypes.POINTER(w.WORD))[1]
                if (
                    not control.value & 0x1000
                    or not actual_dacl
                    or ctypes.cast(actual_dacl, ctypes.POINTER(w.WORD))[1] != size
                    or ctypes.string_at(actual_dacl, size)
                    != ctypes.string_at(dacl, size)
                ):
                    raise PermissionError("Private data DACL verification failed")
            finally:
                kernel.LocalFree(actual_sd)
        finally:
            kernel.CloseHandle(handle)
    return path
