"""Read actual DACLs independently with GetNamedSecurityInfo and SDDL."""

import csv
import ctypes
import os
import stat
import subprocess
from ctypes import wintypes as w
from pathlib import Path


def assert_private(path: Path, mode: int) -> None:
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == mode
        return
    # No production writer/helper is used to validate the persisted descriptor.
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get = dll.GetNamedSecurityInfoW
    get.argtypes = [w.LPCWSTR, ctypes.c_int, w.DWORD] + [w.LPVOID] * 5
    get.restype = w.DWORD
    convert = dll.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = [w.LPVOID, w.DWORD, w.DWORD, w.LPVOID, w.LPVOID]
    convert.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    descriptor = w.LPVOID()
    error = get(str(path), 1, 5, None, None, None, None, ctypes.byref(descriptor))
    assert error == 0, ctypes.FormatError(error)
    output = w.LPVOID()
    try:
        assert convert(descriptor, 1, 5, ctypes.byref(output), None)
        sddl = ctypes.wstring_at(output)
    finally:
        if output:
            kernel.LocalFree(output)
        kernel.LocalFree(descriptor)
    whoami = Path(os.environ["SystemRoot"]) / "System32/whoami.exe"
    result = subprocess.run(
        [str(whoami), "/user", "/fo", "csv", "/nh"],
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    sid = next(csv.reader(result.stdout.strip().splitlines()))[1]
    # Empty/null DACLs, extra ACEs, and inherited grants all fail this check.
    # AI records ACL processing, granting no access. P must remain, and the
    # sole ACE must be explicit (no ID flag) for the current process user.
    assert sddl in (
        f"O:{sid}D:P(A;;FA;;;{sid})",
        f"O:{sid}D:PAI(A;;FA;;;{sid})",
    ), sddl
