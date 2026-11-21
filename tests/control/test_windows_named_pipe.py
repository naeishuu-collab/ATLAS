import ctypes
import os
import threading
import time
import uuid
from types import SimpleNamespace

import pytest

import openjarvis.control.host_supervisor_bootstrap as host_bootstrap
import openjarvis.control.windows_named_pipe as windows_named_pipe
import openjarvis.control.windows_peer as windows_peer
from openjarvis.control.windows_named_pipe import (
    NamedPipeServer,
    connect_named_pipe,
    process_identity_matches,
)
from openjarvis.control.windows_peer import (
    _wait_result_is_running,
    is_process_descendant,
    parent_process_id,
    process_identity,
)


@pytest.mark.parametrize(
    ("wait_result", "running"),
    [(0x00000102, True), (0, False), (0xFFFFFFFF, False), (1, False)],
)
def test_process_identity_wait_result_fails_closed(wait_result, running):
    assert _wait_result_is_running(wait_result) is running


def test_process_identity_reports_process_and_token_close_failures(monkeypatch):
    class Kernel:
        closed = []

        def OpenProcess(self, _access, _inherit, _pid):
            return 101

        def CloseHandle(self, handle):
            self.closed.append(handle.value if hasattr(handle, "value") else handle)
            return False

        def GetProcessTimes(self, *_args):
            return False

    class Security:
        def OpenProcessToken(self, _process, _access, token_pointer):
            ctypes.cast(
                token_pointer, ctypes.POINTER(windows_peer.w.HANDLE)
            ).contents.value = 202
            return True

    kernel = Kernel()
    security = Security()
    monkeypatch.setattr(windows_peer, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_peer, "_apis", lambda: (kernel, security, None))
    monkeypatch.setattr(
        windows_peer.ctypes,
        "WinError",
        lambda _error: OSError("synthetic Windows API failure"),
        raising=False,
    )

    with pytest.raises(PermissionError, match="handles were not fully released"):
        process_identity(303)

    assert kernel.closed == [202, 101]


def test_parent_process_id_reports_snapshot_close_failure(monkeypatch):
    class Kernel:
        closed = []

        def CreateToolhelp32Snapshot(self, _flags, _pid):
            return 404

        def Process32FirstW(self, *_args):
            return False

        def CloseHandle(self, handle):
            self.closed.append(handle)
            return False

    kernel = Kernel()
    monkeypatch.setattr(windows_peer, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(windows_peer, "_apis", lambda: (kernel, None, None))

    with pytest.raises(PermissionError, match="snapshot handle close"):
        parent_process_id(505)

    assert kernel.closed == [404]


def test_named_pipe_rejects_non_windows_name():
    with pytest.raises(ValueError):
        NamedPipeServer("not-a-windows-pipe")
    with pytest.raises(ValueError):
        NamedPipeServer(r"\\.\pipe\atlas-日本語")


def test_named_pipe_handle_close_failure_is_retained_and_not_retried(monkeypatch):
    class Kernel:
        calls = []

        def CloseHandle(self, handle):
            self.calls.append(handle)
            return False

    kernel = Kernel()
    monkeypatch.setattr(windows_named_pipe, "_apis", lambda: (kernel, None))
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "get_last_error",
        lambda: 5,
        raising=False,
    )
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "WinError",
        lambda error: OSError(error, "synthetic CloseHandle failure"),
        raising=False,
    )
    pipe = object.__new__(windows_named_pipe.NamedPipeHandle)
    pipe.handle = 123
    pipe._closed = False
    pipe._close_attempted = False
    pipe._close_unconfirmed = False
    pipe._close_lock = threading.Lock()

    with pytest.raises(OSError, match="CloseHandle failure"):
        pipe.close()
    assert pipe.handle == 123
    assert pipe._closed is False
    assert pipe._close_unconfirmed is True
    with pytest.raises(OSError, match="unconfirmed"):
        pipe.close()
    assert kernel.calls == [123]


def test_named_pipe_handle_setup_failure_reports_unconfirmed_close(monkeypatch):
    class Kernel:
        close_calls = []

        def SetNamedPipeHandleState(self, *_args):
            return False

        def CloseHandle(self, handle):
            self.close_calls.append(handle)
            return False

    kernel = Kernel()
    monkeypatch.setattr(windows_named_pipe, "_apis", lambda: (kernel, None))
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "get_last_error",
        lambda: 5,
        raising=False,
    )
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "WinError",
        lambda error: OSError(error, "synthetic CloseHandle failure"),
        raising=False,
    )

    with pytest.raises(OSError, match="CloseHandle failure") as failure:
        windows_named_pipe.NamedPipeHandle(124)

    assert failure.value.handle == 124
    assert failure.value.close_unconfirmed is True
    assert kernel.close_calls == [124]


def test_named_pipe_server_close_failure_retains_handle_and_is_not_retried(
    monkeypatch,
):
    class Kernel:
        close_calls = []
        cancel_calls = []

        def CancelIoEx(self, handle, _overlapped):
            self.cancel_calls.append(handle)
            return True

        def CloseHandle(self, handle):
            self.close_calls.append(handle)
            return False

    kernel = Kernel()
    monkeypatch.setattr(windows_named_pipe, "_apis", lambda: (kernel, None))
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "get_last_error",
        lambda: 5,
        raising=False,
    )
    monkeypatch.setattr(
        windows_named_pipe.ctypes,
        "WinError",
        lambda error: OSError(error, "synthetic CloseHandle failure"),
        raising=False,
    )
    server = object.__new__(NamedPipeServer)
    server.name = r"\\.\pipe\atlas-test"
    server._closed = False
    server._close_attempted = False
    server._close_unconfirmed = False
    server._cancel_attempted = False
    server._state_lock = threading.Lock()
    server._handle = 456

    with pytest.raises(OSError, match="CloseHandle failure"):
        server.close()
    assert server._handle == 456
    assert server._closed is False
    assert server._close_unconfirmed is True
    with pytest.raises(OSError, match="unconfirmed"):
        server.close()
    assert kernel.cancel_calls == [456]
    assert kernel.close_calls == [456]


def test_host_bootstrap_preserves_broker_and_server_when_drain_fails():
    class Server:
        def close(self):
            pass

    class Broker:
        _close_complete = False

        def __init__(self):
            self.calls = 0

        def close(self):
            self.calls += 1
            raise OSError("synthetic broker drain failure")

    class Manager:
        def __init__(self):
            self.calls = 0

        def close(self):
            self.calls += 1

    server = Server()
    broker = Broker()
    manager = Manager()
    service = object.__new__(host_bootstrap.HostSupervisorBootstrapService)
    service._lock = threading.RLock()
    service._close_lock = threading.Lock()
    service._closed = threading.Event()
    service._close_complete = False
    service._cleanup_unconfirmed = False
    service._cleanup_error = None
    service._server = server
    service._active_connection = None
    service._thread = None
    service._brokers = {"task-a": SimpleNamespace(broker=broker)}
    service.manager = manager

    with pytest.raises(RuntimeError, match="cleanup is unconfirmed"):
        service.close()

    assert service._server is server
    assert service._brokers["task-a"].broker is broker
    assert service._close_complete is False
    assert service._cleanup_unconfirmed is True
    assert manager.calls == 0
    with pytest.raises(RuntimeError, match="cleanup is unconfirmed"):
        service.close()
    assert broker.calls == 1


def test_host_bootstrap_rejects_pid_reuse_after_pipe_identity_lookup(monkeypatch):
    service = object.__new__(host_bootstrap.HostSupervisorBootstrapService)
    service._lock = threading.RLock()
    service._service_identity = {
        "pid": 10,
        "created_filetime": 1,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    service._launcher_identity = {
        "pid": 11,
        "created_filetime": 2,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    client = {
        "pid": 12,
        "created_filetime": 3,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    reused_pid = {**client, "created_filetime": 4}
    monkeypatch.setattr(host_bootstrap, "is_process_descendant", lambda *_: True)
    monkeypatch.setattr(host_bootstrap, "process_identity", lambda _pid: reused_pid)

    with pytest.raises(PermissionError, match="OS identity rejected"):
        service._validate_client(client)


@pytest.mark.parametrize(
    ("field", "value"),
    [("user_sid", "S-1-other"), ("integrity_rid", 4096)],
)
def test_host_bootstrap_rejects_controller_token_mismatch(monkeypatch, field, value):
    service = object.__new__(host_bootstrap.HostSupervisorBootstrapService)
    service._lock = threading.RLock()
    service._service_identity = {"user_sid": "S-1-test", "integrity_rid": 8192}
    service._launcher_identity = None
    service._current_session_id = None
    identity = {"pid": 12, **service._service_identity}
    identity[field] = value
    monkeypatch.setattr(host_bootstrap, "process_identity", lambda _pid: identity)

    with pytest.raises(PermissionError, match="Host Controller token mismatch"):
        service.register_controller(12)


def test_host_bootstrap_rejects_same_user_process_outside_host_tree(monkeypatch):
    service = object.__new__(host_bootstrap.HostSupervisorBootstrapService)
    service._lock = threading.RLock()
    service._service_identity = {
        "pid": 10,
        "created_filetime": 1,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    service._launcher_identity = {
        "pid": 11,
        "created_filetime": 2,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    client = {
        "pid": 12,
        "created_filetime": 3,
        "user_sid": "S-1-test",
        "integrity_rid": 8192,
    }
    monkeypatch.setattr(host_bootstrap, "is_process_descendant", lambda *_: False)
    monkeypatch.setattr(
        host_bootstrap,
        "process_identity",
        lambda _pid: pytest.fail("sibling process must fail before identity reuse"),
    )

    with pytest.raises(PermissionError, match="OS identity rejected"):
        service._validate_client(client)


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe OS boundary")
def test_named_pipe_acl_framing_and_process_identity():
    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s15-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    result = {}

    def serve_once():
        try:
            with server.accept() as connection:
                result["client"] = connection.client_identity()
                result["request"] = connection.receive()
                connection.send({"ok": True})
        except Exception as exc:  # surfaced in the main test thread
            result["error"] = exc

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    with connect_named_pipe(
        pipe_name,
        expected_server_pid=identity["pid"],
        expected_server_created_filetime=identity["created_filetime"],
    ) as connection:
        connection.send({"operation": "synthetic", "sequence": 1})
        assert connection.receive() == {"ok": True}
    thread.join(timeout=5)
    server.close()

    assert not thread.is_alive()
    assert "error" not in result
    assert process_identity_matches(result["client"], identity)
    assert result["request"] == {"operation": "synthetic", "sequence": 1}


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe OS boundary")
def test_named_pipe_rejects_reused_server_pid_binding():
    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s15-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    accepted = threading.Event()

    def serve_once():
        try:
            with server.accept():
                accepted.set()
        except OSError:
            pass

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    try:
        with pytest.raises(PermissionError, match="server identity mismatch"):
            connect_named_pipe(
                pipe_name,
                expected_server_pid=identity["pid"],
                expected_server_created_filetime=identity["created_filetime"] + 1,
            )
    finally:
        server.close()
    thread.join(timeout=5)
    assert accepted.is_set()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe OS boundary")
def test_named_pipe_closes_stalled_local_peer(monkeypatch):
    monkeypatch.setattr(windows_named_pipe, "_PIPE_READ_TIMEOUT", 0.05)
    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s15-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    result = {}

    def serve_once():
        try:
            with server.accept() as connection:
                connection.receive()
        except TimeoutError:
            result["timed_out"] = True

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    with connect_named_pipe(
        pipe_name,
        expected_server_pid=identity["pid"],
        expected_server_created_filetime=identity["created_filetime"],
    ):
        time.sleep(0.1)
    thread.join(timeout=5)
    server.close()

    assert not thread.is_alive()
    assert result == {"timed_out": True}


@pytest.mark.skipif(os.name != "nt", reason="Windows process tree boundary")
def test_process_tree_pins_creation_time():
    identity = process_identity(os.getpid())
    parent_pid = parent_process_id(os.getpid())
    assert parent_pid > 0
    assert is_process_descendant(os.getpid(), identity)
    assert not is_process_descendant(
        os.getpid(), {**identity, "created_filetime": identity["created_filetime"] + 1}
    )


def test_process_tree_rejects_reused_intermediate_parent_pid(monkeypatch):
    identities = {
        10: {
            "pid": 10,
            "created_filetime": 10,
            "user_sid": "S-1-test",
            "integrity_rid": 8192,
        },
        20: {
            "pid": 20,
            "created_filetime": 20,
            "user_sid": "S-1-test",
            "integrity_rid": 8192,
        },
        30: {
            "pid": 30,
            "created_filetime": 15,
            "user_sid": "S-1-test",
            "integrity_rid": 8192,
        },
    }
    monkeypatch.setattr(windows_peer, "process_identity", identities.__getitem__)
    monkeypatch.setattr(
        windows_peer, "parent_process_id", lambda pid: {20: 30, 30: 10}[pid]
    )

    assert windows_peer.is_process_descendant(20, identities[10])
    identities[30] = {**identities[30], "created_filetime": 21}
    assert not windows_peer.is_process_descendant(20, identities[10])


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe ACL")
def test_named_pipe_dacl_is_protected_and_authz_denies_synthetic_foreign_sid():
    import ctypes
    import json
    from ctypes import wintypes as w

    from openjarvis.security.windows_acl import _api

    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s19-acl-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    kernel, security = _api()
    actual_owner, actual_dacl, actual_sd = w.LPVOID(), w.LPVOID(), w.LPVOID()
    authz = None
    resource_manager = w.LPVOID()
    try:
        error = security.GetSecurityInfo(
            w.HANDLE(server._handle),
            6,  # SE_KERNEL_OBJECT; GetSecurityInfo supports named pipes.
            5,  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
            ctypes.byref(actual_owner),
            None,
            ctypes.byref(actual_dacl),
            None,
            ctypes.byref(actual_sd),
        )
        if error:
            raise ctypes.WinError(error)
        if not actual_dacl:
            raise PermissionError("Named pipe DACL was not returned")

        class AclSizeInformation(ctypes.Structure):
            _fields_ = [
                ("ace_count", w.DWORD),
                ("bytes_in_use", w.DWORD),
                ("bytes_free", w.DWORD),
            ]

        class AceHeader(ctypes.Structure):
            _fields_ = [
                ("ace_type", w.BYTE),
                ("ace_flags", w.BYTE),
                ("ace_size", w.WORD),
            ]

        class AllowedAce(ctypes.Structure):
            _fields_ = [
                ("header", AceHeader),
                ("mask", w.DWORD),
                ("sid_start", w.DWORD),
            ]

        security.GetAclInformation.argtypes = [
            w.LPVOID,
            w.LPVOID,
            w.DWORD,
            w.DWORD,
        ]
        security.GetAclInformation.restype = w.BOOL
        security.GetAce.argtypes = [w.LPVOID, w.DWORD, w.LPVOID]
        security.GetAce.restype = w.BOOL
        info = AclSizeInformation()
        if not security.GetAclInformation(
            actual_dacl, ctypes.byref(info), ctypes.sizeof(info), 2
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        entries = []
        for index in range(info.ace_count):
            ace_pointer = w.LPVOID()
            if not security.GetAce(actual_dacl, index, ctypes.byref(ace_pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(AllowedAce)).contents
            if ace.header.ace_type != 0:
                entries.append({"type": ace.header.ace_type})
                continue
            sid = w.LPVOID()
            sid_pointer = ctypes.c_void_p(
                ctypes.addressof(ace) + AllowedAce.sid_start.offset
            )
            if not security.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                sid_text = ctypes.wstring_at(sid)
            finally:
                kernel.LocalFree(sid)
            entries.append(
                {"sid": sid_text, "mask": ace.mask, "flags": ace.header.ace_flags}
            )
        control, revision = w.WORD(), w.DWORD()
        if not security.GetSecurityDescriptorControl(
            actual_sd, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        expected_sids = {"S-1-5-18", identity["user_sid"]}
        file_all_access = 0x001F01FF  # GENERIC_ALL after named-pipe mapping.
        exact_allowlist = (
            len(entries) == 2
            and {entry.get("sid") for entry in entries} == expected_sids
            and all(entry.get("mask") == file_all_access for entry in entries)
            and all(entry.get("flags") == 0 for entry in entries)
        )
        dacl_present = bool(control.value & 0x0004)
        protected = bool(control.value & 0x1000)
        assert dacl_present and exact_allowlist and protected, {
            "entries": entries,
            "control": control.value,
        }

        class Luid(ctypes.Structure):
            _fields_ = [("low_part", w.DWORD), ("high_part", w.LONG)]

        class AccessRequest(ctypes.Structure):
            _fields_ = [
                ("desired_access", w.DWORD),
                ("principal_self_sid", w.LPVOID),
                ("object_type_list", w.LPVOID),
                ("object_type_list_length", w.DWORD),
                ("optional_arguments", w.LPVOID),
            ]

        class AccessReply(ctypes.Structure):
            _fields_ = [
                ("result_list_length", w.DWORD),
                ("granted_access_mask", ctypes.POINTER(w.DWORD)),
                ("sacl_evaluation_results", ctypes.POINTER(w.DWORD)),
                ("error", ctypes.POINTER(w.DWORD)),
            ]

        authz = ctypes.WinDLL("authz.dll", use_last_error=True)
        authz.AuthzInitializeResourceManager.argtypes = [
            w.DWORD,
            w.LPVOID,
            w.LPVOID,
            w.LPVOID,
            w.LPCWSTR,
            ctypes.POINTER(w.LPVOID),
        ]
        authz.AuthzInitializeResourceManager.restype = w.BOOL
        authz.AuthzFreeResourceManager.argtypes = [w.LPVOID]
        authz.AuthzFreeResourceManager.restype = w.BOOL
        if not authz.AuthzInitializeResourceManager(
            1,
            None,
            None,
            None,
            "ATLAS named-pipe DACL test",
            ctypes.byref(resource_manager),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        authz.AuthzInitializeContextFromSid.argtypes = [
            w.DWORD,
            w.LPVOID,
            w.LPVOID,
            w.LPVOID,
            Luid,
            w.LPVOID,
            ctypes.POINTER(w.LPVOID),
        ]
        authz.AuthzInitializeContextFromSid.restype = w.BOOL
        authz.AuthzFreeContext.argtypes = [w.LPVOID]
        authz.AuthzFreeContext.restype = w.BOOL
        authz.AuthzAccessCheck.argtypes = [
            w.DWORD,
            w.LPVOID,
            ctypes.POINTER(AccessRequest),
            w.LPVOID,
            w.LPVOID,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(AccessReply),
            w.LPVOID,
        ]
        authz.AuthzAccessCheck.restype = w.BOOL

        def check_sid(sid_text):
            sid = w.LPVOID()
            if not security.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            context = w.LPVOID()
            try:
                if not authz.AuthzInitializeContextFromSid(
                    2,
                    sid,
                    resource_manager,
                    None,
                    Luid(0, 0),
                    None,
                    ctypes.byref(context),
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                granted = (w.DWORD * 1)()
                sacl_results = (w.DWORD * 1)()
                errors = (w.DWORD * 1)()
                request = AccessRequest(0x001F01FF, None, None, 0, None)
                reply = AccessReply(1, granted, sacl_results, errors)
                if not authz.AuthzAccessCheck(
                    0,
                    context,
                    ctypes.byref(request),
                    None,
                    actual_sd,
                    None,
                    0,
                    ctypes.byref(reply),
                    None,
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                return int(granted[0]), int(errors[0])
            finally:
                if context:
                    authz.AuthzFreeContext(context)
                kernel.LocalFree(sid)

        # shortcut: synthetic SID only; add foreign-user process when available.
        foreign_sid = "S-1-5-21-123456789-987654321-1122334455-424242"
        foreign_access = check_sid(foreign_sid)
        owner_access = check_sid(identity["user_sid"])
        assert foreign_access == (0, 5), {
            "foreign_sid": foreign_sid,
            "result": foreign_access,
        }
        assert owner_access == (0x001F01FF, 0), {
            "owner_sid": identity["user_sid"],
            "result": owner_access,
        }
        print(
            json.dumps(
                {
                    "pipe_server_pid": identity["pid"],
                    "expected_sids": sorted(expected_sids),
                    "actual_entries": entries,
                    "dacl_present": dacl_present,
                    "protected_dacl": protected,
                    "foreign_sid_access_check": {
                        "granted_mask": foreign_access[0],
                        "error": foreign_access[1],
                    },
                    "owner_sid_access_check": {
                        "granted_mask": owner_access[0],
                        "error": owner_access[1],
                    },
                },
                sort_keys=True,
            )
        )
    finally:
        if resource_manager and authz:
            authz.AuthzFreeResourceManager(resource_manager)
        if actual_sd:
            kernel.LocalFree(actual_sd)
        server.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe ACL")
def test_named_pipe_dacl_denies_kernel_open_from_restricted_sid_token():
    import ctypes
    import json
    from ctypes import wintypes as w

    from openjarvis.security.windows_acl import _api

    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s19-restricted-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    kernel, security = _api()
    foreign_sid = "S-1-5-21-123456789-987654321-1122334455-424242"
    foreign_sid_ptr = w.LPVOID()
    primary_token, restricted_token = w.HANDLE(), w.HANDLE()
    impersonating = False

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", w.LPVOID), ("attributes", w.DWORD)]

    try:
        security.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(w.LPVOID)]
        security.ConvertStringSidToSidW.restype = w.BOOL
        security.OpenProcessToken.argtypes = [
            w.HANDLE,
            w.DWORD,
            ctypes.POINTER(w.HANDLE),
        ]
        security.OpenProcessToken.restype = w.BOOL
        security.CreateRestrictedToken.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.DWORD,
            ctypes.POINTER(SidAndAttributes),
            w.DWORD,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(SidAndAttributes),
            ctypes.POINTER(w.HANDLE),
        ]
        security.CreateRestrictedToken.restype = w.BOOL
        security.IsTokenRestricted.argtypes = [w.HANDLE]
        security.IsTokenRestricted.restype = w.BOOL
        security.ImpersonateLoggedOnUser.argtypes = [w.HANDLE]
        security.ImpersonateLoggedOnUser.restype = w.BOOL
        security.RevertToSelf.argtypes = []
        security.RevertToSelf.restype = w.BOOL

        if not security.ConvertStringSidToSidW(
            foreign_sid, ctypes.byref(foreign_sid_ptr)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_entry = SidAndAttributes(foreign_sid_ptr, 0)
        if not security.OpenProcessToken(
            kernel.GetCurrentProcess(), 0x0002 | 0x0008, ctypes.byref(primary_token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.CreateRestrictedToken(
            primary_token,
            0,
            0,
            None,
            0,
            None,
            1,
            ctypes.byref(sid_entry),
            ctypes.byref(restricted_token),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.IsTokenRestricted(restricted_token):
            raise AssertionError("synthetic restricting SID was not applied")
        if not security.ImpersonateLoggedOnUser(restricted_token):
            raise ctypes.WinError(ctypes.get_last_error())
        impersonating = True
        try:
            ctypes.set_last_error(0)
            client = kernel.CreateFileW(
                pipe_name, 0xC0000000, 0, None, 3, 0x00000080, None
            )
            error = ctypes.get_last_error()
            if client != ctypes.c_void_p(-1).value:
                kernel.CloseHandle(client)
                error = 0
        finally:
            if not security.RevertToSelf():
                raise ctypes.WinError(ctypes.get_last_error())
            impersonating = False

        assert error == 5, {
            "expected": "ERROR_ACCESS_DENIED",
            "actual_error": error,
            "user_sid": identity["user_sid"],
            "restricting_sid": foreign_sid,
        }
        print(
            json.dumps(
                {
                    "pipe_server_pid": identity["pid"],
                    "thread_impersonation_pid": os.getpid(),
                    "token_user_sid": identity["user_sid"],
                    "restricting_sid": foreign_sid,
                    "token_restricted": True,
                    "kernel_create_file_error": error,
                },
                sort_keys=True,
            )
        )
    finally:
        if impersonating and not security.RevertToSelf():
            raise ctypes.WinError(ctypes.get_last_error())
        if restricted_token:
            kernel.CloseHandle(restricted_token)
        if primary_token:
            kernel.CloseHandle(primary_token)
        if foreign_sid_ptr:
            kernel.LocalFree(foreign_sid_ptr)
        server.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows named-pipe integrity label")
# shortcut: thread-only test, upgrade when an approved child launcher exists.
def test_named_pipe_denies_low_integrity_write_even_for_owner_sid():
    import ctypes
    import json
    from ctypes import wintypes as w

    from openjarvis.security.windows_acl import _api

    identity = process_identity(os.getpid())
    pipe_name = rf"\\.\pipe\atlas-s19-low-integrity-{uuid.uuid4().hex}"
    server = NamedPipeServer(pipe_name)
    kernel, security = _api()
    primary_token, low_token, thread_token = w.HANDLE(), w.HANDLE(), w.HANDLE()
    low_sid, actual_sacl, actual_sd = w.LPVOID(), w.LPVOID(), w.LPVOID()
    impersonating = False

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", w.LPVOID), ("attributes", w.DWORD)]

    class TokenMandatoryLabel(ctypes.Structure):
        _fields_ = [("label", SidAndAttributes)]

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("ace_count", w.DWORD),
            ("bytes_in_use", w.DWORD),
            ("bytes_free", w.DWORD),
        ]

    class AceHeader(ctypes.Structure):
        _fields_ = [
            ("ace_type", w.BYTE),
            ("ace_flags", w.BYTE),
            ("ace_size", w.WORD),
        ]

    class LabelAce(ctypes.Structure):
        _fields_ = [("header", AceHeader), ("mask", w.DWORD), ("sid_start", w.DWORD)]

    def token_sid(token, token_info_class):
        needed = w.DWORD()
        security.GetTokenInformation(
            token, token_info_class, None, 0, ctypes.byref(needed)
        )
        if not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(
            token, token_info_class, buffer, needed.value, ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_entry = ctypes.cast(buffer, ctypes.POINTER(SidAndAttributes)).contents
        sid_text = w.LPVOID()
        if not security.ConvertSidToStringSidW(sid_entry.sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(sid_text)
        finally:
            kernel.LocalFree(sid_text)

    try:
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.GetCurrentThread.restype = w.HANDLE
        security.OpenProcessToken.argtypes = [
            w.HANDLE,
            w.DWORD,
            ctypes.POINTER(w.HANDLE),
        ]
        security.OpenProcessToken.restype = w.BOOL
        security.DuplicateTokenEx.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.LPVOID,
            w.DWORD,
            w.DWORD,
            ctypes.POINTER(w.HANDLE),
        ]
        security.DuplicateTokenEx.restype = w.BOOL
        security.SetTokenInformation.argtypes = [w.HANDLE, w.DWORD, w.LPVOID, w.DWORD]
        security.SetTokenInformation.restype = w.BOOL
        security.GetTokenInformation.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        security.GetTokenInformation.restype = w.BOOL
        security.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(w.LPVOID)]
        security.ConvertStringSidToSidW.restype = w.BOOL
        security.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPVOID)]
        security.ConvertSidToStringSidW.restype = w.BOOL
        security.GetLengthSid.argtypes = [w.LPVOID]
        security.GetLengthSid.restype = w.DWORD
        security.ImpersonateLoggedOnUser.argtypes = [w.HANDLE]
        security.ImpersonateLoggedOnUser.restype = w.BOOL
        security.OpenThreadToken.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.BOOL,
            ctypes.POINTER(w.HANDLE),
        ]
        security.OpenThreadToken.restype = w.BOOL
        security.RevertToSelf.argtypes = []
        security.RevertToSelf.restype = w.BOOL
        security.GetSecurityInfo.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.DWORD,
            w.LPVOID,
            w.LPVOID,
            w.LPVOID,
            ctypes.POINTER(w.LPVOID),
            ctypes.POINTER(w.LPVOID),
        ]
        security.GetSecurityInfo.restype = w.DWORD
        security.GetAclInformation.argtypes = [w.LPVOID, w.LPVOID, w.DWORD, w.DWORD]
        security.GetAclInformation.restype = w.BOOL
        security.GetAce.argtypes = [w.LPVOID, w.DWORD, ctypes.POINTER(w.LPVOID)]
        security.GetAce.restype = w.BOOL
        security.RevertToSelf.argtypes = []
        security.RevertToSelf.restype = w.BOOL

        medium_client = kernel.CreateFileW(
            pipe_name, 0x40000000, 0, None, 3, 0x00000080, None
        )
        if medium_client == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(medium_client)

        error = security.GetSecurityInfo(
            w.HANDLE(server._handle),
            6,
            0x10,  # LABEL_SECURITY_INFORMATION; querying a label needs READ_CONTROL.
            None,
            None,
            None,
            ctypes.byref(actual_sacl),
            ctypes.byref(actual_sd),
        )
        if error:
            raise ctypes.WinError(error)
        # Windows treats unlabeled objects as medium/no-write-up.
        pipe_integrity_rid, pipe_integrity_policy = 8192, 1
        if actual_sacl:
            acl_info = AclSizeInformation()
            if not security.GetAclInformation(
                actual_sacl, ctypes.byref(acl_info), ctypes.sizeof(acl_info), 2
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            for index in range(acl_info.ace_count):
                ace_pointer = w.LPVOID()
                if not security.GetAce(actual_sacl, index, ctypes.byref(ace_pointer)):
                    raise ctypes.WinError(ctypes.get_last_error())
                ace = ctypes.cast(ace_pointer, ctypes.POINTER(LabelAce)).contents
                if ace.header.ace_type == 0x11:  # SYSTEM_MANDATORY_LABEL_ACE
                    sid_pointer = ctypes.c_void_p(
                        ctypes.addressof(ace) + LabelAce.sid_start.offset
                    )
                    label_sid = w.LPVOID()
                    if not security.ConvertSidToStringSidW(
                        sid_pointer, ctypes.byref(label_sid)
                    ):
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        pipe_integrity_rid = int(
                            ctypes.wstring_at(label_sid).rsplit("-", 1)[-1]
                        )
                    finally:
                        kernel.LocalFree(label_sid)
                    pipe_integrity_policy = ace.mask
                    break

        if not security.OpenProcessToken(
            kernel.GetCurrentProcess(), 0x0002 | 0x0008, ctypes.byref(primary_token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.DuplicateTokenEx(
            primary_token, 0x0008 | 0x0004 | 0x0080, None, 2, 2, ctypes.byref(low_token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.ConvertStringSidToSidW("S-1-16-4096", ctypes.byref(low_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        low_label = TokenMandatoryLabel(SidAndAttributes(low_sid, 0x20))
        label_size = ctypes.sizeof(low_label) + security.GetLengthSid(low_sid)
        if not security.SetTokenInformation(
            low_token, 25, ctypes.byref(low_label), label_size
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        low_integrity_sid = token_sid(low_token, 25)
        assert low_integrity_sid == "S-1-16-4096", low_integrity_sid
        assert int(low_integrity_sid.rsplit("-", 1)[-1]) < pipe_integrity_rid
        assert pipe_integrity_policy & 1, hex(pipe_integrity_policy)
        if not security.ImpersonateLoggedOnUser(low_token):
            raise ctypes.WinError(ctypes.get_last_error())
        impersonating = True
        try:
            if not security.OpenThreadToken(
                kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(thread_token)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            assert token_sid(thread_token, 1) == identity["user_sid"]
            assert token_sid(thread_token, 25) == "S-1-16-4096"
            ctypes.set_last_error(0)
            client = kernel.CreateFileW(
                pipe_name, 0x40000000, 0, None, 3, 0x00000080, None
            )
            error = ctypes.get_last_error()
            if client != ctypes.c_void_p(-1).value:
                kernel.CloseHandle(client)
                error = 0
        finally:
            if not security.RevertToSelf():
                raise ctypes.WinError(ctypes.get_last_error())
            impersonating = False

        assert error == 5, {"expected": "ERROR_ACCESS_DENIED", "actual_error": error}
        print(
            json.dumps(
                {
                    "pipe_server_pid": identity["pid"],
                    "thread_impersonation_pid": os.getpid(),
                    "token_user_sid": identity["user_sid"],
                    "low_integrity_sid": low_integrity_sid,
                    "pipe_integrity_rid": pipe_integrity_rid,
                    "pipe_integrity_policy": pipe_integrity_policy,
                    "owner_integrity_rid": identity["integrity_rid"],
                    "owner_write_open": "allowed",
                    "low_integrity_owner_write_error": error,
                },
                sort_keys=True,
            )
        )
    finally:
        if impersonating and not security.RevertToSelf():
            raise ctypes.WinError(ctypes.get_last_error())
        for token in (thread_token, low_token, primary_token):
            if token:
                kernel.CloseHandle(token)
        if low_sid:
            kernel.LocalFree(low_sid)
        if actual_sd:
            kernel.LocalFree(actual_sd)
        server.close()
