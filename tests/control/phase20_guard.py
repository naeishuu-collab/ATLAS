"""Explicit pytest-only guard for the Phase 20 reviewed Mock/local lane.

Python audit hooks supplement the allowlist; they are not an OS sandbox.
"""

from __future__ import annotations

import ipaddress
import sys


def _loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError):
        return False


def deny_side_effect(event, args):
    if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
                 "_winapi.CreateProcess", "os.startfile"}:
        raise PermissionError("PHASE20_SUBPROCESS_DENIED")
    if event in {"socket.connect", "socket.bind", "socket.sendto"}:
        address = args[-1]
        if not isinstance(address, tuple) or not _loopback(address[0]):
            raise PermissionError("PHASE20_EXTERNAL_NETWORK_DENIED")
    if event in {"socket.getaddrinfo", "socket.gethostbyname",
                 "socket.gethostbyaddr"} and not _loopback(args[0]):
        raise PermissionError("PHASE20_EXTERNAL_DNS_DENIED")


def pytest_load_initial_conftests(early_config, parser, args):
    sys.addaudithook(deny_side_effect)
