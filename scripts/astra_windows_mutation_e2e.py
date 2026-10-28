"""Run owned GUI fixtures after genuine, verified foreground activation.

No input injection, desktop/session switching, focus-lock bypass or policy edits.
Activate the guardian's titlebar once when requested; only test-owned processes
receive scoped foreground grants. The production action path never focuses.
"""

import argparse
import ctypes
import importlib
import sys
import time
from ctypes import wintypes as w

import pytest
from tests.security.windows_mutation_fixture import FixtureProcess

from openjarvis.windows.observer import WindowsObserver


class OwnedFixtureOrder:
    """Run foreground-dependent cases before other fixture-window lifecycles."""

    def __init__(self, fixture_first=False, activation=None):
        self.fixture_first = fixture_first
        self.activation = activation

    def pytest_collection_finish(self):
        # Full collection can take several minutes. Foreground evidence captured
        # before it is not permission to run mutations after the user returns to
        # another application. Wait for genuine activation immediately afterward.
        # Pytest has now configured assertion rewriting for plugin dependencies.
        # Import the actual boundary before activation, not before pytest.main.
        for module in (
            "openjarvis.agents.native_react",
            "openjarvis.tools.windows",
            "openjarvis.tools.execution_journal",
            "openjarvis.traces.collector",
            "openjarvis.traces.store",
        ):
            importlib.import_module(module)
        if self.activation is not None:
            self.activation()

    def pytest_collection_modifyitems(self, items):
        positions = [
            i
            for i, item in enumerate(items)
            if item.path.name == "test_windows_mutation.py"
        ]

        def rank(item):
            if item.name == "test_process_restart_cannot_inherit_old_authorization":
                return 6
            if item.name == "test_window_recreation_requires_fresh_authorization":
                return 5
            if item.name.endswith("identity_gap[recreate]"):
                return 3
            if item.name.startswith("test_wrong_foreground"):
                return 2
            if item.name.endswith("identity_gap[foreground]"):
                return 1
            if item.name.startswith(
                (
                    "test_cross_process",
                    "test_duplicate_semantic",
                    "test_replaced_control",
                    "test_bounded_hwnd",
                )
            ):
                return 4
            return 0

        ordered = sorted((items[i] for i in positions), key=rank)
        if self.fixture_first:
            selected = set(positions)
            items[:] = ordered + [
                item for i, item in enumerate(items) if i not in selected
            ]
            return
        for index, item in zip(positions, ordered):
            items[index] = item


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--activation-timeout", type=int, default=300)
    parser.add_argument("--fixture-first", action="store_true")
    parser.add_argument("--manual-activation", action="store_true")
    args, pytest_args = parser.parse_known_args()
    if not 1 <= args.activation_timeout <= 600:
        raise ValueError("Activation timeout must be between 1 and 600 seconds")
    user = ctypes.WinDLL("user32")
    user.GetForegroundWindow.restype = w.HWND
    with FixtureProcess() as guardian, WindowsObserver(timeout=15) as observer:
        # Initialize the COM owner worker before arranging foreground. Observation
        # is read-only, and subsequent tests still capture fresh target identities.
        observer.observe(guardian.hwnd)
        guardian.rpc(
            "title",
            {
                "title": f"JARVIS Astra MAIN safety fixture PID {guardian.pid}"
                " - KEEP ACTIVE"
            },
        )
        guardian.rpc("show_front")
        if not args.manual_activation:
            try:
                guardian.focus()
            except AssertionError:
                pass  # supported request denied: genuine activation still required
        print(
            f"Test-owned guardian PID={guardian.pid} HWND={guardian.hwnd}. "
            "Activate its titlebar once; do not press its buttons. "
            "No automated mutation starts before foreground is verified.",
            flush=True,
        )
        FixtureProcess.guardian = guardian
        FixtureProcess.prewarmed_observer = observer

        def activate_after_collection():
            print(
                "Collection complete. Waiting for genuine fixture foreground.",
                flush=True,
            )
            deadline = time.perf_counter() + args.activation_timeout
            while user.GetForegroundWindow() != guardian.hwnd:
                if time.perf_counter() >= deadline:
                    pytest.exit(
                        "Foreground activation not established; "
                        "mutation E2E NOT EXECUTED.",
                        returncode=2,
                    )
                time.sleep(0.05)
            print("Genuine fixture foreground observed after collection.", flush=True)

        try:
            return pytest.main(
                pytest_args,
                plugins=[
                    OwnedFixtureOrder(args.fixture_first, activate_after_collection)
                ],
            )
        finally:
            FixtureProcess.guardian = None
            FixtureProcess.prewarmed_observer = None


if __name__ == "__main__":
    sys.exit(main())
