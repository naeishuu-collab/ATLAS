"""Real Windows/UIA reads against hidden isolated synthetic windows."""

import multiprocessing
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from openjarvis.windows.identity import IdentityError
from openjarvis.windows.observer import WindowsObserver

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Real Windows UIA fixture")


def _unresponsive_worker(connection, max_controls):
    threading.Event().wait(60)


def _unresponsive_request_worker(connection, max_controls):
    connection.send_bytes(b'{"ready":true}')
    connection.recv_bytes()
    threading.Event().wait(60)


def _application_fixture(connection):
    from tests.security.windows_fixture import FixtureWindow

    window = FixtureWindow()
    try:
        connection.send((window.hwnd, os.getpid()))
        connection.recv()
    finally:
        window.close()
        connection.close()


@pytest.mark.parametrize("worker", [_unresponsive_worker, _unresponsive_request_worker])
def test_owned_worker_timeout_terminates_without_target_recovery(
    monkeypatch, worker, window
):
    from openjarvis.windows import observer as module

    monkeypatch.setattr(module, "_worker", worker)
    with WindowsObserver(timeout=0.5) as observer:
        before = {p.pid for p in multiprocessing.active_children()}
        started = time.perf_counter()
        with pytest.raises(TimeoutError):
            observer.observe(window.hwnd)
        assert time.perf_counter() - started < 6
        assert not observer._state
        assert {p.pid for p in multiprocessing.active_children()} == before
        with pytest.raises(IdentityError, match="No retained"):
            observer.select("old", name="Save")


def test_real_application_restart_requires_explicit_new_observation():
    context = multiprocessing.get_context("spawn")
    processes = []
    pipes = []
    try:
        with WindowsObserver(timeout=15) as observer:
            previous = None
            for _ in range(2):
                host, child = context.Pipe()
                process = context.Process(target=_application_fixture, args=(child,))
                processes.append(process)
                pipes.append(host)
                process.start()
                child.close()
                assert host.poll(10)
                hwnd, pid = host.recv()
                current = observer.observe(hwnd)
                assert current["window"]["process"]["pid"] == pid
                target = observer.select(current["observation_id"], automation_id="201")
                if previous:
                    assert current["window"]["process"] != previous["window"]["process"]
                    assert current["observation_id"] != previous["observation_id"]
                host.send("close")
                process.join(10)
                assert process.exitcode == 0
                with pytest.raises(IdentityError):
                    observer.validate(
                        current["observation_id"], target, require_foreground=False
                    )
                assert not observer._state
                previous = current
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(3)
        for connection in pipes:
            connection.close()


@pytest.fixture
def window():
    from tests.security.windows_fixture import FixtureWindow

    fixture = FixtureWindow()
    yield fixture
    fixture.close()


def test_real_process_window_and_uia_identity(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        identity = observation["window"]
        assert identity["process"]["pid"] == os.getpid()
        assert identity["process"]["created_filetime"] > 0
        assert identity["process"]["executable"].endswith("python.exe")
        assert identity["hwnd"] == window.hwnd
        assert identity["thread_id"] > 0
        assert identity["class_name"] == "#32770"
        buttons = [c for c in observation["controls"] if c["name"] == "Save"]
        assert len(buttons) == 2
        assert {c["identity"]["automation_id"] for c in buttons} == {"201", "202"}
        for control in buttons:
            identity = control["identity"]
            assert identity["runtime_id"]
            assert identity["process_id"] == os.getpid()
            assert identity["hwnd"] in window.controls
            assert identity["control_type"] == 50000
            assert identity["class_name"] == "Button"
            assert identity["framework"] == "Win32"
            assert len(identity["hierarchy"]) == 2
        target = observer.select(observation["observation_id"], automation_id="201")
        assert target in {c["target_id"] for c in buttons}


def test_real_duplicate_name_has_no_first_match(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        process = observer._state["process"]
        with pytest.raises(IdentityError, match="2 matches"):
            observer.select(observation["observation_id"], name="Save")
        assert not process.is_alive()
        assert not observer._state


def test_real_wrong_foreground_refused(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        assert observation["foreground_hwnd"] != window.hwnd  # hidden fixture
        target = observer.select(observation["observation_id"], automation_id="201")
        with pytest.raises(IdentityError, match="Wrong foreground"):
            observer.validate(observation["observation_id"], target)


def test_real_hidden_control_preconditions_refused(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        target = observer.select(observation["observation_id"], automation_id="201")
        with pytest.raises(IdentityError, match="preconditions"):
            observer.validate(
                observation["observation_id"], target, require_foreground=False
            )


def test_real_same_name_target_replacement_invalidates_observation(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        target = observer.select(observation["observation_id"], automation_id="201")
        window.replace_button()
        with pytest.raises(IdentityError, match="mismatch|Stale|COMError"):
            observer.validate(
                observation["observation_id"], target, require_foreground=False
            )
        assert not observer._state


def test_real_window_recreation_refused(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        target = observer.select(observation["observation_id"], automation_id="201")
        window.recreate_window()
        with pytest.raises(IdentityError):
            observer.validate(
                observation["observation_id"], target, require_foreground=False
            )


def test_real_stale_observation_and_foreign_target_id_refused(window):
    with WindowsObserver(timeout=15) as observer:
        old = observer.observe(window.hwnd)
        current = observer.observe(window.hwnd)
        assert old["observation_id"] != current["observation_id"]
        with pytest.raises(IdentityError, match="Stale or unknown"):
            observer.select(old["observation_id"], automation_id="201")


def test_real_enumeration_limit_fails_closed(window):
    with WindowsObserver(timeout=15, max_controls=1) as observer:
        with pytest.raises(IdentityError, match="limit exceeded"):
            observer.observe(window.hwnd)
        assert not observer._state


def test_real_worker_crash_cannot_recover_semantically(window):
    with WindowsObserver(timeout=15) as observer:
        observation = observer.observe(window.hwnd)
        process = observer._state["process"]
        process.terminate()
        process.join(3)
        with pytest.raises((IdentityError, OSError, EOFError)):
            observer.select(observation["observation_id"], automation_id="201")
        assert not observer._state
        fresh = observer.observe(window.hwnd)  # explicit new read only
        assert fresh["observation_id"] != observation["observation_id"]


def test_real_observation_owner_process_from_multiple_callers(window):
    with WindowsObserver(timeout=15) as observer:
        with ThreadPoolExecutor(max_workers=2) as pool:
            observations = list(
                pool.map(lambda _: observer.observe(window.hwnd), range(2))
            )
        assert observations[0]["observation_id"] != observations[1]["observation_id"]
        assert observer._state["process"].pid != os.getpid()
    assert threading.current_thread() is threading.main_thread()


@pytest.mark.parametrize("hwnd", [0, -1, True, "123", 1 << 65])
def test_invalid_hwnd_cannot_wrap_into_another_target(hwnd):
    with WindowsObserver() as observer:
        with pytest.raises(IdentityError):
            observer.observe(hwnd)
        assert not observer._state
