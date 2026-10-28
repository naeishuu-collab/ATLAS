"""Offline Phase 21-23 SDK presence and fail-closed adapter tests."""

from __future__ import annotations

import json

import pytest

from openjarvis.control.oss_adapter import (
    AdapterMode,
    ControlSurface,
    ObservationSnapshot,
)
from openjarvis.control.sdk_gate import (
    BROWSER_USE,
    UFO,
    BrowserUseAdapter,
    SdkStatus,
    UFOAdapter,
    inspect_sdk,
    negotiate_capabilities,
)
from openjarvis.core.execution import ExecutionState


def _browser_transcript() -> str:
    return json.dumps(
        {
            "action_id": "a1",
            "observation_id": "o1",
            "target_id": "t1",
            "target_identity": {
                "session_id": "s1",
                "tab_id": "tab1",
                "page_id": "page1",
                "frame_id": "frame1",
                "origin": "https://fixture.invalid",
                "dom_revision": "r1",
            },
            "action": "browser_click",
            "arguments": {},
            "mutation": True,
        }
    )


def _browser_snapshot() -> ObservationSnapshot:
    identity = json.loads(_browser_transcript())["target_identity"]
    return ObservationSnapshot(
        ControlSurface.BROWSER,
        "o1",
        ({"target_id": "t1", "identity": identity},),
        privacy="PUBLIC",
    )


@pytest.mark.parametrize("descriptor", [BROWSER_USE, UFO])
def test_local_sdk_inspection_does_not_import_or_download(descriptor):
    status = inspect_sdk(descriptor)
    assert status.version is None or isinstance(status.version, str)
    assert status.reason in {
        "DISTRIBUTION_NOT_INSTALLED",
        "IMPORT_SPEC_UNAVAILABLE",
        "API_AND_EXECUTION_UNVERIFIED",
        "SDK_VERSION_MISMATCH",
    }


def test_isolated_site_package_inspection_reads_metadata_without_import(tmp_path):
    site = tmp_path / "site-packages"
    package = site / "browser_use"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("raise AssertionError('not imported')")
    dist_info = site / "browser_use-0.13.13.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: browser-use\nVersion: 0.13.13\n"
    )

    status = inspect_sdk(BROWSER_USE, site_packages=site)

    assert status.available
    assert status.version == "0.13.13"
    assert status.reason == "API_AND_EXECUTION_UNVERIFIED"


def test_isolated_site_package_version_mismatch_is_unavailable(tmp_path):
    site = tmp_path / "site-packages"
    package = site / "browser_use"
    package.mkdir(parents=True)
    dist_info = site / "browser_use-0.99.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: browser-use\nVersion: 0.99.0\n"
    )

    status = inspect_sdk(BROWSER_USE, site_packages=site)

    assert not status.available
    assert status.reason == "SDK_VERSION_MISMATCH"


@pytest.mark.parametrize("adapter_cls", [BrowserUseAdapter, UFOAdapter])
def test_unverified_sdk_cannot_negotiate_capabilities(adapter_cls):
    descriptor = adapter_cls.descriptor
    status = SdkStatus(descriptor, False, False, None, "DISTRIBUTION_NOT_INSTALLED")
    decision = negotiate_capabilities(status, descriptor.required_capabilities)
    assert not decision.allowed
    assert decision.supported == ()
    assert set(decision.denied) == set(descriptor.required_capabilities)
    assert decision.reason == "SDK_UNAVAILABLE"


@pytest.mark.parametrize("adapter_cls", [BrowserUseAdapter, UFOAdapter])
def test_adapter_is_not_enabled_by_presence_or_shadow_mode(adapter_cls):
    status = SdkStatus(
        adapter_cls.descriptor,
        True,
        True,
        adapter_cls.descriptor.expected_version or "0.0-test",
        "API_AND_EXECUTION_UNVERIFIED",
    )
    adapter = adapter_cls(
        _browser_transcript(), session_id="s1", mode=AdapterMode.SHADOW,
        status=status,
    )
    result = adapter.propose(_browser_snapshot())
    assert result.state is ExecutionState.NOT_STARTED
    assert result.failure == "SDK_API_UNVERIFIED"
    assert adapter.execute(None, None).failure == "SDK_EXECUTION_DISABLED"


def test_browser_adapter_legacy_default_preserves_existing_engine_gate(monkeypatch):
    monkeypatch.delenv("ASTRA_CONTROL_ENGINE", raising=False)
    adapter = BrowserUseAdapter(_browser_transcript(), session_id="s1")
    result = adapter.propose(_browser_snapshot())
    assert result.failure == "LEGACY_ENGINE_ACTIVE"


def test_enforce_mode_is_rejected_before_any_candidate_dispatch():
    with pytest.raises(ValueError, match="SDK execution is disabled"):
        BrowserUseAdapter(
            _browser_transcript(), session_id="s1", mode=AdapterMode.ENFORCE
        )


def test_capability_negotiation_deduplicates_and_denies_unknown():
    status = SdkStatus(BROWSER_USE, False, False, None, "DISTRIBUTION_NOT_INSTALLED")
    decision = negotiate_capabilities(status, ["observation", "observation", "new"])
    assert decision.requested == ("observation", "new")
    assert decision.denied == ("observation", "new")


def test_unavailable_sdk_denies_before_proposal_decoding():
    status = SdkStatus(UFO, False, False, None, "DISTRIBUTION_NOT_INSTALLED")
    adapter = UFOAdapter(
        "not JSON", session_id="s1", mode=AdapterMode.SHADOW, status=status
    )
    result = adapter.propose(_browser_snapshot())
    assert result.failure == "SDK_UNAVAILABLE"
