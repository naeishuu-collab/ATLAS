"""Offline release-evidence tests (Gates B-F preparation).

Pure parsing and pure validation only. PE fixtures are hand-crafted
byte strings; no compiler, linker, signature, policy, or OS execution.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from openjarvis.sandbox.release_evidence import (
    BundleExpectations,
    EvidenceError,
    classify_signing_evidence,
    parse_pe_evidence,
    validate_release_bundle,
    validate_wdac_evidence,
)


def _build_pe(
    *, machine=0x8664, subsystem=3, dll_chars=0x160, with_import=False, n_sections=1
) -> bytes:
    dos = bytearray(64)
    struct.pack_into("<H", dos, 0, 0x5A4D)
    struct.pack_into("<L", dos, 0x3C, 0x80)
    pe = bytearray()
    pe += b"PE\x00\x00"
    pe += struct.pack("<HHLLLHH", machine, n_sections, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<H", opt, 68, subsystem)
    struct.pack_into("<H", opt, 70, dll_chars)
    struct.pack_into("<L", opt, 108, 2)
    if with_import:
        struct.pack_into("<LL", opt, 120, 0x1000, 40)
    pe += opt
    for index in range(n_sections):
        section = bytearray(40)
        name = f".s{index}".encode("ascii")
        section[0 : len(name)] = name
        if with_import and index == 0:
            struct.pack_into("<LLLL", section, 8, 0x200, 0x1000, 0x200, 0x200)
        else:
            struct.pack_into("<LLLL", section, 8, 0x100, 0x2000 + index * 0x1000, 0, 0)
        pe += section
    image = bytes(dos) + b"\x00" * (0x80 - 64) + bytes(pe)
    image += b"\x00" * (0x200 - len(image))
    if with_import:
        idata = bytearray(0x200)
        struct.pack_into("<LLLLL", idata, 0, 0x1028, 0, 0, 0x1040, 0x1028)
        idata[0x40 : 0x40 + 12] = b"KERNEL32.dll\x00"
        image += bytes(idata)
    return image


def test_valid_pe32plus_static_console() -> None:
    image = _build_pe()
    evidence = parse_pe_evidence(image)
    assert evidence["machine"] == "AMD64"
    assert evidence["subsystem"] == 3
    assert evidence["executable_image"] is True
    assert evidence["security_flags"] == {
        "dynamic_base": True,
        "nx_compat": True,
        "high_entropy_va": True,
    }
    assert evidence["sha256"] == hashlib.sha256(image).hexdigest()
    assert evidence["imports"] == []


def test_pe_import_table_parsed() -> None:
    evidence = parse_pe_evidence(_build_pe(with_import=True))
    assert evidence["imports"] == ["KERNEL32.dll"]


def test_pe_missing_security_flags_visible() -> None:
    evidence = parse_pe_evidence(_build_pe(dll_chars=0))
    assert evidence["security_flags"]["dynamic_base"] is False
    assert evidence["security_flags"]["nx_compat"] is False


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda b: b"ZZ" + b[2:], "PE_BAD_MAGIC"),
        (lambda b: b[:0x3C] + struct.pack("<L", 0xFFFFFF) + b[0x40:], "PE_BAD_OFFSET"),
        (lambda b: b[:0x80] + b"XX" + b[0x82:], "PE_BAD_MAGIC"),
    ],
)
def test_pe_malformed_headers_rejected(mutate, code: str) -> None:
    with pytest.raises(EvidenceError) as excinfo:
        parse_pe_evidence(mutate(bytearray(_build_pe())))
    assert excinfo.value.code == code


def test_pe_wrong_machine_rejected() -> None:
    with pytest.raises(EvidenceError) as excinfo:
        parse_pe_evidence(_build_pe(machine=0x14C))
    assert excinfo.value.code == "PE_WRONG_MACHINE"


def test_pe_section_count_bounded() -> None:
    with pytest.raises(EvidenceError) as excinfo:
        parse_pe_evidence(_build_pe(n_sections=97))
    assert excinfo.value.code == "PE_BAD_SECTIONS"


def test_pe_truncated_rejected() -> None:
    with pytest.raises(EvidenceError):
        parse_pe_evidence(_build_pe()[:100])


def _signing(**kw) -> dict:
    base = {
        "status": "Valid",
        "signer_subject": "CN=Approved",
        "signer_thumbprint": "AB" * 20,
        "file_sha256": "CD" * 32,
        "chain": [{"valid": True, "revoked": False}],
        "ekus": ["code_signing"],
        "timestamp": "2026-01-01T00:00:00Z",
        "revocation_ok": True,
    }
    base.update(kw)
    return base


def test_signing_matrix() -> None:
    approved = ["CN=Approved"]
    assert classify_signing_evidence({"status": "NotSigned"}, approved) == "UNSIGNED"
    assert classify_signing_evidence({}, approved) == "UNSIGNED"
    assert (
        classify_signing_evidence(_signing(status="HashMismatch"), approved)
        == "INVALID"
    )
    assert (
        classify_signing_evidence(
            _signing(chain=[{"valid": True, "revoked": True}]), approved
        )
        == "INVALID"
    )
    assert (
        classify_signing_evidence(_signing(ekus=["server_auth"]), approved) == "INVALID"
    )
    assert (
        classify_signing_evidence(_signing(revocation_ok=False), approved) == "INVALID"
    )
    assert (
        classify_signing_evidence(_signing(signer_subject="CN=Evil"), approved)
        == "UNTRUSTED_PUBLISHER"
    )
    assert classify_signing_evidence(_signing(), approved) == "APPROVED_PUBLISHER"
    assert classify_signing_evidence(_signing(signer_subject=""), approved) == "INVALID"


def _wdac(**kw) -> dict:
    base = {
        "policy_id": "POL-1",
        "rule_id": "R-1",
        "binding": "hash",
        "binding_value": "AA" * 32,
        "mode": "enforced",
        "scope_approved": True,
    }
    base.update(kw)
    return base


def _wexpect(**kw) -> dict:
    base = {"policy_id": "POL-1", "artifact_sha256": "AA" * 32, "signer": "CN=Approved"}
    base.update(kw)
    return base


def test_wdac_matrix() -> None:
    assert validate_wdac_evidence(_wdac(), _wexpect())["ok"] is True
    assert (
        validate_wdac_evidence(_wdac(policy_id="OTHER"), _wexpect())["code"]
        == "WDAC_POLICY_MISMATCH"
    )
    assert (
        validate_wdac_evidence(_wdac(binding_value="00" * 32), _wexpect())["code"]
        == "WDAC_BINDING_MISMATCH"
    )
    assert (
        validate_wdac_evidence(_wdac(mode="audit"), _wexpect())["code"]
        == "WDAC_NOT_ENFORCED"
    )
    assert (
        validate_wdac_evidence(_wdac(scope_approved=False), _wexpect())["code"]
        == "WDAC_SCOPE_UNAPPROVED"
    )
    assert (
        validate_wdac_evidence(
            _wdac(binding="signer", binding_value="CN=Approved"), _wexpect()
        )["ok"]
        is True
    )
    assert validate_wdac_evidence({}, _wexpect())["code"] == "WDAC_MISSING_FIELD"


def _bundle(**kw) -> dict:
    digest = "AA" * 32
    gates = {
        "b": {"artifact_sha256": digest},
        "c": {
            "artifact_sha256": digest,
            "signer": "CN=Approved",
            "signing": _signing(),
        },
        "d": {"artifact_sha256": digest, "wdac": _wdac()},
        "e": {
            "artifact_sha256": digest,
            "scenarios_passed": 19,
            "scenarios_total": 19,
            "unknown_outcome_quarantined": True,
        },
    }
    bundle = {"schema": 1, "produced_at": 1700000000, "gates": gates}
    bundle.update(kw)
    return bundle


def _bexpect(**kw) -> BundleExpectations:
    base = {
        "artifact_sha256": "AA" * 32,
        "signer": "CN=Approved",
        "policy_id": "POL-1",
        "approved_publishers": ("CN=Approved",),
    }
    base.update(kw)
    return BundleExpectations(**base)


def test_bundle_complete_consistent() -> None:
    result = validate_release_bundle(_bundle(), _bexpect(), now=1700000100)
    assert result["complete"] is True
    assert result["code"] == "OK"


def test_bundle_adversarial_matrix() -> None:
    good = _bundle()
    exp = _bexpect()
    assert (
        validate_release_bundle({**good, "synthetic": True}, exp, now=1700000100)[
            "code"
        ]
        == "SYNTHETIC_NOT_PROOF"
    )
    tampered = _bundle()
    tampered["gates"]["d"]["artifact_sha256"] = "00" * 32
    assert (
        validate_release_bundle(tampered, exp, now=1700000100)["code"]
        == "BUNDLE_CONTRADICTORY"
    )
    assert validate_release_bundle(good, exp, now=1900000000)["code"] == "BUNDLE_STALE"
    unsigned = _bundle()
    unsigned["gates"]["c"]["signing"] = {"status": "NotSigned"}
    assert (
        validate_release_bundle(unsigned, exp, now=1700000100)["code"]
        == "BUNDLE_UNSIGNED"
    )
    evil = _bundle()
    evil["gates"]["c"]["signing"] = _signing(signer_subject="CN=Evil")
    evil["gates"]["c"]["signer"] = "CN=Evil"
    assert validate_release_bundle(evil, exp, now=1700000100)["code"] in (
        "BUNDLE_UNTRUSTED_PUBLISHER",
        "BUNDLE_SIGNER_MISMATCH",
    )
    noquorum = _bundle()
    noquorum["gates"]["e"]["unknown_outcome_quarantined"] = False
    assert (
        validate_release_bundle(noquorum, exp, now=1700000100)["code"]
        == "BUNDLE_OUTCOME_UNSAFE"
    )
    partial = _bundle()
    partial["gates"]["e"]["scenarios_passed"] = 18
    assert (
        validate_release_bundle(partial, exp, now=1700000100)["code"]
        == "BUNDLE_PHYSICAL_INCOMPLETE"
    )
    assert (
        validate_release_bundle({"schema": 1}, exp, now=1700000100)["code"]
        == "BUNDLE_MALFORMED"
    )
