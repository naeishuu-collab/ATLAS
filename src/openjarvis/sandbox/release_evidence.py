"""Offline release-evidence validation for Gates B-F.

Pure functions only: no OS calls, no process creation, no network, no
signature verification against live chains. Evidence dictionaries use
the field shapes produced by the future authorized tooling
(`certutil`, `Get-AuthenticodeSignature`, WDAC policy records); this
module checks their consistency and completeness.

A "complete" bundle is reviewable evidence, never authorization:
human approval remains mandatory for every gate.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

EVIDENCE_SCHEMA_VERSION = 1

_MZ = 0x5A4D
_NT_SIG = b"PE\x00\x00"
_MACHINE_AMD64 = 0x8664
_OPT_MAGIC_PE32PLUS = 0x20B
_SUBSYSTEM_CUI = 3
_DLL_DYNAMIC_BASE = 0x40
_DLL_NX_COMPAT = 0x100
_DLL_HIGH_ENTROPY_VA = 0x20
_MAX_SECTIONS = 96
_MAX_IMPORT_DLLS = 64
_MAX_IMPORT_NAMES = 512
_MAX_NAME_BYTES = 256


class EvidenceError(ValueError):
    """Malformed evidence with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise EvidenceError("PE_TRUNCATED", "buffer overrun")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise EvidenceError("PE_TRUNCATED", "buffer overrun")
    return struct.unpack_from("<L", data, offset)[0]


def _rva_to_offset(sections: Sequence[dict], rva: int) -> int:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            offset = rva - start + section["raw_offset"]
            if offset < 0:
                break
            return offset
    raise EvidenceError("PE_BAD_RVA", "RVA outside sections")


def _asciiz(data: bytes, offset: int) -> str:
    end = offset
    limit = min(offset + _MAX_NAME_BYTES, len(data))
    while end < limit and data[end] != 0:
        end += 1
    if end >= len(data):
        raise EvidenceError("PE_TRUNCATED", "unterminated name")
    try:
        return bytes(data[offset:end]).decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceError("PE_BAD_NAME", "non-ASCII name") from exc


def parse_pe_evidence(data: bytes) -> dict:
    """Parse PE headers into evidence. Raises EvidenceError if malformed."""
    if not isinstance(data, (bytes, bytearray)):
        raise EvidenceError("PE_MALFORMED", "input must be bytes")
    data = bytes(data)
    if len(data) < 64 or _u16(data, 0) != _MZ:
        raise EvidenceError("PE_BAD_MAGIC", "missing MZ header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset > len(data) - 6:
        raise EvidenceError("PE_BAD_OFFSET", "e_lfanew out of range")
    if data[pe_offset : pe_offset + 4] != _NT_SIG:
        raise EvidenceError("PE_BAD_MAGIC", "missing PE signature")
    coff = pe_offset + 4
    machine = _u16(data, coff)
    num_sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    if machine != _MACHINE_AMD64:
        raise EvidenceError("PE_WRONG_MACHINE", "not AMD64")
    if num_sections == 0 or num_sections > _MAX_SECTIONS:
        raise EvidenceError("PE_BAD_SECTIONS", "section count out of range")
    opt = coff + 20
    if opt + opt_size > len(data):
        raise EvidenceError("PE_TRUNCATED", "optional header overrun")
    if _u16(data, opt) != _OPT_MAGIC_PE32PLUS:
        raise EvidenceError("PE_NOT_32PLUS", "not PE32+")
    subsystem = _u16(data, opt + 68)
    dll_chars = _u16(data, opt + 70)
    num_dirs = _u32(data, opt + 108)
    if num_dirs > 16:
        raise EvidenceError("PE_BAD_DIRS", "too many data directories")
    import_rva, import_size = 0, 0
    if num_dirs >= 2:
        import_rva = _u32(data, opt + 120)
        import_size = _u32(data, opt + 124)
    sections = []
    table = opt + opt_size
    for index in range(num_sections):
        base = table + index * 40
        if base + 40 > len(data):
            raise EvidenceError("PE_TRUNCATED", "section table overrun")
        try:
            name = bytes(data[base : base + 8]).split(b"\x00")[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise EvidenceError("PE_BAD_NAME", "bad section name") from exc
        virtual_size = _u32(data, base + 8)
        virtual_address = _u32(data, base + 12)
        raw_size = _u32(data, base + 16)
        raw_offset = _u32(data, base + 20)
        if raw_size and raw_offset + raw_size > len(data):
            raise EvidenceError("PE_BAD_SECTION_DATA", "section data outside file")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
            }
        )
    imports: list[str] = []
    if import_rva and import_size:
        directory = _rva_to_offset(sections, import_rva)
        for index in range(_MAX_IMPORT_DLLS):
            entry = directory + index * 20
            if entry + 20 > len(data):
                raise EvidenceError("PE_TRUNCATED", "import directory overrun")
            thunk_rva = _u32(data, entry)
            name_rva = _u32(data, entry + 12)
            first_thunk = _u32(data, entry + 16)
            if thunk_rva == 0 and name_rva == 0 and first_thunk == 0:
                break
            if name_rva == 0:
                raise EvidenceError("PE_BAD_IMPORT", "nameless import")
            imports.append(_asciiz(data, _rva_to_offset(sections, name_rva)))
        else:
            raise EvidenceError("PE_TOO_MANY_IMPORTS", "import count over limit")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "machine": "AMD64",
        "subsystem": subsystem,
        "executable_image": bool(characteristics & 0x2),
        "security_flags": {
            "dynamic_base": bool(dll_chars & _DLL_DYNAMIC_BASE),
            "nx_compat": bool(dll_chars & _DLL_NX_COMPAT),
            "high_entropy_va": bool(dll_chars & _DLL_HIGH_ENTROPY_VA),
        },
        "sections": [{"name": s["name"], "raw_size": s["raw_size"]} for s in sections],
        "imports": imports,
    }


def classify_signing_evidence(
    evidence: Mapping[str, Any], approved_publishers: Sequence[str]
) -> str:
    """Classify Authenticode evidence. Fail closed on any gap."""
    if not isinstance(evidence, Mapping):
        return "INVALID"
    status = evidence.get("status")
    if status in (None, "", "NotSigned", "UnknownError"):
        return "UNSIGNED"
    if status != "Valid":
        return "INVALID"
    for field in (
        "signer_subject",
        "signer_thumbprint",
        "file_sha256",
        "chain",
        "timestamp",
    ):
        if not evidence.get(field):
            return "INVALID"
    chain = evidence.get("chain")
    if (
        not isinstance(chain, Sequence)
        or isinstance(chain, (str, bytes))
        or not chain
        or not all(isinstance(c, Mapping) for c in chain)
    ):
        return "INVALID"
    for cert in chain:
        if cert.get("revoked") is True:
            return "INVALID"
        if cert.get("valid") is not True:
            return "INVALID"
    ekus = evidence.get("ekus", [])
    if "code_signing" not in list(ekus):
        return "INVALID"
    if evidence.get("revocation_ok") is not True:
        return "INVALID"
    if str(evidence.get("signer_subject", "")) not in set(approved_publishers):
        return "UNTRUSTED_PUBLISHER"
    return "APPROVED_PUBLISHER"


def validate_wdac_evidence(
    evidence: Mapping[str, Any], expected: Mapping[str, Any]
) -> dict:
    """Validate WDAC binding evidence. Fail closed with a stable code."""

    def deny(code: str, detail: str) -> dict:
        return {"ok": False, "code": code, "detail": detail}

    if not isinstance(evidence, Mapping) or not isinstance(expected, Mapping):
        return deny("WDAC_MALFORMED", "evidence must be objects")
    for field in ("policy_id", "rule_id", "binding", "binding_value", "mode"):
        if not evidence.get(field):
            return deny("WDAC_MISSING_FIELD", f"missing: {field}")
    if str(evidence.get("policy_id")) != str(expected.get("policy_id", "")):
        return deny("WDAC_POLICY_MISMATCH", "wrong policy identity")
    binding = str(evidence.get("binding"))
    if binding == "hash":
        if str(evidence.get("binding_value")) != str(
            expected.get("artifact_sha256", "")
        ):
            return deny("WDAC_BINDING_MISMATCH", "hash binding mismatch")
    elif binding == "signer":
        if str(evidence.get("binding_value")) != str(expected.get("signer", "")):
            return deny("WDAC_BINDING_MISMATCH", "signer binding mismatch")
    else:
        return deny("WDAC_BAD_BINDING", "unknown binding type")
    if str(evidence.get("mode")) != "enforced":
        return deny("WDAC_NOT_ENFORCED", "policy is not enforcing")
    if expected.get("require_scope_approved", True) and not evidence.get(
        "scope_approved"
    ):
        return deny("WDAC_SCOPE_UNAPPROVED", "scope not approved")
    return {"ok": True, "code": "OK", "detail": "WDAC evidence consistent"}


@dataclass(frozen=True)
class BundleExpectations:
    """Host-owned expectations for a cross-gate evidence bundle."""

    artifact_sha256: str
    signer: str = ""
    policy_id: str = ""
    approved_publishers: tuple = ()
    max_evidence_age_s: float = 86400.0


def validate_release_bundle(
    bundle: Mapping[str, Any], expected: BundleExpectations, now: float
) -> dict:
    """Validate a Gate B-F evidence bundle. Never authorizes.

    Returns complete=True only when the package is well-formed,
    internally consistent, and fresh. Human approval per gate is
    still mandatory.
    """

    def deny(code: str, detail: str) -> dict:
        return {
            "complete": False,
            "code": code,
            "detail": detail,
            "audit": {"code": code, "synthetic": bool(bundle.get("synthetic", False))},
        }

    if not isinstance(bundle, Mapping):
        return deny("BUNDLE_MALFORMED", "bundle must be an object")
    if bundle.get("synthetic", False) is True:
        return deny(
            "SYNTHETIC_NOT_PROOF", "synthetic fixtures are not production proof"
        )
    if bundle.get("schema") != EVIDENCE_SCHEMA_VERSION:
        return deny("BUNDLE_SCHEMA", "unsupported bundle schema")
    gates = bundle.get("gates")
    if not isinstance(gates, Mapping):
        return deny("BUNDLE_MALFORMED", "gates must be an object")
    for gate in ("b", "c", "d", "e"):
        gate_evidence = gates.get(gate)
        if not isinstance(gate_evidence, Mapping):
            return deny("BUNDLE_INCOMPLETE", f"gate {gate} evidence missing")
    try:
        produced_at = float(bundle.get("produced_at", 0))
    except (TypeError, ValueError):
        return deny("BUNDLE_MALFORMED", "bad produced_at")
    if not (produced_at <= now <= produced_at + expected.max_evidence_age_s):
        return deny("BUNDLE_STALE", "evidence outside freshness window")
    hashes = set()
    for gate in ("b", "c", "d", "e"):
        digest = gates[gate].get("artifact_sha256", "")
        if not digest:
            return deny("BUNDLE_INCOMPLETE", f"gate {gate} artifact hash missing")
        hashes.add(str(digest).lower())
    if len(hashes) != 1 or expected.artifact_sha256.lower() not in hashes:
        return deny("BUNDLE_CONTRADICTORY", "artifact identity differs across gates")
    signing = classify_signing_evidence(
        gates["c"].get("signing", {}), list(expected.approved_publishers)
    )
    if signing == "UNSIGNED":
        return deny("BUNDLE_UNSIGNED", "gate C artifact unsigned")
    if signing == "INVALID":
        return deny("BUNDLE_SIGNING_INVALID", "gate C signature invalid")
    if signing == "UNTRUSTED_PUBLISHER":
        return deny("BUNDLE_UNTRUSTED_PUBLISHER", "signer not approved")
    if expected.signer and str(gates["c"].get("signer", "")) != expected.signer:
        return deny("BUNDLE_SIGNER_MISMATCH", "gate C signer mismatch")
    wdac = validate_wdac_evidence(
        gates["d"].get("wdac", {}),
        {
            "policy_id": expected.policy_id,
            "artifact_sha256": expected.artifact_sha256,
            "signer": expected.signer,
        },
    )
    if not wdac["ok"]:
        return deny("BUNDLE_WDAC_" + wdac["code"], wdac["detail"])
    physical = gates["e"].get("scenarios_passed", 0)
    physical_total = gates["e"].get("scenarios_total", 0)
    if not isinstance(physical, int) or not isinstance(physical_total, int):
        return deny("BUNDLE_MALFORMED", "physical counts must be integers")
    if physical_total <= 0 or physical != physical_total:
        return deny("BUNDLE_PHYSICAL_INCOMPLETE", "physical acceptance incomplete")
    if gates["e"].get("unknown_outcome_quarantined") is not True:
        return deny("BUNDLE_OUTCOME_UNSAFE", "unknown outcomes not quarantined")
    return {
        "complete": True,
        "code": "OK",
        "detail": "evidence complete and consistent; human approval still required",
        "audit": {
            "code": "OK",
            "synthetic": False,
            "artifact_sha256": expected.artifact_sha256,
        },
    }


__all__ = [
    "BundleExpectations",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceError",
    "classify_signing_evidence",
    "parse_pe_evidence",
    "validate_release_bundle",
    "validate_wdac_evidence",
]
