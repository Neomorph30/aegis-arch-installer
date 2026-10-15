"""Read-only release-readiness manifest for the AEGIS developer preview.

This is a *declaration* of implemented/not implemented capabilities. It does not
probe the current workstation and cannot certify a machine is secure. Only tests,
review and external evidence can establish that a future control passed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

CapabilityStatus = Literal["PREVIEW_ONLY", "NOT_IMPLEMENTED"]


@dataclass(frozen=True)
class Capability:
    id: str
    description: str
    status: CapabilityStatus
    evidence: str


CAPABILITIES: tuple[Capability, ...] = (
    Capability("hardware-inspection", "Non-privileged hardware observations", "PREVIEW_ONLY", "Fixture-backed read-only probes, not device identity proof"),
    Capability("storage-planning", "Partition and encryption proposals", "PREVIEW_ONLY", "Read-only planner tests, no disk execution capability"),
    Capability("network-preflight", "HTTPS checks and consent-gated Wi-Fi tooling", "PREVIEW_ONLY", "Mocked network tests; hardware compatibility not verified"),
    Capability("planning-report", "Redacted proposal-only HTML and JSON", "PREVIEW_ONLY", "Report sanitization regression tests"),
    Capability("disposable-vm-lab", "Restricted QEMU/OVMF/software-TPM launch smoke test", "PREVIEW_ONLY", "CI smoke test verifies VM launch and virtual TPM presence only; no guest boot or install proof"),
    Capability("guest-install-preflight", "Read-only guest device identity and install-layout preflight", "PREVIEW_ONLY", "Fixed QEMU lab identities, fail-closed observations and negative tests; no guest commands executed"),
    Capability("iso-integrity-gate", "Arch-labelled ISO9660 and SHA-256 validation", "PREVIEW_ONLY", "Local ISO verification requires an independently trusted expected digest; provenance is not automatic"),
    Capability("transaction-journal", "Private hash-chained install phase journal and conservative recovery assessment", "PREVIEW_ONLY", "Unit-tested journal primitive; not connected to an installer executor and not a digital signature"),
    Capability("privileged-executor", "Any actual disk/firmware/system installer operations", "NOT_IMPLEMENTED", "No privileged executor shipped"),
    Capability("luks2-tpm", "LUKS2/TPM2/PIN enrollment and offline recovery", "NOT_IMPLEMENTED", "Virtual TPM and recovery tests required"),
    Capability("signed-boot", "Signed UKI and Secure Boot policy management", "NOT_IMPLEMENTED", "Secure Boot enrollment and attestation required"),
    Capability("desktop-gaming-vr", "KDE, kernel, graphics, gaming and VR installation", "NOT_IMPLEMENTED", "Only package recommendations exist"),
    Capability("security-guardian", "Firewall, malware scans and mandatory access control", "NOT_IMPLEMENTED", "No host policy changes shipped"),
    Capability("optimization-review-policy", "Evidence-gated review of benchmark candidates", "PREVIEW_ONLY", "Unit-tested comparison policy only; no benchmarks run, system changes applied, or rollback executed"),
    Capability("adaptive-optimizer", "Reversible benchmark-backed hardware tuning", "NOT_IMPLEMENTED", "No hardware probes, tuning operations, or rollback executor shipped"),
    Capability("public-iso", "Signed bootable end-user installation medium", "NOT_IMPLEMENTED", "Reproducible, qualified build required"),
)


def manifest() -> dict[str, object]:
    """Return a stable, program-readable preview capability declaration."""
    return {
        "schema_version": 1,
        "release_stage": "PRE_ALPHA_NON_DESTRUCTIVE",
        "installation_enabled": False,
        "security_certification": False,
        "external_security_review": "NOT_COMPLETED",
        "capabilities": [vars(cap).copy() for cap in CAPABILITIES],
        "limitations": [
            "No physical or virtual disk-writing installer is included.",
            "Read-only inspection and unit tests are not evidence of security on a real system.",
            "Network onboarding may modify the live network only with user consent.",
        ],
    }


def formatted_manifest(*, as_json: bool = False) -> str:
    result = manifest()
    if as_json:
        return json.dumps(result, indent=2)
    lines = ["AEGIS PRE-ALPHA — CAPABILITY AND SAFETY STATUS", "No installation or disk writes are available.", ""]
    lines.extend(f"[{cap.status}] {cap.description}" for cap in CAPABILITIES)
    lines.append("\nNOT SECURITY CERTIFIED. Independent review and real hardware tests remain outstanding.")
    return "\n".join(lines)
