"""Advisory software and tuning profiles: do not run packages or change settings."""

from __future__ import annotations

from typing import Any

PROFILES = frozenset({"secure-workstation", "secure-gaming"})


def recommend(inventory: dict[str, Any], profile: str = "secure-gaming") -> dict[str, Any]:
    """Make support-qualified recommendations, not install or tuning commands.

    A GPU's presence is not sufficient to guarantee compatible driver packages.
    """
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile: {profile}")
    gpu_lines = inventory.get("gpu_devices") or []
    lines = " ".join(str(s).lower() for s in gpu_lines)
    vendors = [name for name, hints in {
        "nvidia": ("nvidia", "[10de:"),
        "amd": ("advanced micro devices", "amd/ati", "[1002:"),
        "intel": ("intel corporation", "[8086:"),
    }.items() if any(h in lines for h in hints)]
    packages = ["linux", "linux-lts", "linux-firmware", "cryptsetup", "btrfs-progs",
                "networkmanager", "firewalld", "apparmor"]
    if profile == "secure-gaming":
        packages += ["linux-zen", "steam", "gamemode", "mangohud", "pipewire", "wireplumber"]
    elif profile == "secure-workstation":
        packages += ["pipewire", "wireplumber"]
    arch = inventory.get("architecture", "unknown")
    cpu = (inventory.get("cpu") or "").lower()
    if "intel" in cpu:
        packages.append("intel-ucode")
    elif "amd" in cpu:
        packages.append("amd-ucode")
    notes = []
    if not vendors:
        notes.append("GPU vendor unknown; driver choice requires manual identification")
    elif len(vendors) > 1:
        notes.append("Hybrid/multi-GPU configuration; per-device driver selection requires review")
    elif vendors == ["nvidia"]:
        notes.append("NVIDIA identified; confirm generation and driver compatibility before choosing open DKMS modules")
    elif vendors == ["amd"]:
        notes.append("AMD identified; Mesa/RADV is a candidate, subject to chip and firmware support")
    elif vendors == ["intel"]:
        notes.append("Intel GPU identified; Mesa/Vulkan options depend on exact generation")
    if inventory.get("tpm_version") != "2.0-detected-unverified":
        notes.append("TPM 2.0 + PIN prerequisites not verified; recovery-passphrase fallback required")
    notes.append("No performance claim is made without hardware benchmarks and stability checks")
    return {
        "schema_version": "0.2",
        "profile": profile,
        "status": "RECOMMENDATIONS_ONLY",
        "architecture": arch,
        "detected_gpu_vendors": vendors,
        "package_candidates": sorted(set(packages)),
        "security_controls": [
            {"name": "Firewall", "status": "NOT_CONFIGURED", "proposal": "firewalld; inbound denied by default; detect remote management"},
            {"name": "Malware detection", "status": "NOT_CONFIGURED", "proposal": "optional ClamAV scheduled scans"},
            {"name": "Mandatory access control", "status": "NOT_CONFIGURED", "proposal": "reviewed AppArmor profiles"},
        ],
        "optimization": {"status": "NOT_RUN", "mode": "conservative", "rollback_required": True},
        "notes": notes,
    }
