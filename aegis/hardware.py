"""Non-privileged, strictly read-only Linux hardware discovery.

All observations are *hints*. The eventual privileged executor must independently
re-identify every device and check it is not in use immediately before any write.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any

LSBLK_FIELDS = (
    "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,FSTYPE,MOUNTPOINTS,RM,RO,"
    "PTTYPE,PARTUUID,UUID,PKNAME,HOTPLUG"
)


class HardwareInspectionError(RuntimeError):
    pass


def _read_text(filename: str) -> str:
    try:
        return Path(filename).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _run_readonly(command: list[str], timeout: int = 12) -> str:
    """Execute a static, argument-vector command; never a shell command."""
    approved = {
        ("lsblk", "--json", "--bytes", "--tree", "--output", LSBLK_FIELDS),
        ("lspci", "-nn"),
    }
    if tuple(command) not in approved:
        raise HardwareInspectionError("Probe command is not on the read-only allowlist")
    try:
        return subprocess.run(command, check=True, capture_output=True,
                              text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise HardwareInspectionError(f"Read-only probe failed ({command[0]}): {exc}") from exc


def read_disks() -> list[dict[str, Any]]:
    """Enumerate all physical block disks (not partitions, loopback or RAM disks)."""
    if not shutil.which("lsblk"):
        raise HardwareInspectionError("lsblk is required; use a Linux installation environment")
    try:
        output = json.loads(_run_readonly([
            "lsblk", "--json", "--bytes", "--tree", "--output", LSBLK_FIELDS
        ]))
    except (ValueError, TypeError) as exc:
        raise HardwareInspectionError("lsblk returned invalid JSON") from exc
    if not isinstance(output, dict) or not isinstance(output.get("blockdevices"), list):
        raise HardwareInspectionError("lsblk returned an unexpected device structure")
    return [d for d in output["blockdevices"]
            if isinstance(d, dict) and d.get("type") == "disk"]


def _active_swap_paths() -> set[str] | None:
    """Read active swap device paths; None means state could not be verified."""
    try:
        lines = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    paths: set[str] = set()
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        try:
            paths.add(str(Path(fields[0]).resolve(strict=False)))
        except (OSError, RuntimeError):
            paths.add(fields[0])
    return paths


def _enrich_block_node(node: dict[str, Any], swap_paths: set[str] | None) -> None:
    """Attach explicit holder and swap observations to every lsblk tree node."""
    path = node.get("path")
    name = Path(path).name if isinstance(path, str) else ""
    holder_dir = Path("/sys/class/block") / name / "holders"
    try:
        node["holders"] = sorted(entry.name for entry in holder_dir.iterdir())
    except OSError:
        # Unknown is deliberately not represented as an empty holder list.
        node["holders"] = None
    if swap_paths is None or not isinstance(path, str):
        node["active_swap"] = None
    else:
        try:
            resolved = str(Path(path).resolve(strict=False))
        except (OSError, RuntimeError):
            resolved = path
        node["active_swap"] = resolved in swap_paths
    # Identity collisions are checked by the assessor across the complete tree.
    node["ambiguous"] = False
    children = node.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                _enrich_block_node(child, swap_paths)


def read_assessment_observation() -> dict[str, Any]:
    """Build a live, read-only observation for the conservative inventory assessor."""
    disks = read_disks()
    swap_paths = _active_swap_paths()
    for disk in disks:
        _enrich_block_node(disk, swap_paths)
    return {"devices": disks}


def _cpu_label() -> str:
    for line in _read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            return line.partition(":")[2].strip()
    return platform.processor() or "unknown"


def _memory_mib() -> int | None:
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            try:
                return int(line.split()[1]) // 1024
            except (IndexError, ValueError):
                return None
    return None


def _gpu_summary() -> list[str]:
    if not shutil.which("lspci"):
        return []
    try:
        output = _run_readonly(["lspci", "-nn"], timeout=8)
    except HardwareInspectionError:
        return []
    return [line.strip() for line in output.splitlines()
            if any(tag in line for tag in
                   ("VGA compatible controller", "3D controller", "Display controller"))]


def _tpm_version() -> str:
    """Report kernel-advertised TPM major versions, not proof enrollment works."""
    base = Path("/sys/class/tpm")
    try:
        devices = list(base.glob("tpm[0-9]*"))
    except OSError:
        return "unknown"
    versions = {_read_text(str(d / "tpm_version_major")).strip() for d in devices}
    if "2" in versions:
        return "2.0-detected-unverified"
    if "1" in versions:
        return "1.2-detected"
    return "unknown" if devices else "not-detected"


def _secure_boot_state() -> str:
    """Read the SecureBoot EFI variable (first 4 bytes are efivar attributes)."""
    efivars = Path("/sys/firmware/efi/efivars")
    if not efivars.is_dir():
        return "unavailable"
    try:
        entries = list(efivars.glob("SecureBoot-*"))
        if len(entries) != 1:
            return "unverified"
        payload = entries[0].read_bytes()
        if len(payload) != 5:
            return "unverified"
        return "enabled-reported" if payload[4] == 1 else (
            "disabled-reported" if payload[4] == 0 else "unverified"
        )
    except OSError:
        return "unverified"


def inspect() -> dict[str, Any]:
    if platform.system() != "Linux":
        raise HardwareInspectionError("Hardware inspection requires Linux")
    tpm_version = _tpm_version()
    return {
        "schema_version": "0.2",
        "architecture": platform.machine(),
        "cpu": _cpu_label(),
        "ram_mib": _memory_mib(),
        "uefi_detected": Path("/sys/firmware/efi").exists(),
        "tpm_device_detected": tpm_version not in ("not-detected", "unknown"),
        "tpm_version": tpm_version,
        "secure_boot_state": _secure_boot_state(),
        "gpu_devices": _gpu_summary(),
        "disks": read_disks(),
        "notes": [
            "Read-only preflight, not a certificate of device safety or TPM enrollment support.",
            "UEFI Secure Boot variable is reported, not independently attested.",
            "Storage enumeration may include installation media, removable media and active disks.",
        ],
    }
