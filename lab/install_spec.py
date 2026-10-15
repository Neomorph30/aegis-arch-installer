"""Pure Layer 07 guest-install preflight specification; no commands are executed."""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


class InstallSpecError(ValueError):
    """A guest installation specification failed closed preflight."""


MIN_PRIMARY_BYTES = 24 * 1024**3
EFI_BYTES = 4 * 1024**3
PRIMARY_PATH = "/dev/vda"
PRIMARY_SERIAL = "AEGIS-LAB-PRIMARY"
SECONDARY_PATH = "/dev/vdb"
SECONDARY_SERIAL = "AEGIS-LAB-SECONDARY"
BOOT_PATH = "/dev/sr0"


def _mountpoints(node: dict[str, Any]) -> list[str]:
    if "mountpoints" in node:
        values = node["mountpoints"]
    elif "mountpoint" in node:
        values = node["mountpoint"]
    else:
        raise InstallSpecError("Mountpoint observations are missing")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or any(value is not None and not isinstance(value, str) for value in values):
        raise InstallSpecError("Mountpoint observations are malformed")
    return [value for value in values if isinstance(value, str) and value.strip()]


def _walk(node: dict[str, Any]):
    yield node
    if "children" not in node or not isinstance(node["children"], list):
        raise InstallSpecError("Device tree children are missing or malformed")
    children = node["children"]
    for child in children:
        if not isinstance(child, dict):
            raise InstallSpecError("Device tree contains a malformed child")
        yield from _walk(child)


def _digest(value: dict[str, Any]) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    except (TypeError, ValueError) as exc:
        raise InstallSpecError("Guest install spec is not canonically serializable") from exc
    return hashlib.sha256(raw).hexdigest()


def verify_guest_install_spec(spec: dict[str, Any]) -> bool:
    if not isinstance(spec, dict) or not isinstance(spec.get("spec_digest"), str):
        return False
    unsigned = {key: value for key, value in spec.items() if key != "spec_digest"}
    try:
        return hmac.compare_digest(spec["spec_digest"], _digest(unsigned))
    except (InstallSpecError, TypeError, ValueError):
        return False


def build_guest_install_spec(observation: dict[str, Any]) -> dict[str, Any]:
    """Build a review-only spec from guest observations; never executes or writes."""
    if not isinstance(observation, dict):
        raise InstallSpecError("Guest observations must be an object")
    environment = observation.get("environment")
    if not isinstance(environment, dict):
        raise InstallSpecError("Guest environment identity is missing")
    if environment.get("sys_vendor") != "QEMU" or "Q35" not in str(environment.get("product_name", "")):
        raise InstallSpecError("Guest is not verified as the supported QEMU Q35 lab")
    if observation.get("network_mode") not in ("disabled", "user-nat-explicit"):
        raise InstallSpecError("Network mode must be explicitly declared")

    raw = observation.get("devices")
    if not isinstance(raw, list):
        raise InstallSpecError("Block device observations must be a list")
    if any(not isinstance(device, dict) for device in raw):
        raise InstallSpecError("Block device list contains a malformed observation")
    disks = [d for d in raw if d.get("type") == "disk"]
    roms = [d for d in raw if d.get("type") == "rom"]
    if len(disks) != 2:
        raise InstallSpecError("Expected exactly two lab disks; extra or missing disks are forbidden")
    primary = [d for d in disks if d.get("path") == PRIMARY_PATH]
    secondary = [d for d in disks if d.get("path") == SECONDARY_PATH]
    if len(primary) != 1 or len(secondary) != 1:
        raise InstallSpecError("Expected the fixed primary and secondary lab disk paths")
    primary, secondary = primary[0], secondary[0]
    if primary.get("serial") != PRIMARY_SERIAL or secondary.get("serial") != SECONDARY_SERIAL:
        raise InstallSpecError("Lab disk serial mismatch; stop and rebuild the virtual workspace")
    size = primary.get("size_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size < MIN_PRIMARY_BYTES:
        raise InstallSpecError("Primary lab disk must have a verified capacity of at least 24 GiB")
    if primary.get("read_only") is not False:
        raise InstallSpecError("Primary lab disk read/write state is not positively verified")
    if secondary.get("read_only") is not True:
        raise InstallSpecError("Secondary lab disk must be read-only during Layer 07")
    secondary_size = secondary.get("size_bytes")
    if isinstance(secondary_size, bool) or not isinstance(secondary_size, int) or secondary_size <= 0:
        raise InstallSpecError("Secondary lab disk capacity is missing or malformed")
    for disk in (primary, secondary):
        holders = disk.get("holders")
        active_swap = disk.get("active_swap")
        if not isinstance(holders, list) or any(not isinstance(item, str) for item in holders):
            raise InstallSpecError("Disk holder state is missing or malformed")
        if not isinstance(active_swap, bool):
            raise InstallSpecError("Active-swap state is missing or malformed")
        if _mountpoints(disk) or holders or active_swap:
            raise InstallSpecError("A lab disk is mounted, held, or active as swap")
        for node in _walk(disk):
            if _mountpoints(node):
                raise InstallSpecError("A partition in the lab disk tree is mounted")
    if not any(d.get("path") == BOOT_PATH and d.get("type") == "rom" and d.get("read_only") is True for d in roms):
        raise InstallSpecError("A separate read-only boot medium was not verified")
    swaps = observation.get("active_swaps", [])
    if not isinstance(swaps, list) or any(not isinstance(path, str) for path in swaps):
        raise InstallSpecError("Active swap observations are malformed")
    if any(path == PRIMARY_PATH or path.startswith(PRIMARY_PATH) for path in swaps):
        raise InstallSpecError("Primary lab disk is active as swap")

    root_bytes = ((size - 16 * 1024**2) // (1024**2)) * (1024**2) - EFI_BYTES
    if root_bytes < 16 * 1024**3:
        raise InstallSpecError("Insufficient capacity after EFI and GPT headroom")
    spec = {
        "schema_version": 1,
        "status": "PREFLIGHT_ONLY",
        "execution_enabled": False,
        "network_mode": observation["network_mode"],
        "target": {
            "path": PRIMARY_PATH,
            "serial": PRIMARY_SERIAL,
            "size_bytes": size,
            "secondary_policy": "PRESERVE",
        },
        "layout": [
            {"label": "AEGIS_EFI", "size_bytes": EFI_BYTES, "filesystem": "FAT32",
             "encrypted": False, "mount": "/efi"},
            {"label": "AEGIS_ROOT", "size_bytes": root_bytes, "filesystem": "Btrfs",
             "encryption": "LUKS2", "encrypted": True, "mount": "/"},
        ],
        "phases": [
            {"id": "preflight", "mutating": False, "retry": "bounded_read_only_only"},
            {"id": "explicit_target_review", "mutating": False, "retry": "never_automatic"},
            {"id": "partition_gpt", "mutating": True, "retry": "never"},
            {"id": "format_efi", "mutating": True, "retry": "never"},
            {"id": "luks2_format_root", "mutating": True, "retry": "never"},
            {"id": "open_encrypted_root", "mutating": True, "retry": "never"},
            {"id": "format_btrfs", "mutating": True, "retry": "never"},
            {"id": "mount_target", "mutating": True, "retry": "never"},
            {"id": "pacstrap_base", "mutating": True, "retry": "never"},
            {"id": "configure_initramfs_and_boot", "mutating": True, "retry": "never"},
            {"id": "verify_installed_guest", "mutating": False, "retry": "bounded_read_only_only"},
        ],
        "recovery_policy": {
            "ambiguous_state": "STOP_AND_PRESERVE_EVIDENCE",
            "destructive_failure": "NO_AUTOMATIC_RETRY",
            "lab_recovery": "PRESERVE_JOURNAL_THEN_RECREATE_EPHEMERAL_VM",
        },
        "limitations": [
            "Specification only; no commands executed and no disks modified.",
            "Secondary disk is not a target and must remain untouched.",
            "TPM enrollment, signed boot, offline recovery and physical hardware are unverified.",
        ],
    }
    spec["spec_digest"] = _digest(spec)
    return spec
