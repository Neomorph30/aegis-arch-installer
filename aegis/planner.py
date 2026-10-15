"""Pure read-only storage planning. Deliberately NO executable disk actions.

Proposals carry identity and safety flags for review, but must never become
privileged instructions without independent device identification and consent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import hashlib
import json

MIB = 1024 ** 2
GIB = 1024 ** 3
ALIGNMENT = MIB
EFI_SIZE_BYTES = 4 * GIB
GPT_HEADROOM_BYTES = 16 * MIB
MIN_PRIMARY_BYTES = 32 * GIB
SECONDARY_ACTIONS = frozenset({"preserve", "unlock-existing", "erase"})
FILESYSTEMS = frozenset({"btrfs", "ext4"})
SENSITIVE_MOUNTPOINTS = frozenset({
    "/", "/boot", "/efi", "/boot/efi", "/run/archiso/bootmnt",
    "/run/archiso/cowspace", "/run/live/medium", "/cdrom",
})


class PlanError(ValueError):
    pass


def _validated_disks(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    raw = inventory.get("disks")
    if not isinstance(raw, list) or not raw:
        raise PlanError("Inventory must contain a non-empty disks list")
    paths: set[str] = set()
    identifiers: dict[str, str] = {}
    result: list[dict[str, Any]] = []
    for index, disk in enumerate(raw):
        if not isinstance(disk, dict):
            raise PlanError(f"Inventory disk entry {index} is malformed")
        path = disk.get("path")
        if not isinstance(path, str) or not path.startswith("/dev/") or ".." in path or path in paths:
            raise PlanError("Inventory has an invalid or duplicate device path")
        paths.add(path)
        # Treat serial and WWN as separate namespaces, but reject collisions within each.
        for field in ("serial", "wwn"):
            value = disk.get(field)
            if value is not None and value != "":
                if not isinstance(value, str) or not value.strip():
                    raise PlanError(f"Inventory contains an invalid {field}")
                key = f"{field}:{value.strip()}"
                if key in identifiers:
                    raise PlanError(f"Inventory has duplicate {field} values; device identity is ambiguous")
                identifiers[key] = path
        result.append(disk)
    return result


def _find_disk(inventory: dict[str, Any], path: str) -> dict[str, Any]:
    if not isinstance(path, str) or not path.startswith("/dev/") or ".." in path:
        raise PlanError("Disk must have a /dev/ device path")
    disks = _validated_disks(inventory)
    matches = [d for d in disks if d.get("path") == path and d.get("type", "disk") == "disk"]
    if len(matches) != 1:
        raise PlanError(f"Disk {path!r} is not uniquely present in the inventory")
    return matches[0]


def _canonical_digest(value: dict[str, Any]) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PlanError("Plan contains data that cannot be canonically serialized") from exc
    return hashlib.sha256(encoded).hexdigest()


def verify_storage_plan_integrity(plan: dict[str, Any]) -> bool:
    """Detect accidental or malicious edits to a generated proposal; not authorization."""
    if not isinstance(plan, dict) or not isinstance(plan.get("plan_digest"), str):
        return False
    expected = plan["plan_digest"]
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    try:
        import hmac\n        return hmac.compare_digest(expected, _canonical_digest(unsigned))
    except (PlanError, TypeError, ValueError):
        return False


def _partition_summary(children: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not isinstance(children, list):
        return result
    for child in children:
        if not isinstance(child, dict):
            continue
        mounts = child.get("mountpoints") or []
        if isinstance(mounts, str):
            mounts = [mounts]
        result.append({
            "path": child.get("path"),
            "type": child.get("type"),
            "filesystem": child.get("fstype"),
            "size_bytes": child.get("size"),
            "mountpoints": [m for m in mounts if isinstance(m, str) and m.strip()],
            "partuuid": child.get("partuuid"),
        })
        result.extend(_partition_summary(child.get("children", [])))
    return result


def _disk_identity(disk: dict[str, Any]) -> dict[str, Any]:
    mounts = disk.get("mountpoints") or []
    if isinstance(mounts, str):
        mounts = [mounts]
    return {
        "path": disk.get("path"),
        "model": str(disk.get("model") or "").strip(),
        "serial": str(disk.get("serial") or "").strip() or None,
        "wwn": str(disk.get("wwn") or "").strip() or None,
        "size_bytes": disk.get("size"),
        "transport": disk.get("tran"),
        "removable": bool(disk.get("rm")),
        "read_only": bool(disk.get("ro")),
        "hotplug": bool(disk.get("hotplug")),
        "mountpoints": [m for m in mounts if isinstance(m, str) and m.strip()],
        "current_partitions": _partition_summary(disk.get("children", [])),
    }


def _mounted_points(disk: dict[str, Any]) -> list[str]:
    return disk["mountpoints"] + [m for p in disk["current_partitions"]
                                  for m in p["mountpoints"]]


def _safety_checks(disk: dict[str, Any], role: str, destructive: bool) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    blockers: list[str] = []
    if not destructive:
        if _mounted_points(disk):
            warnings.append(f"{role}: existing mounted volumes will not be modified")
        return warnings, blockers
    if disk["removable"] or disk["hotplug"] or disk["transport"] == "usb":
        blockers.append(f"{role}: removable/hotplug/USB device; cannot prove it is not installation media")
    if disk["read_only"]:
        blockers.append(f"{role}: target is read-only")
    if not disk["serial"] and not disk["wwn"]:
        blockers.append(f"{role}: no serial or WWN to support stable hardware identification")
    mountpoints = _mounted_points(disk)
    if mountpoints:
        blockers.append(f"{role}: mounted device tree ({', '.join(sorted(set(mountpoints)))})")
        if any(m in SENSITIVE_MOUNTPOINTS or m.startswith("/run/archiso/") for m in mountpoints):
            blockers.append(f"{role}: contains active system or installation-media mount")
    if disk["size_bytes"] is None or isinstance(disk["size_bytes"], bool) or not isinstance(disk["size_bytes"], int):
        blockers.append(f"{role}: disk capacity could not be verified")
    warnings.append(f"{role}: a future executor must re-check device identity and in-use state immediately before writing")
    return warnings, blockers


def _align_down(value: int, alignment: int = ALIGNMENT) -> int:
    return (value // alignment) * alignment


def _primary_layout(size: int, filesystem: str) -> list[dict[str, Any]]:
    """Pure proposed geometry with explicit end-exclusive byte offsets."""
    first = ALIGNMENT
    root_first = first + EFI_SIZE_BYTES
    root_end = _align_down(size - GPT_HEADROOM_BYTES)
    if root_end - root_first < 20 * GIB:
        raise PlanError("Insufficient space for a secure system after EFI and GPT headroom")
    return [
        {"label": "EFI System Partition", "offset_bytes": first,
         "end_exclusive_bytes": root_first, "size_bytes": EFI_SIZE_BYTES,
         "filesystem": "FAT32", "encrypted": False, "mount": "/efi"},
        {"label": "AEGIS root", "offset_bytes": root_first,
         "end_exclusive_bytes": root_end, "size_bytes": root_end - root_first,
         "filesystem": filesystem, "encrypted": True, "encryption": "LUKS2", "mount": "/"},
    ]


def _secondary_layout(size: int) -> list[dict[str, Any]]:
    first = ALIGNMENT
    end = _align_down(size - GPT_HEADROOM_BYTES)
    if end <= first:
        raise PlanError("Secondary disk has insufficient available capacity")
    return [{"label": "AEGIS encrypted data", "offset_bytes": first,
             "end_exclusive_bytes": end, "size_bytes": end - first,
             "filesystem": "btrfs", "encrypted": True,
             "encryption": "LUKS2", "mount": "/data"}]


def build_storage_plan(
    inventory: dict[str, Any], primary: str, secondary: str | None = None,
    secondary_action: str = "preserve", *, filesystem: str = "btrfs",
) -> dict[str, Any]:
    """Create a human-reviewable plan. It cannot be executed by this package."""
    if not isinstance(inventory, dict):
        raise PlanError("Hardware inventory must be an object")
    if secondary_action not in SECONDARY_ACTIONS:
        raise PlanError(f"secondary_action must be one of {sorted(SECONDARY_ACTIONS)}")
    if filesystem not in FILESYSTEMS:
        raise PlanError(f"filesystem must be one of {sorted(FILESYSTEMS)}")
    if secondary is None and secondary_action != "preserve":
        raise PlanError("Select a secondary disk to propose unlock or erase")
    if secondary is not None and secondary == primary:
        raise PlanError("Primary and secondary cannot be the same disk")
    primary_disk = _disk_identity(_find_disk(inventory, primary))
    size = primary_disk["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int) or size < MIN_PRIMARY_BYTES:
        raise PlanError("Primary disk must have a verified size of at least 32 GiB")
    second_disk = _disk_identity(_find_disk(inventory, secondary)) if secondary else None
    if second_disk and secondary_action == "erase":
        second_size = second_disk["size_bytes"]
        if isinstance(second_size, bool) or not isinstance(second_size, int) or second_size < GIB:
            raise PlanError("Secondary erase proposal requires a verified disk size of at least 1 GiB")
    if second_disk and secondary_action == "unlock-existing":
        if not any(p["filesystem"] == "crypto_LUKS" for p in second_disk["current_partitions"]):
            raise PlanError("Secondary drive has no detected LUKS container")
    # Collision of two device paths pointing at the same WWN/serial, when known.
    if second_disk and any(primary_disk[key] and second_disk[key] and
                           primary_disk[key] == second_disk[key] for key in ("wwn", "serial")):
        raise PlanError("Selected disk identities collide; refusing ambiguous multi-disk plan")
    warning1, blocked1 = _safety_checks(primary_disk, "primary", True)
    warning2, blocked2 = _safety_checks(second_disk, "secondary", secondary_action == "erase") if second_disk else ([], [])
    warnings = warning1 + warning2 + [
        "PROPOSAL ONLY: no partition, encryption, firmware, or boot operations are implemented",
        "Backups, per-device confirmation, offline recovery enrollment, and independently tested boot are mandatory",
        "TPM + PIN, Secure Boot, encryption and recovery are planned, not configured or verified",
    ]
    blockers = blocked1 + blocked2
    if inventory.get("architecture") not in (None, "x86_64"):
        blockers.append("Installer target is not verified as x86_64")
    if inventory.get("uefi_detected") is False:
        blockers.append("UEFI not detected; this particular encrypted boot profile requires UEFI")
    actions = [{
        "target": primary, "action": "erase", "destructive": True,
        "description": f"Propose GPT, 4 GiB EFI, remaining LUKS2/{filesystem} root",
        "partitions": _primary_layout(size, filesystem),
    }]
    if second_disk:
        actions.append({
            "target": secondary, "action": secondary_action,
            "destructive": secondary_action == "erase",
            "description": {
                "preserve": "Leave secondary storage untouched and unmounted",
                "unlock-existing": "Review existing LUKS partition for potential mount; no credentials collected",
                "erase": "Propose GPT and one new LUKS2/Btrfs data partition",
            }[secondary_action],
            "partitions": _secondary_layout(second_disk["size_bytes"]) if secondary_action == "erase" else [],
        })
    plan = {
        "schema_version": "0.3",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PROPOSAL_ONLY",
        "execution_enabled": False,
        "review_state": "BLOCKED" if blockers else "REQUIRES_EXPLICIT_APPROVAL",
        "filesystem": filesystem,
        "root_encryption": "LUKS2 planned, not configured",
        "boot_policy": "TPM 2.0 + PIN planned, offline recovery required; not configured",
        "primary": primary_disk,
        "secondary": second_disk,
        "efi_partition_bytes": EFI_SIZE_BYTES,
        "btrfs_subvolumes": ["@", "@home", "@snapshots", "@var_log", "@var_cache"] if filesystem == "btrfs" else [],
        "actions": actions,
        "blockers": blockers,
        "warnings": warnings,
        "tests": [
            {"name": "Hardware identity and mounted-device review", "result": "BLOCKED" if blockers else "REVIEW_REQUIRED"},
            {"name": "Storage changes", "result": "UNVERIFIED"},
            {"name": "TPM enrollment", "result": "UNVERIFIED"},
            {"name": "Offline recovery", "result": "UNVERIFIED"},
        ],
    }
    # Fingerprint the selected and available storage identities to detect stale proposals.
    plan["inventory_fingerprint"] = _canonical_digest({
        "disks": [_disk_identity(d) for d in _validated_disks(inventory)],
        "architecture": inventory.get("architecture"),
        "uefi_detected": inventory.get("uefi_detected"),
    })
    plan["plan_digest"] = _canonical_digest(plan)
    return plan
