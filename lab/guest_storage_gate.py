"""Preflight contract for future disposable-VM guest storage operations.

This module deliberately performs no I/O and authorizes no writes. It validates
an observed lsblk-like tree against the lab's fixed two-disk contract so a future
guest-only executor can build on tested, fail-closed checks.
"""
from __future__ import annotations

from typing import Any
import re

PRIMARY_SERIAL = "AEGIS-LAB-PRIMARY"
PRIMARY_BYTES = 24 * 1024**3
SECONDARY_SERIAL = "AEGIS-LAB-SECONDARY"
SECONDARY_BYTES = 8 * 1024**3
_DEVICE_PATH = re.compile(r"^/dev/[A-Za-z0-9_.!:+-]+(?:/[A-Za-z0-9_.!:+-]+)*$")
_MAJOR_MINOR = re.compile(r"^[0-9]+:[0-9]+$")


class GuestStorageGateError(ValueError):
    """The guest's storage observation does not satisfy the lab contract."""


def validate_lab_primary(observation: dict[str, Any]) -> dict[str, Any]:
    """Return a review record only for one exact, unused lab primary disk.

    A successful result is eligibility for a *separate future one-use consent
    step*, not write authorization. This function never opens a device.
    """
    if not isinstance(observation, dict) or not isinstance(observation.get("devices"), list):
        raise GuestStorageGateError("A complete devices list is required")
    roots = observation["devices"]
    if len(roots) != 2:
        raise GuestStorageGateError("Expected exactly the two lab virtual disks; extra or missing disks block writes")
    if any(not isinstance(root, dict) or root.get("type") != "disk" for root in roots):
        raise GuestStorageGateError("Both root devices must be whole virtual disks")

    all_nodes: list[dict[str, Any]] = []
    paths: set[str] = set()
    kernel_identities: set[tuple[int, int]] = set()
    serial_matches: list[dict[str, Any]] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 16 or len(all_nodes) >= 4096:
            raise GuestStorageGateError("Block-device topology exceeds safety limits")
        if not isinstance(node, dict):
            raise GuestStorageGateError("Malformed block-device entry")
        path = node.get("path")
        kind = node.get("type")
        if (not isinstance(path, str)
                or not _DEVICE_PATH.fullmatch(path)
                or any(part in (".", "..") for part in path.split("/"))
                or path in paths):
            raise GuestStorageGateError("Missing, invalid or duplicate device path")
        if not isinstance(kind, str) or not kind:
            raise GuestStorageGateError("Missing block-device type")
        size = node.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise GuestStorageGateError(f"Invalid block-device capacity on {path}")
        for flag in ("ro", "rm"):
            flag_value = node.get(flag)
            if type(flag_value) not in (bool, int) or flag_value not in (0, 1):
                raise GuestStorageGateError(f"Unverified {flag} flag on {path}")
        major_minor = node.get("major_minor")
        if not isinstance(major_minor, str) or not _MAJOR_MINOR.fullmatch(major_minor):
            raise GuestStorageGateError(f"Missing or malformed kernel device identity on {path}")
        major_text, minor_text = major_minor.split(":", 1)
        identity = (int(major_text), int(minor_text))
        if identity in kernel_identities:
            raise GuestStorageGateError("Duplicate kernel major/minor identity; device paths may alias the same block device")
        kernel_identities.add(identity)
        paths.add(path)
        all_nodes.append(node)
        if kind == "disk" and node.get("serial") == PRIMARY_SERIAL:
            serial_matches.append(node)

        for field in ("mountpoints", "holders"):
            value = node.get(field)
            if not isinstance(value, list):
                raise GuestStorageGateError(f"Unverified {field} on {path}")
            if any(item is not None and (not isinstance(item, str) or not item.strip())
                   for item in value):
                raise GuestStorageGateError(f"Malformed {field} on {path}")
        if "active_swap" not in node or not isinstance(node["active_swap"], bool):
            raise GuestStorageGateError(f"Unverified active-swap state on {path}")
        if "ambiguous" not in node or not isinstance(node["ambiguous"], bool):
            raise GuestStorageGateError(f"Unverified identity ambiguity state on {path}")
        children = node.get("children")
        if not isinstance(children, list):
            raise GuestStorageGateError(f"Incomplete child topology on {path}")
        for child in children:
            visit(child, depth + 1)

    for root in roots:
        visit(root)

    if len(serial_matches) != 1:
        raise GuestStorageGateError("Expected exactly one AEGIS-LAB-PRIMARY disk")
    secondary_matches = [
        node for node in roots
        if isinstance(node, dict) and node.get("type") == "disk"
        and node.get("serial") == SECONDARY_SERIAL
    ]
    if len(secondary_matches) != 1:
        raise GuestStorageGateError("Expected exactly one AEGIS-LAB-SECONDARY disk")
    if {node.get("serial") for node in roots} != {PRIMARY_SERIAL, SECONDARY_SERIAL}:
        raise GuestStorageGateError("Root disks must have exactly the two fixed lab serials")
    secondary = secondary_matches[0]
    target = serial_matches[0]
    if target.get("path") != "/dev/vda" or secondary.get("path") != "/dev/vdb":
        raise GuestStorageGateError("Lab disks must use the fixed /dev/vda primary and /dev/vdb secondary paths")
    if secondary.get("size") != SECONDARY_BYTES or secondary.get("ro") not in (True, 1):
        raise GuestStorageGateError("Secondary lab disk must match its exact capacity and be read-only")
    if secondary.get("rm") not in (False, 0):
        raise GuestStorageGateError("Removable secondary lab disks are forbidden")

    if target.get("type") != "disk" or target.get("size") != PRIMARY_BYTES:
        raise GuestStorageGateError("Lab primary disk type or exact capacity does not match")
    if target.get("ro") not in (False, 0):
        raise GuestStorageGateError("Lab primary disk is read-only or its state is unknown")
    if target.get("rm") not in (False, 0):
        raise GuestStorageGateError("Removable primary targets are forbidden")
    if target.get("ambiguous") is not False:
        raise GuestStorageGateError("Lab primary identity is ambiguous")
    if not isinstance(target.get("serial"), str) or target["serial"] != PRIMARY_SERIAL:
        raise GuestStorageGateError("Stable lab primary serial is missing")

    for node in all_nodes:
        mounts = node.get("mountpoints", [])
        if any(isinstance(item, str) and item.strip() for item in mounts):
            raise GuestStorageGateError("Mounted block devices are forbidden for lab writes")
        if node.get("holders"):
            raise GuestStorageGateError("Block-device holders are forbidden for lab writes")
        if node.get("active_swap") is not False:
            raise GuestStorageGateError("Active or unknown swap state blocks lab writes")
        if node.get("ambiguous") is not False:
            raise GuestStorageGateError("Ambiguous device identity blocks lab writes")

    if target.get("children") != [] or secondary.get("children") != []:
        raise GuestStorageGateError("Lab disks must be blank whole disks before a write plan is considered")

    return {
        "schema_version": 1,
        "status": "ELIGIBLE_FOR_SEPARATE_EXPLICIT_LAB_CONSENT",
        "target": {"path": target["path"], "serial": target["serial"], "size_bytes": target["size"]},
        "write_authorized": False,
        "writes_performed": False,
        "note": "Preflight only. A future executor must independently re-probe and require one-use consent.",
    }

def observe_guest_storage() -> dict[str, Any]:
    """Collect a fresh read-only lsblk/sysfs/swap snapshot; unknown state fails closed."""
    import json
    import os
    import stat
    import subprocess
    from pathlib import Path

    command = [
        "lsblk", "--json", "--bytes", "--paths", "--tree",
        "--output", "PATH,TYPE,SERIAL,SIZE,RO,RM,MOUNTPOINTS,MAJ:MIN",
    ]
    try:
        completed = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=10,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise GuestStorageGateError("Unable to obtain a fresh complete lsblk observation") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("blockdevices"), list):
        raise GuestStorageGateError("lsblk response is incomplete")

    try:
        swap_lines = Path("/proc/swaps").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GuestStorageGateError("Unable to verify active swap state") from exc
    swap_ids: set[tuple[int, int]] = set()
    for line in swap_lines[1:]:
        fields = line.split()
        if not fields:
            continue
        try:
            info = os.stat(fields[0])
        except OSError:
            # A swap file is not a block device; its backing filesystem is still
            # protected by the mount check. Do not treat an unreadable entry as safe.
            if not Path(fields[0]).is_file():
                raise GuestStorageGateError("Unable to resolve an active swap entry")
            continue
        if stat.S_ISBLK(info.st_mode):
            swap_ids.add((os.major(info.st_rdev), os.minor(info.st_rdev)))

    serial_counts: dict[str, int] = {}
    # Inspect raw topology iteratively before any recursive enrichment. Bound both
    # depth and total nodes so hostile/malformed lsblk JSON cannot exhaust stack or
    # CPU before the validator gets a chance to reject it.
    raw_roots = payload["blockdevices"]
    stack = [(root, 0) for root in reversed(raw_roots)]
    visited = 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        if depth > 16 or visited > 4096:
            raise GuestStorageGateError("Block-device topology exceeds safety limits")
        if not isinstance(node, dict):
            raise GuestStorageGateError("Malformed lsblk child entry")
        serial = node.get("serial")
        if isinstance(serial, str) and serial.strip():
            normalized_serial = serial.strip()
            serial_counts[normalized_serial] = serial_counts.get(normalized_serial, 0) + 1
        children = node.get("children", [])
        if not isinstance(children, list):
            raise GuestStorageGateError("lsblk returned malformed child topology")
        stack.extend((child, depth + 1) for child in reversed(children))
    # A booted live ISO commonly exposes its optical drive and one or more
    # loop devices. They are not candidate installation disks. Exclude only
    # these explicit non-disk types; unexpected disks and other root block
    # device types remain visible to the strict validation gate.
    candidate_roots = [
        root for root in raw_roots
        if isinstance(root, dict) and root.get("type") not in ("loop", "rom")
    ]

    def enrich(node: dict[str, Any]) -> dict[str, Any]:
        path = node.get("path")
        major_minor = node.get("maj:min")
        if not isinstance(path, str) or not isinstance(major_minor, str) or ":" not in major_minor:
            raise GuestStorageGateError("Device path or kernel major/minor identity is missing")
        try:
            major_text, minor_text = major_minor.split(":", 1)
            identity = (int(major_text), int(minor_text))
            sysfs = Path("/sys/dev/block") / f"{identity[0]}:{identity[1]}"
            holders_dir = sysfs / "holders"
            holders = sorted(entry.name for entry in holders_dir.iterdir())
        except (ValueError, OSError) as exc:
            raise GuestStorageGateError(f"Unable to verify sysfs holders for {path}") from exc

        mounts = node.get("mountpoints")
        if mounts is None:
            raise GuestStorageGateError(f"Unable to verify mountpoints for {path}")
        if not isinstance(mounts, list) or any(
            item is not None and (not isinstance(item, str) or not item.strip())
            for item in mounts
        ):
            raise GuestStorageGateError(f"Malformed mountpoints for {path}")
        # lsblk commonly represents an unmounted device as [null]; normalize
        # that to an empty list so only real mount paths block the target.
        mounts = [item for item in mounts if isinstance(item, str) and item.strip()]
        serial = node.get("serial")
        serial = serial.strip() if isinstance(serial, str) and serial.strip() else None
        # lsblk omits "children" on leaf devices; --tree includes nested
        # devices when present. The normalized gate input always gets a list.
        children = node.get("children", [])
        if not isinstance(children, list):
            raise GuestStorageGateError(f"Unable to verify child topology for {path}")
        if not isinstance(node.get("size"), int) or isinstance(node.get("size"), bool):
            raise GuestStorageGateError(f"Unable to verify capacity for {path}")
        if node.get("ro") not in (0, 1, False, True) or node.get("rm") not in (0, 1, False, True):
            raise GuestStorageGateError(f"Unable to verify read-only/removable flags for {path}")
        kind = node.get("type")
        if not isinstance(kind, str) or not kind:
            raise GuestStorageGateError(f"Unable to verify type for {path}")
        return {
            "path": path,
            "major_minor": f"{identity[0]}:{identity[1]}",
            "type": kind,
            "serial": serial,
            "size": node["size"],
            "ro": bool(node["ro"]),
            "rm": bool(node["rm"]),
            "mountpoints": mounts,
            "holders": holders,
            "active_swap": identity in swap_ids,
            "ambiguous": bool(serial and serial_counts.get(serial, 0) > 1),
            "children": [enrich(child) for child in children],
        }

    return {"devices": [enrich(root) for root in candidate_roots]}


def main(argv: list[str] | None = None) -> int:
    """Read-only guest preflight entry point; it never authorizes or performs writes."""
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Read-only AEGIS disposable-VM storage preflight")
    parser.add_argument("--preflight", action="store_true", help="probe live block devices and assess the fixed lab pair")
    parser.add_argument("--marker", action="store_true",
                        help="emit a short success marker for automated disposable-VM verification")
    args = parser.parse_args(argv)
    if not args.preflight:
        parser.error("only --preflight is supported; storage writes are not implemented")
    try:
        observation = observe_guest_storage()
        result = validate_lab_primary(observation)
    except GuestStorageGateError as exc:
        print(json.dumps({
            "schema_version": 1, "status": "BLOCKED",
            "write_authorized": False, "writes_performed": False,
            "reason": str(exc),
        }, sort_keys=True))
        return 2
    if args.marker:
        if result.get("write_authorized") is not False or result.get("writes_performed") is not False:
            print("AEGIS PREFLIGHT BLOCKED UNSAFE RESULT")
            return 2
        print("AEGIS PREFLIGHT PASS WRITE AUTHORIZED FALSE WRITES PERFORMED FALSE")
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
