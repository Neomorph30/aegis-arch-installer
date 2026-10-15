"""Preflight contract for future disposable-VM guest storage operations.

This module deliberately performs no I/O and authorizes no writes. It validates
an observed lsblk-like tree against the lab's fixed two-disk contract so a future
guest-only executor can build on tested, fail-closed checks.
"""
from __future__ import annotations

from typing import Any

PRIMARY_SERIAL = "AEGIS-LAB-PRIMARY"
PRIMARY_BYTES = 24 * 1024**3
SECONDARY_SERIAL = "AEGIS-LAB-SECONDARY"
SECONDARY_BYTES = 8 * 1024**3


class GuestStorageGateError(ValueError):
    """The guest's storage observation does not satisfy the lab contract."""


def validate_lab_primary(
    observation: dict[str, Any],
    *,
    expected_serial: str = PRIMARY_SERIAL,
    expected_size_bytes: int = PRIMARY_BYTES,
) -> dict[str, Any]:
    """Return a review record only for one exact, unused lab primary disk.

    A successful result is eligibility for a *separate future one-use consent
    step*, not write authorization. This function never opens a device.
    """
    if not isinstance(observation, dict) or not isinstance(observation.get("devices"), list):
        raise GuestStorageGateError("A complete devices list is required")
    roots = observation["devices"]
    if len(roots) != 2:
        raise GuestStorageGateError("Expected exactly the two lab virtual disks; extra or missing disks block writes")

    all_nodes: list[dict[str, Any]] = []
    paths: set[str] = set()
    serial_matches: list[dict[str, Any]] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 16 or len(all_nodes) >= 4096:
            raise GuestStorageGateError("Block-device topology exceeds safety limits")
        if not isinstance(node, dict):
            raise GuestStorageGateError("Malformed block-device entry")
        path = node.get("path")
        kind = node.get("type")
        if not isinstance(path, str) or not path.startswith("/dev/") or path in paths:
            raise GuestStorageGateError("Missing, invalid or duplicate device path")
        if not isinstance(kind, str) or not kind:
            raise GuestStorageGateError("Missing block-device type")
        paths.add(path)
        all_nodes.append(node)
        if kind == "disk" and node.get("serial") == expected_serial:
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
    secondary = secondary_matches[0]
    if secondary.get("size") != SECONDARY_BYTES or secondary.get("ro") not in (True, 1):
        raise GuestStorageGateError("Secondary lab disk must match its exact capacity and be read-only")

    target = serial_matches[0]
    if target.get("type") != "disk" or target.get("size") != expected_size_bytes:
        raise GuestStorageGateError("Lab primary disk type or exact capacity does not match")
    if target.get("ro") not in (False, 0):
        raise GuestStorageGateError("Lab primary disk is read-only or its state is unknown")
    if target.get("rm") not in (False, 0):
        raise GuestStorageGateError("Removable primary targets are forbidden")
    if target.get("ambiguous") is not False:
        raise GuestStorageGateError("Lab primary identity is ambiguous")
    if not isinstance(target.get("serial"), str) or target["serial"] != expected_serial:
        raise GuestStorageGateError("Stable lab primary serial is missing")

    for node in all_nodes:
        if node.get("mountpoints"):
            raise GuestStorageGateError("Mounted block devices are forbidden for lab writes")
        if node.get("holders"):
            raise GuestStorageGateError("Block-device holders are forbidden for lab writes")
        if node.get("active_swap") is not False:
            raise GuestStorageGateError("Active or unknown swap state blocks lab writes")
        if node.get("ambiguous") is not False:
            raise GuestStorageGateError("Ambiguous device identity blocks lab writes")

    return {
        "schema_version": 1,
        "status": "ELIGIBLE_FOR_SEPARATE_EXPLICIT_LAB_CONSENT",
        "target": {"path": target["path"], "serial": target["serial"], "size_bytes": target["size"]},
        "write_authorized": False,
        "writes_performed": False,
        "note": "Preflight only. A future executor must independently re-probe and require one-use consent.",
    }
