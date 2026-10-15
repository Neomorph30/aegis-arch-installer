"""Conservative, read-only analysis of Linux block-device observations.

This module consumes structured observations; it does not probe or mutate hardware.
An assessment is advisory and never grants permission to write to a device.
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA_VERSION = 1
_BLOCKED = {"mounted", "active_swap", "has_holders", "ambiguous_identity", "malformed"}
_MAX_DEPTH = 16
_MAX_NODES = 4096
_DEVICE_PATH = re.compile(r"^/dev/[A-Za-z0-9_.!:+-]+(?:/[A-Za-z0-9_.!:+-]+)*$")


def _meaningful_references(value: Any) -> tuple[bool, bool]:
    """Return (has-reference, malformed) for lsblk-style optional reference lists."""
    if value is None or value == "":
        return False, False
    if isinstance(value, str):
        if value and not value.strip():
            return False, True
        return bool(value.strip()), False
    if isinstance(value, list):
        found = False
        for item in value:
            if item is None or item == "":
                continue
            if isinstance(item, str):
                if item and not item.strip():
                    return False, True
                found = found or bool(item.strip())
            else:
                return False, True
        return found, False
    return False, True


def assess_inventory(observation: dict[str, Any]) -> dict[str, Any]:
    """Validate a lsblk-like fixture and return per-device safety findings."""
    findings: list[dict[str, str]] = []
    devices: list[dict[str, Any]] = []

    def add(code: str, severity: str, message: str, next_action: str) -> None:
        findings.append({"code": code, "severity": severity,
                         "message": message, "next_action": next_action})

    def blocked_result(code: str, message: str, next_action: str) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "status": "blocked", "devices": [],
                "findings": [{"code": code, "severity": "error", "message": message,
                              "next_action": next_action}], "write_authorized": False}

    if not isinstance(observation, dict) or not isinstance(observation.get("devices"), list):
        return blocked_result("INVALID_INVENTORY", "Expected an object with a devices list.",
                              "Re-run read-only discovery; do not plan writes.")
    if not observation["devices"]:
        return blocked_result("EMPTY_INVENTORY", "No devices were discovered.",
                              "Check discovery tools and permissions; do not plan writes.")

    seen_paths: set[str] = set()
    seen_ids: dict[str, str] = {}
    count = 0
    limit_reported = False

    def visit(node: Any, depth: int = 0) -> None:
        nonlocal count, limit_reported
        if depth > _MAX_DEPTH or count >= _MAX_NODES:
            if not limit_reported:
                add("TREE_LIMIT", "error", "Device tree exceeds safety limits.",
                    "Inspect hardware topology manually.")
                limit_reported = True
            return
        count += 1
        if not isinstance(node, dict):
            add("MALFORMED_NODE", "error", "Device entry is not an object.",
                "Repeat discovery and inspect source output.")
            return

        path = node.get("path")
        kind = node.get("type")
        state = "review"
        if (not isinstance(path, str) or not _DEVICE_PATH.fullmatch(path)
                or any(part in {".", ".."} for part in path.split("/"))
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in path)):
            add("AMBIGUOUS_PATH", "error", "Missing or invalid device path.",
                "Do not select this device; refresh inventory.")
            state = "blocked"
        elif path in seen_paths:
            add("AMBIGUOUS_PATH", "error", "Duplicate device path.",
                "Do not select this device; refresh inventory.")
            state = "blocked"
        else:
            seen_paths.add(path)

        if not isinstance(kind, str) or not kind.strip():
            add("MALFORMED_TYPE", "error", "Device type is missing or invalid.",
                "Repeat discovery and inspect source output.")
            state = "blocked"

        serial = node.get("serial")
        wwn = node.get("wwn")
        ident: str | None = None
        if serial is not None and serial != "" and not isinstance(serial, str):
            add("MALFORMED_IDENTITY", "error", "Serial identifier has an invalid type.",
                "Resolve device identity ambiguity before planning.")
            state = "blocked"
        if wwn is not None and wwn != "" and not isinstance(wwn, str):
            add("MALFORMED_IDENTITY", "error", "WWN identifier has an invalid type.",
                "Resolve device identity ambiguity before planning.")
            state = "blocked"
        if isinstance(serial, str) and serial.strip():
            ident = serial.strip()
        if isinstance(wwn, str) and wwn.strip():
            ident = wwn.strip()
        # Stable serial/WWN identifiers are required for physical-disk candidates.
        # Partitions and device-mapper nodes commonly inherit identity from a parent
        # and must not be rejected solely because their own fields are empty.
        if ident is None and kind == "disk":
            add("MISSING_STABLE_IDENTITY", "error",
                "No stable serial or WWN identifier is available for this disk.",
                "Refresh discovery and resolve the disk identity before planning.")
            state = "blocked"
        # Collision checks protect physical-disk selection. Child nodes may repeat
        # a parent device's identifiers in some discovery formats.
        for label, raw in ((("serial", serial), ("wwn", wwn)) if kind == "disk" else ()):
            if isinstance(raw, str) and raw != "":
                normalized = raw.strip()
                if (not normalized or any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized)):
                    add("MALFORMED_IDENTITY", "error", "Stable device identifier is blank or contains control characters.",
                        "Resolve device identity ambiguity before planning.")
                    state = "blocked"
                elif (f"{label}:{normalized}" in seen_ids
                      and seen_ids[f"{label}:{normalized}"] != (path if isinstance(path, str) else "UNKNOWN")):
                    add("DUPLICATE_IDENTITY", "error", "Duplicate stable device identifier across devices.",
                        "Resolve device identity ambiguity before planning.")
                    state = "blocked"
                else:
                    # A serial and WWN may legitimately have the same text on the
                    # same device; only cross-device collisions are ambiguous.
                    seen_ids[f"{label}:{normalized}"] = path if isinstance(path, str) else "UNKNOWN"

        if "mountpoints" not in node and "mountpoint" not in node:
            mountpoints, bad_mountpoints = False, True
        else:
            mountpoints, bad_mountpoints = _meaningful_references(
                node.get("mountpoints", node.get("mountpoint")))
        if "holders" not in node:
            holders, bad_holders = False, True
        else:
            holders, bad_holders = _meaningful_references(node.get("holders"))
        reasons: list[str] = []
        if bad_mountpoints:
            add("MALFORMED_MOUNTPOINTS", "error", "Mountpoint information has an invalid shape.",
                "Repeat discovery; do not infer that the device is unused.")
            reasons.append("malformed")
        elif mountpoints:
            reasons.append("mounted")
        if bad_holders:
            add("MALFORMED_HOLDERS", "error", "Device-holder information has an invalid shape.",
                "Repeat discovery; do not infer that the device is unused.")
            reasons.append("malformed")
        elif holders:
            reasons.append("has_holders")

        active_swap = node.get("active_swap", False)
        ambiguous = node.get("ambiguous", False)
        if not isinstance(active_swap, bool):
            add("MALFORMED_SWAP_STATE", "error", "Active-swap state is not a boolean.",
                "Repeat discovery and inspect active swap.")
            reasons.append("malformed")
        elif active_swap:
            reasons.append("active_swap")
        if not isinstance(ambiguous, bool):
            add("MALFORMED_AMBIGUITY_STATE", "error", "Ambiguity state is not a boolean.",
                "Repeat discovery and inspect device identity.")
            reasons.append("malformed")
        elif ambiguous:
            reasons.append("ambiguous_identity")

        if isinstance(kind, str) and kind in {"crypt", "lvm", "raid", "md", "mpath", "dm"}:
            reasons.append("has_holders")
        for reason in dict.fromkeys(reasons):
            if reason not in {"malformed"}:
                add(reason.upper(), "warning",
                    f"Device {path if isinstance(path, str) else 'UNKNOWN'} has {reason.replace('_', ' ')} state.",
                    "Review dependencies; never automatically detach or deactivate it.")
        if any(reason in _BLOCKED for reason in reasons):
            state = "blocked"

        devices.append({
            "path": path if isinstance(path, str) else None,
            "type": kind if isinstance(kind, str) else None,
            "stable_id": ident,
            "state": state,
            "reasons": list(dict.fromkeys(reasons)),
        })

        children = node.get("children", [])
        if children is None:
            return
        if not isinstance(children, list):
            add("MALFORMED_CHILDREN", "error", "Children field is not a list.",
                "Refresh inventory and inspect probe output.")
            # This is a global block even if the node's display state is retained.
            return
        for child in children:
            visit(child, depth + 1)

    for index, root in enumerate(observation["devices"]):
        visit(root)
        if count >= _MAX_NODES:
            if index + 1 < len(observation["devices"]) and not limit_reported:
                add("TREE_LIMIT", "error", "Device tree exceeds safety limits.",
                    "Inspect hardware topology manually.")
                limit_reported = True
            break

    blocked = any(device["state"] == "blocked" for device in devices) or any(
        finding["severity"] == "error" for finding in findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "blocked" if blocked else "review_required",
        "devices": devices,
        "findings": findings,
        "write_authorized": False,
        "note": "Read-only assessment only. Re-probe device identity immediately before any future operation.",
    }
