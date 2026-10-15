"""Conservative, read-only analysis of Linux block-device observations.

This module consumes structured observations; it does not probe or mutate hardware.
An assessment is advisory and never grants permission to write to a device.
"""
from __future__ import annotations
from typing import Any

SCHEMA_VERSION = 1
_BLOCKED = {"mounted", "active_swap", "has_holders", "ambiguous_identity", "malformed"}

def assess_inventory(observation: dict[str, Any]) -> dict[str, Any]:
    """Validate a lsblk-like fixture and return per-device safety findings."""
    findings: list[dict[str, str]] = []
    devices: list[dict[str, Any]] = []
    if not isinstance(observation, dict) or not isinstance(observation.get("devices"), list):
        return {"schema_version": SCHEMA_VERSION, "status": "blocked",
                "devices": [], "findings": [{"code": "INVALID_INVENTORY",
                "severity": "error", "message": "Expected an object with a devices list.",
                "next_action": "Re-run read-only discovery; do not plan writes."}]}
    seen_paths: set[str] = set()
    seen_ids: dict[str, str] = {}
    count = 0
    def visit(node: Any, depth: int = 0) -> None:
        nonlocal count
        if depth > 16 or count >= 4096:
            findings.append({"code":"TREE_LIMIT","severity":"error","message":"Device tree exceeds safety limits.","next_action":"Inspect hardware topology manually."})
            return
        count += 1
        if not isinstance(node, dict):
            findings.append({"code":"MALFORMED_NODE","severity":"error","message":"Device entry is not an object.","next_action":"Repeat discovery and inspect source output."})
            return
        path = node.get("path")
        kind = node.get("type")
        if not isinstance(path, str) or not path.startswith("/dev/") or path in seen_paths:
            findings.append({"code":"AMBIGUOUS_PATH","severity":"error","message":"Missing, invalid or duplicate device path.","next_action":"Do not select this device; refresh inventory."})
            state = "blocked"
        else:
            seen_paths.add(path)
            state = "review"
        ident = node.get("wwn") or node.get("serial")
        if ident:
            if not isinstance(ident, str) or ident in seen_ids:
                findings.append({"code":"DUPLICATE_IDENTITY","severity":"error","message":"Duplicate or invalid stable device identifier.","next_action":"Resolve device identity ambiguity before planning."})
                state = "blocked"
            else:
                seen_ids[ident] = path
        reasons = []
        if node.get("mountpoints") or node.get("mountpoint"):
            reasons.append("mounted")
        if node.get("active_swap"):
            reasons.append("active_swap")
        if node.get("holders") or node.get("children"):
            # Child partitions alone are normal; nested mapper/RAID holders are not.
            if node.get("holders") or kind in {"crypt", "lvm", "raid", "md"}:
                reasons.append("has_holders")
        if node.get("ambiguous"):
            reasons.append("ambiguous_identity")
        for reason in reasons:
            findings.append({"code":reason.upper(),"severity":"warning","message":f"Device {path} has {reason.replace('_',' ')} state.","next_action":"Review dependencies; never automatically detach or deactivate it."})
        if any(r in _BLOCKED for r in reasons):
            state = "blocked"
        devices.append({"path":path if isinstance(path,str) else None,"type":kind if isinstance(kind,str) else None,
                        "stable_id":ident if isinstance(ident,str) else None,"state":state,"reasons":reasons})
        children = node.get("children", [])
        if children is not None:
            if not isinstance(children, list):
                findings.append({"code":"MALFORMED_CHILDREN","severity":"error","message":"Children field is not a list.","next_action":"Refresh inventory and inspect probe output."})
            else:
                for child in children:
                    visit(child, depth + 1)
    for root in observation["devices"]:
        visit(root)
    blocked = any(d["state"] == "blocked" for d in devices) or any(f["severity"] == "error" for f in findings)
    return {"schema_version":SCHEMA_VERSION,"status":"blocked" if blocked else "review_required",
            "devices":devices,"findings":findings,
            "write_authorized":False,
            "note":"Read-only assessment only. Re-probe device identity immediately before any future operation."}
