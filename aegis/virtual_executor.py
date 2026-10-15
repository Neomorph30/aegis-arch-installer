"""Virtual-only execution gate for testing authorization and recovery.

This module never partitions, formats, mounts, encrypts, or opens a block device.
It validates a proposal against synthetic regular files and writes only a review
journal into a private temporary workspace. It is not an installation executor.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from .planner import verify_storage_plan_integrity


class VirtualExecutionError(RuntimeError):
    """A virtual execution request failed a safety gate."""


def _private_workspace(workspace: Path) -> Path:
    try:
        if workspace.is_symlink():
            raise VirtualExecutionError("Workspace must not be a symlink")
        root = workspace.resolve(strict=True)
        st = root.stat()
    except OSError as exc:
        raise VirtualExecutionError("Workspace is unavailable; recreate a private lab workspace") from exc
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o077:
        raise VirtualExecutionError("Workspace must be a private directory with mode 0700 or stricter")
    return root


def _regular_virtual_target(root: Path, candidate: str) -> Path:
    path = Path(candidate)
    if path.is_symlink():
        raise VirtualExecutionError("Virtual target symlinks are forbidden")
    try:
        resolved = path.resolve(strict=True)
        st = resolved.stat()
    except OSError as exc:
        raise VirtualExecutionError("Virtual target is missing; recreate the lab image") from exc
    if resolved.parent != root:
        raise VirtualExecutionError("Virtual targets must be direct children of the private lab workspace")
    if not stat.S_ISREG(st.st_mode):
        raise VirtualExecutionError("Only synthetic regular files are accepted; block devices are forbidden")
    if st.st_mode & 0o077:
        raise VirtualExecutionError("Virtual target permissions must be 0600 or stricter")
    return resolved


def _identity_matches(expected: dict[str, Any], supplied: dict[str, Any]) -> bool:
    if not isinstance(expected, dict) or not isinstance(supplied, dict):
        return False
    stable = [key for key in ("serial", "wwn") if expected.get(key)]
    if not stable:
        return False
    return all(isinstance(supplied.get(key), str) and supplied[key] == expected[key]
               for key in stable)


def simulate_execution(
    plan: dict[str, Any],
    *,
    workspace: str | Path,
    virtual_targets: dict[str, str | Path],
    approved_identities: dict[str, dict[str, Any]],
    journal_name: str = "execution-journal.json",
) -> dict[str, Any]:
    """Simulate an execution review; writes only a new journal, never target files.

    The caller must explicitly map each destructive plan target to a synthetic
    regular file and separately confirm its displayed stable identity. This is
    not authorization for, or a path to, physical-device execution.
    """
    if not verify_storage_plan_integrity(plan):
        raise VirtualExecutionError("Plan digest is missing or invalid; regenerate and review the plan")
    if plan.get("status") != "PROPOSAL_ONLY" or plan.get("execution_enabled") is not False:
        raise VirtualExecutionError("Only proposal-only plans may enter virtual simulation")
    if plan.get("review_state") != "REQUIRES_EXPLICIT_APPROVAL" or plan.get("blockers"):
        raise VirtualExecutionError("Blocked or incomplete plans cannot be simulated")
    if not isinstance(plan.get("actions"), list) or not plan["actions"]:
        raise VirtualExecutionError("Plan has no actions to review")
    if not isinstance(virtual_targets, dict) or not isinstance(approved_identities, dict):
        raise VirtualExecutionError("Virtual target mapping and identity approvals are required")

    root = _private_workspace(Path(workspace))
    journal_path = root / journal_name
    if Path(journal_name).name != journal_name or journal_name in ("", ".", ".."):
        raise VirtualExecutionError("Journal name must be a simple filename")
    events: list[dict[str, Any]] = []
    destructive_count = 0
    for action in plan["actions"]:
        if not isinstance(action, dict) or not isinstance(action.get("target"), str):
            raise VirtualExecutionError("Malformed action; discard plan and refresh inventory")
        if not action.get("destructive"):
            events.append({"target": action["target"], "result": "SKIPPED_NON_DESTRUCTIVE",
                           "reason": "Virtual simulation records but does not execute non-destructive actions"})
            continue
        target = action["target"]
        expected_identity = None
        for role in ("primary", "secondary"):
            device = plan.get(role)
            if isinstance(device, dict) and device.get("path") == target:
                expected_identity = device
                break
        if expected_identity is None:
            raise VirtualExecutionError("Action target is not bound to a selected device identity")
        if target not in virtual_targets or target not in approved_identities:
            raise VirtualExecutionError("Every destructive target requires an explicit virtual mapping and identity approval")
        if not _identity_matches(expected_identity, approved_identities[target]):
            raise VirtualExecutionError("Approved stable identity does not match the reviewed plan")
        image = _regular_virtual_target(root, str(virtual_targets[target]))
        events.append({
            "target": target,
            "virtual_file": image.name,
            "result": "SIMULATED_ONLY",
            "identity_verified": True,
            "image_bytes": image.stat().st_size,
            "operations_not_performed": ["partition", "format", "encrypt", "mount", "bootloader-write"],
        })
        destructive_count += 1

    if destructive_count == 0:
        raise VirtualExecutionError("No explicitly approved destructive target was available for simulation")
    record = {
        "schema_version": 1,
        "mode": "VIRTUAL_SIMULATION_ONLY",
        "execution_performed": False,
        "physical_devices_accessed": False,
        "plan_digest": plan["plan_digest"],
        "inventory_fingerprint": plan.get("inventory_fingerprint"),
        "events": events,
        "recovery": {
            "state": "NO_TARGET_MUTATION",
            "action": "Discard this journal and regenerate a plan if inventory changes",
        },
    }
    encoded = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(journal_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise VirtualExecutionError("Journal already exists; choose a new name to preserve evidence") from exc
    except OSError as exc:
        raise VirtualExecutionError("Could not safely write the journal; no target files were modified") from exc
    return record
