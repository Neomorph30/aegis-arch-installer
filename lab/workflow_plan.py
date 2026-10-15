"""Non-executing Layer 07 workflow plan with fresh target identity revalidation.

This module plans and gates future work only. It never invokes commands, opens devices,
writes a journal, or enables installation execution.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .install_spec import (
    InstallSpecError,
    build_guest_install_spec,
    verify_guest_install_spec,
)


class WorkflowPlanError(ValueError):
    """A review plan is stale, malformed, or unsafe to proceed with."""


REQUIRED_GATES = {
    "preflight": ["fresh_read_only_observation"],
    "explicit_target_review": ["fresh_read_only_observation", "human_confirmation"],
    "partition_gpt": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "format_efi": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "luks2_format_root": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "open_encrypted_root": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "format_btrfs": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "mount_target": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "pacstrap_base": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "configure_initramfs_and_boot": ["fresh_read_only_observation", "human_confirmation", "journal_intent"],
    "verify_installed_guest": ["fresh_read_only_observation"],
}


def build_review_plan(spec: dict[str, Any], fresh_observation: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic review-only plan if the original spec is still current.

    Exact spec digest equality is intentionally conservative: any change in observed
    hardware, target state, network mode, or generated layout blocks this plan.
    """
    if not verify_guest_install_spec(spec):
        raise WorkflowPlanError("Original preflight spec digest is invalid; rerun read-only preflight")
    if spec.get("status") != "PREFLIGHT_ONLY" or spec.get("execution_enabled") is not False:
        raise WorkflowPlanError("Only a review-only preflight spec is accepted")
    phases = spec.get("phases")
    if not isinstance(phases, list) or not phases:
        raise WorkflowPlanError("Preflight phase plan is missing")
    phase_ids = [phase.get("id") for phase in phases if isinstance(phase, dict)]
    if len(phase_ids) != len(phases) or phase_ids != list(REQUIRED_GATES):
        raise WorkflowPlanError("Preflight phases are unknown, missing, or out of order")
    try:
        fresh_spec = build_guest_install_spec(fresh_observation)
    except (InstallSpecError, TypeError, ValueError) as exc:
        raise WorkflowPlanError("Fresh target observation failed safety checks; stop and rediscover") from exc
    if fresh_spec.get("spec_digest") != spec.get("spec_digest"):
        raise WorkflowPlanError("Target or environment changed since preflight; discard plan and review a new spec")

    planned_phases = []
    for phase in phases:
        phase_id = phase["id"]
        planned_phases.append({
            "id": phase_id,
            "mutating": phase["mutating"],
            "retry": phase["retry"],
            "required_gates": list(REQUIRED_GATES[phase_id]),
            "execution_enabled": False,
        })

    return {
        "schema_version": 1,
        "status": "TARGET_RECONFIRMED_REVIEW_PLAN",
        "execution_enabled": False,
        "disk_changes_performed": False,
        "spec_digest": spec["spec_digest"],
        "target": deepcopy(spec["target"]),
        "secondary_policy": "PRESERVE",
        "phases": planned_phases,
        "required_operator_action": (
            "Review the exact target identity and layout. This plan does not authorize "
            "execution; a future executor must independently re-probe before each mutation."
        ),
        "limitations": [
            "Planning only: no commands, journal writes, device opens, or disk changes.",
            "Fresh identity comparison is not a substitute for per-phase executor-side checks.",
            "No physical-hardware support or installation success is implied.",
        ],
    }
