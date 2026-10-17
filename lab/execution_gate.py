"""Review-only gate for a single future guest-install phase.

This module never executes commands or writes the journal. A passed gate is evidence
that the request met the local review contract, not permission for a real executor.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .install_spec import InstallSpecError, build_guest_install_spec
from .transaction_journal import JournalError, parse_journal
from .workflow_plan import REQUIRED_GATES

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
PHASE_ORDER = tuple(REQUIRED_GATES)
MUTATING_PHASES = frozenset(
    phase for phase, gates in REQUIRED_GATES.items() if "journal_intent" in gates
)


class PhaseGateError(ValueError):
    """A phase request is stale, out of order, or missing a required gate."""


def confirmation_phrase(target: dict[str, Any]) -> str:
    """Return an exact target-bound phrase; never accept a generic yes."""
    if not isinstance(target, dict):
        raise PhaseGateError("Plan target is malformed")
    if target.get("path") != "/dev/vda" or target.get("serial") != "AEGIS-LAB-PRIMARY":
        raise PhaseGateError("Plan target does not match the fixed disposable lab identity")
    size = target.get("size_bytes")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise PhaseGateError("Plan target capacity is malformed")
    gib = size / (1024 ** 3)
    size_label = str(int(gib)) if gib.is_integer() else f"{gib:.3f}".rstrip("0").rstrip(".")
    return f"CONFIRM AEGIS-LAB-PRIMARY {size_label} GiB"


def _validated_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(events, list):
        raise PhaseGateError("Journal evidence must be a parsed event list")
    if not events:
        return []
    try:
        raw = b"".join(
            (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            for event in events
        )
        return parse_journal(raw)
    except (JournalError, TypeError, ValueError) as exc:
        raise PhaseGateError("Journal evidence is invalid; preserve it and stop") from exc


def assess_phase_request(
    plan: dict[str, Any],
    fresh_observation: dict[str, Any],
    phase_id: str,
    operator_confirmation: str | None,
    journal_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return a fail-closed, non-executing assessment for exactly one phase."""
    try:
        if not isinstance(plan, dict):
            raise PhaseGateError("Review plan must be an object")
        if (plan.get("status") != "TARGET_RECONFIRMED_REVIEW_PLAN"
                or plan.get("execution_enabled") is not False
                or plan.get("disk_changes_performed") is not False):
            raise PhaseGateError("Only a non-executing review plan is accepted")
        digest = plan.get("spec_digest")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise PhaseGateError("Review plan digest is missing or malformed")
        phases = plan.get("phases")
        if (not isinstance(phases, list)
                or any(not isinstance(item, dict) for item in phases)
                or [item.get("id") for item in phases] != list(PHASE_ORDER)):
            raise PhaseGateError("Review plan phases are malformed, missing, unknown, or out of order")
        for item in phases:
            phase_name = item["id"]
            if (item.get("mutating") is not (phase_name in MUTATING_PHASES)
                    or item.get("execution_enabled") is not False
                    or item.get("required_gates") != list(REQUIRED_GATES[phase_name])):
                raise PhaseGateError("Review plan phase contract was altered")
        if phase_id not in PHASE_ORDER:
            raise PhaseGateError("Requested phase is not allowlisted")
        try:
            fresh_spec = build_guest_install_spec(fresh_observation)
        except (InstallSpecError, TypeError, ValueError) as exc:
            raise PhaseGateError("Fresh target observation failed safety checks") from exc
        if fresh_spec.get("spec_digest") != digest:
            raise PhaseGateError("Fresh target evidence differs from the reviewed plan")
        target = plan.get("target")
        if target != fresh_spec.get("target"):
            raise PhaseGateError("Reviewed target identity does not match fresh observation")

        events = _validated_events(journal_events)
        intents = {event["phase"] for event in events if event["event_type"] == "phase_intent"}
        results = {
            event["phase"]: event
            for event in events if event["event_type"] == "phase_result"
        }
        unresolved = intents - set(results)
        if unresolved:
            raise PhaseGateError("A prior phase has unresolved state; preserve evidence")
        failed = [phase for phase, event in results.items() if event["status"] != "SUCCEEDED"]
        if failed:
            raise PhaseGateError("A prior phase failed or is uncertain; do not continue")
        if phase_id in intents:
            raise PhaseGateError("Phase already has journal history; automatic retries are forbidden")
        index = PHASE_ORDER.index(phase_id)
        for prior in PHASE_ORDER[:index]:
            if results.get(prior, {}).get("status") != "SUCCEEDED":
                raise PhaseGateError(f"Required earlier phase {prior} has not been verified successful")
        if "human_confirmation" in REQUIRED_GATES[phase_id]:
            required_phrase = confirmation_phrase(target)
            if not isinstance(operator_confirmation, str) or operator_confirmation != required_phrase:
                raise PhaseGateError("Exact target-bound operator confirmation is required")
        selected = next(item for item in phases if item["id"] == phase_id)
        return {
            "schema_version": 1,
            "status": "GATE_PASSED_REVIEW_ONLY",
            "phase": phase_id,
            "target": target,
            "execution_enabled": False,
            "commands_executed": False,
            "journal_written": False,
            "disk_changes_performed": False,
            "required_gates": list(selected["required_gates"]),
            "next_requirement": (
                "A future executor must independently re-probe target identity, persist journal intent, "
                "and enforce the operation allowlist immediately before any mutation."
            ),
            "limitations": [
                "This is a review gate only; it does not authorize or perform installation.",
                "A successful assessment is not a cryptographic capability or durable authorization token.",
            ],
        }
    except PhaseGateError as exc:
        return {
            "schema_version": 1,
            "status": "BLOCKED",
            "phase": phase_id if isinstance(phase_id, str) else None,
            "execution_enabled": False,
            "commands_executed": False,
            "journal_written": False,
            "disk_changes_performed": False,
            "error": str(exc),
            "recovery": "Preserve evidence, stop, and repeat read-only preflight and plan review.",
        }
