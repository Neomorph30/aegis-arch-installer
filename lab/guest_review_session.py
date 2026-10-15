"""Journaled review-only guest session; no disk mutation phase is executable."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Callable

from .execution_gate import assess_phase_request, confirmation_phrase
from .guest_probe import GuestProbeError, observe_guest
from .install_spec import InstallSpecError, build_guest_install_spec
from .transaction_journal import JournalError, TransactionJournal
from .workflow_plan import WorkflowPlanError, build_review_plan


def _blocked(message: str, journal: Path | None = None) -> dict[str, Any]:
    result = {
        "schema_version": 1, "status": "BLOCKED", "execution_enabled": False,
        "commands_executed": False, "disk_changes_performed": False,
        "error": message,
        "recovery": "Stop, preserve the session journal, and repeat read-only preflight in a fresh live session.",
    }
    if journal is not None:
        result["journal_path"] = str(journal)
    return result


def run_review_session(
    journal: TransactionJournal,
    *,
    probe: Callable[[], dict[str, Any]] = observe_guest,
    confirm: Callable[[dict[str, Any], str], str | None],
) -> dict[str, Any]:
    """Record preflight and exact target review; never execute install commands."""
    if os.path.lexists(journal.path):
        return _blocked("A journal already exists; do not reuse a review session", journal.path)
    try:
        journal.append("phase_intent", phase="preflight", status="STARTED")
        try:
            observed = probe()
            spec = build_guest_install_spec(observed)
            plan = build_review_plan(spec, observed)
            gate = assess_phase_request(plan, observed, "preflight", None, [])
            if gate.get("status") != "GATE_PASSED_REVIEW_ONLY":
                raise WorkflowPlanError("Preflight review gate blocked")
            fresh = build_guest_install_spec(probe())
            if fresh.get("spec_digest") != spec.get("spec_digest"):
                raise WorkflowPlanError("Target evidence changed during preflight")
        except (GuestProbeError, InstallSpecError, WorkflowPlanError, TypeError, ValueError) as exc:
            note = "probe_timeout" if "timeout" in str(exc).casefold() else "invalid_target"
            journal.append("phase_result", phase="preflight", status="FAILED", note_code=note)
            return _blocked(f"Read-only preflight failed: {exc}", journal.path)
        journal.append("phase_result", phase="preflight", status="SUCCEEDED")

        phrase = confirmation_phrase(plan["target"])
        try:
            supplied = confirm(plan, phrase)
        except (EOFError, OSError):
            supplied = None
        if supplied != phrase:
            journal.append("recovery_decision", status="STOP_AND_PRESERVE_EVIDENCE",
                           note_code="operator_requested_stop")
            return _blocked("Exact target-bound confirmation was not supplied; no target review or disk changes occurred", journal.path)

        events = journal.read()
        try:
            fresh_for_gate = probe()
            gate = assess_phase_request(plan, fresh_for_gate, "explicit_target_review", supplied, events)
        except (GuestProbeError, InstallSpecError, WorkflowPlanError, TypeError, ValueError) as exc:
            journal.append("recovery_decision", status="STOP_AND_PRESERVE_EVIDENCE",
                           note_code="invalid_target")
            return _blocked(f"Fresh target observation failed after confirmation: {exc}", journal.path)
        if gate.get("status") != "GATE_PASSED_REVIEW_ONLY":
            journal.append("recovery_decision", status="STOP_AND_PRESERVE_EVIDENCE",
                           note_code="invalid_target")
            return _blocked("Fresh target review gate blocked; preserve the journal", journal.path)

        journal.append("phase_intent", phase="explicit_target_review", status="STARTED")
        try:
            latest = build_guest_install_spec(probe())
            if latest.get("spec_digest") != spec.get("spec_digest"):
                raise WorkflowPlanError("Target evidence changed immediately before review completion")
        except (GuestProbeError, InstallSpecError, WorkflowPlanError, TypeError, ValueError) as exc:
            journal.append("phase_result", phase="explicit_target_review", status="FAILED",
                           note_code="invalid_target")
            return _blocked(f"Target changed during explicit review: {exc}", journal.path)

        journal.append("phase_result", phase="explicit_target_review", status="SUCCEEDED")
        return {
            "schema_version": 1, "status": "REVIEW_ONLY_COMPLETE",
            "execution_enabled": False, "commands_executed": False,
            "journal_written": True, "disk_changes_performed": False,
            "target": plan["target"], "layout": spec["layout"],
            "completed_phases": ["preflight", "explicit_target_review"],
            "journal_path": str(journal.path),
            "next_requirement": "Independent executor review and failure-injection tests before any mutation phase can be enabled.",
            "limitations": [
                "No partitioning, formatting, encryption, mounting, package installation, or boot configuration was performed.",
                "The journal and phase gate are evidence controls, not a cryptographic authorization capability.",
            ],
        }
    except JournalError as exc:
        return _blocked(f"Journal integrity or write precondition failed: {exc}", journal.path)


def _new_journal() -> TransactionJournal:
    base = Path("/run/aegis")
    try:
        info = base.lstat()
    except FileNotFoundError:
        base.mkdir(mode=0o700)
        info = base.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise JournalError("Review directory must be a real directory")
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise JournalError("Review directory must be root-owned and private")
    session = Path(tempfile.mkdtemp(prefix="review-", dir=base))
    os.chmod(session, 0o700)
    return TransactionJournal(session / "transaction.jsonl")


def main(argv: list[str] | None = None) -> int:
    if argv not in (None, []):
        print(json.dumps(_blocked("This review-only command accepts no arguments"), indent=2))
        return 2
    if os.name != "posix" or os.geteuid() != 0:
        print(json.dumps(_blocked("Run from the Arch live environment as root"), indent=2))
        return 2
    try:
        journal = _new_journal()
    except (OSError, JournalError) as exc:
        print(json.dumps(_blocked(f"Cannot create a private review session: {exc}"), indent=2))
        return 2

    def ask(plan: dict[str, Any], phrase: str) -> str | None:
        print("Review-only plan; installation commands are disabled:", file=sys.stderr)
        print(json.dumps(plan, indent=2, sort_keys=True), file=sys.stderr)
        print(f"Type exactly to confirm this disposable target: {phrase}", file=sys.stderr)
        try:
            return input("AEGIS target confirmation> ")
        except EOFError:
            return None

    result = run_review_session(journal, confirm=ask)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "REVIEW_ONLY_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
