"""Tamper-evident, secret-free transaction journal for the future guest executor.

This module records phase intent and outcomes only. It does not execute installation
commands, resume phases, or roll back destructive operations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any


class JournalError(RuntimeError):
    """Journal integrity or safe-write preconditions failed."""


PHASES = {
    "preflight",
    "explicit_target_review",
    "partition_gpt",
    "format_efi",
    "luks2_format_root",
    "open_encrypted_root",
    "format_btrfs",
    "mount_target",
    "pacstrap_base",
    "configure_initramfs_and_boot",
    "verify_installed_guest",
}
DESTRUCTIVE_PHASES = {
    "partition_gpt", "format_efi", "luks2_format_root", "format_btrfs",
    "mount_target", "pacstrap_base", "configure_initramfs_and_boot",
}
EVENT_TYPES = {"phase_intent", "phase_result", "recovery_decision"}
NOTE_CODES = {
    "none", "probe_timeout", "invalid_target", "command_nonzero",
    "process_interrupted", "verification_failed", "state_ambiguous",
    "operator_requested_stop", "fresh_lab_required", "journal_integrity_failure",
}
RECOVERY_STATUSES = {
    "STOP_AND_PRESERVE_EVIDENCE",
    "RESTART_READ_ONLY_PREFLIGHT",
    "RECREATE_EPHEMERAL_VM_AFTER_EVIDENCE_CAPTURE",
}
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 4096
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EVENT_KEYS = {
    "sequence", "timestamp", "event_type", "phase", "status",
    "note_code", "exit_code", "previous_hash", "event_hash",
}


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _event_hash(record: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "event_hash"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _validate_event(event: dict[str, Any], sequence: int, previous_hash: str) -> None:
    if set(event) != EVENT_KEYS:
        raise JournalError("Journal record schema mismatch; preserve the journal for review")
    actual_sequence = event.get("sequence")
    if isinstance(actual_sequence, bool) or not isinstance(actual_sequence, int) or actual_sequence != sequence:
        raise JournalError("Journal sequence mismatch; do not resume")
    recorded_previous = event.get("previous_hash")
    if not isinstance(recorded_previous, str) or not HASH_PATTERN.fullmatch(recorded_previous) or recorded_previous != previous_hash:
        raise JournalError("Journal hash chain mismatch; do not resume")
    if not isinstance(event.get("timestamp"), str) or len(event["timestamp"]) > 40:
        raise JournalError("Journal timestamp is malformed")
    try:
        datetime.fromisoformat(event["timestamp"])
    except ValueError as exc:
        raise JournalError("Journal timestamp is malformed") from exc
    if not isinstance(event.get("event_hash"), str) or not HASH_PATTERN.fullmatch(event["event_hash"]):
        raise JournalError("Journal event hash is malformed")
    if event.get("event_type") not in EVENT_TYPES:
        raise JournalError("Journal event type is not allowlisted")
    if event.get("note_code") not in NOTE_CODES:
        raise JournalError("Journal note code is not allowlisted")
    exit_code = event.get("exit_code")
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255):
        raise JournalError("Journal exit code is malformed")
    kind, phase, status = event["event_type"], event["phase"], event["status"]
    if kind in ("phase_intent", "phase_result"):
        if phase not in PHASES:
            raise JournalError("Journal phase is not allowlisted")
        if kind == "phase_intent" and status != "STARTED":
            raise JournalError("Phase intent must use STARTED status")
        if kind == "phase_result" and status not in {"SUCCEEDED", "FAILED", "UNCERTAIN"}:
            raise JournalError("Phase result status is invalid")
    else:
        if phase is not None or status not in RECOVERY_STATUSES:
            raise JournalError("Recovery decision is malformed")
    if not hmac.compare_digest(event["event_hash"], _event_hash(event)):
        raise JournalError("Journal record hash mismatch; preserve evidence")


def parse_journal(raw: bytes) -> list[dict[str, Any]]:
    if not raw:
        return []
    if len(raw) > MAX_JOURNAL_BYTES:
        raise JournalError("Journal exceeds the supported evidence size; preserve it for offline review")
    if not raw.endswith(b"\n"):
        raise JournalError("Journal ends with an incomplete record; preserve evidence")
    if any(len(line) > MAX_RECORD_BYTES for line in raw.splitlines()):
        raise JournalError("Journal record exceeds the supported size; preserve evidence")
    events: list[dict[str, Any]] = []
    previous = "0" * 64
    for index, line in enumerate(raw.splitlines()):
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise JournalError("Journal contains invalid JSON; preserve evidence") from exc
        if not isinstance(event, dict):
            raise JournalError("Journal record is not an object")
        _validate_event(event, index + 1, previous)
        _validate_transition(events, event)
        events.append(event)
        previous = event["event_hash"]
    return events


def _validate_transition(events: list[dict[str, Any]], event: dict[str, Any]) -> None:
    kind, phase, status = event["event_type"], event["phase"], event["status"]
    intents = [e for e in events if e["event_type"] == "phase_intent" and e["phase"] == phase]
    results = [e for e in events if e["event_type"] == "phase_result" and e["phase"] == phase]
    if kind == "phase_intent":
        if intents:
            raise JournalError("Automatic phase retries are forbidden; create a new reviewed lab")
        unresolved = [e["phase"] for e in events if e["event_type"] == "phase_intent"
                      and not any(r["event_type"] == "phase_result" and r["phase"] == e["phase"] for r in events)]
        if unresolved:
            raise JournalError("A previous phase has no result; stop and preserve evidence")
    elif kind == "phase_result":
        if len(intents) != 1 or results:
            raise JournalError("Phase result has no unique unmatched intent")
    elif kind == "recovery_decision":
        unresolved = [e["phase"] for e in events if e["event_type"] == "phase_intent"
                      and not any(r["event_type"] == "phase_result" and r["phase"] == e["phase"] for r in events)]
        if unresolved and status != "STOP_AND_PRESERVE_EVIDENCE":
            raise JournalError("Ambiguous phase state can only stop and preserve evidence")


def assess_recovery(events: list[dict[str, Any]]) -> dict[str, str]:
    """Recommend a safe next action; never resumes or executes recovery itself."""
    if not events:
        return {"action": "RESTART_READ_ONLY_PREFLIGHT", "reason": "no_phase_started"}
    intents = {e["phase"] for e in events if e["event_type"] == "phase_intent"}
    results = {e["phase"]: e for e in events if e["event_type"] == "phase_result"}
    unresolved = sorted(phase for phase in intents if phase not in results)
    if unresolved:
        return {"action": "STOP_AND_PRESERVE_EVIDENCE", "reason": "phase_outcome_unknown"}
    failed = [phase for phase, event in results.items() if event["status"] in {"FAILED", "UNCERTAIN"}]
    if any(phase in DESTRUCTIVE_PHASES for phase in failed):
        return {"action": "STOP_AND_PRESERVE_EVIDENCE", "reason": "destructive_phase_failed"}
    if failed:
        return {"action": "RESTART_READ_ONLY_PREFLIGHT", "reason": "non_destructive_phase_failed"}
    return {"action": "REVIEW_BEFORE_NEXT_PHASE", "reason": "completed_phases_require_verification"}


class TransactionJournal:
    """Append-only hash-chained journal in a private, caller-owned lab directory."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _check_parent(self) -> None:
        parent = self.path.parent
        try:
            info = parent.lstat()
        except OSError as exc:
            raise JournalError("Journal directory must already exist") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise JournalError("Journal directory must be a private non-symlink directory")

    def append(
        self,
        event_type: str,
        *,
        phase: str | None = None,
        status: str,
        note_code: str = "none",
        exit_code: int | None = None,
    ) -> dict[str, Any]:
        self._check_parent()
        if event_type not in EVENT_TYPES or note_code not in NOTE_CODES:
            raise JournalError("Event type or note code is not allowlisted")
        if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255):
            raise JournalError("Exit code is invalid")
        # Validate caller intent before opening the journal.
        probe = {
            "sequence": 1, "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type, "phase": phase, "status": status,
            "note_code": note_code, "exit_code": exit_code,
            "previous_hash": "0" * 64, "event_hash": "",
        }
        # Hash is filled after schema/transition validation.
        unsigned = dict(probe)
        unsigned.pop("event_hash")
        probe["event_hash"] = hashlib.sha256(_canonical(unsigned)).hexdigest()
        _validate_event(probe, 1, "0" * 64)

        flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags)
        except FileNotFoundError:
            try:
                fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                fd = os.open(self.path, flags)
        except OSError as exc:
            raise JournalError("Cannot safely open journal; preserve existing evidence") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
                raise JournalError("Journal must be a private single-link regular file")
            os.lseek(fd, 0, os.SEEK_SET)
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            events = parse_journal(b"".join(chunks))
            _validate_transition(events, probe)
            previous = events[-1]["event_hash"] if events else "0" * 64
            event = dict(probe)
            event["sequence"] = len(events) + 1
            event["previous_hash"] = previous
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
            event["event_hash"] = _event_hash(event)
            _validate_event(event, len(events) + 1, previous)
            line = _canonical(event) + b"\n"
            written = 0
            while written < len(line):
                written += os.write(fd, line[written:])
            os.fsync(fd)
            return event
        except OSError as exc:
            raise JournalError("Journal append failed; inspect and preserve the journal before any recovery") from exc
        finally:
            os.close(fd)

    def read(self) -> list[dict[str, Any]]:
        self._check_parent()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise JournalError("Cannot safely read journal") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
                raise JournalError("Journal must be a private single-link regular file")
            raw = bytearray()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                raw.extend(chunk)
            return parse_journal(bytes(raw))
        except OSError as exc:
            raise JournalError("Journal read failed; preserve evidence") from exc
        finally:
            os.close(fd)
