"""Explicit retry and recovery policy for AEGIS operations."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class RecoveryDecision:
    action: str
    reason: str
    attempts_allowed: int = 0

def classify_failure(operation: str, error_kind: str, attempt: int = 1) -> RecoveryDecision:
    """Fail closed; only bounded retries for explicitly read-only transient probes."""
    op = operation.strip().lower()
    err = error_kind.strip().lower()
    if op in {"partition", "format", "encrypt", "erase", "write", "mount-write", "bootloader-write"}:
        return RecoveryDecision("stop_and_inspect", "Mutating operations are never automatically retried.", 0)
    if op in {"inventory", "network-check", "read-only-probe"} and err in {"timeout", "temporary-unavailable", "interrupted"}:
        if attempt <= 1:
            return RecoveryDecision("retry_once", "Read-only transient failure; bounded retry is allowed.", 1)
        return RecoveryDecision("stop_and_report", "Read-only retry budget exhausted.", 0)
    if err in {"permission-denied", "invalid-input", "identity-mismatch", "device-busy", "unknown"}:
        return RecoveryDecision("stop_and_report", "Failure is not safely recoverable automatically.", 0)
    return RecoveryDecision("stop_and_report", "No safe recovery policy matches this failure.", 0)
