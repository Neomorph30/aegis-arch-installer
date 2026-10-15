# Layer 03 — Hardware inventory and recovery

Status: initial implementation; advisory only.

- Inventory analysis accepts structured observations and does not call system commands.
- Malformed data, duplicate paths/identifiers, nested mappings, active swap and mounted devices are flagged conservatively.
- All output sets `write_authorized: false`. A future executor must independently re-probe stable identity immediately before an operation.
- Read-only transient probes may receive one retry. Formatting, partitioning, encryption, erasure and boot writes are never retried automatically.
- This is not a hardware support certification or a substitute for real-hardware testing.

## Recovery contract

Every operation should report its operation ID, stage, sanitized error class, attempts, recovery action and verification result. Secrets and raw credentials must never enter logs. If recovery cannot be verified, stop and provide a manual next step.
