# Layer 05 — Storage proposal integrity

Storage plans are review documents, not executable instructions.

- The planner rejects malformed disk entries, duplicate paths and duplicate serial/WWN values anywhere in the discovered disk list. Ambiguous inventory must be refreshed rather than guessed around.
- Plans use schema version 0.3 and include an inventory fingerprint plus a SHA-256 digest over the canonical plan representation.
- `verify_storage_plan_integrity` detects plan edits. A digest is not a signature, not user consent, and not proof that the hardware has remained unchanged.
- A future executor must obtain explicit authorization separately, re-probe and match stable device identity immediately before each operation, verify current mounts/holders/swap, and reject stale inventory or plan fingerprints.
- The secondary disk remains preserved by default. Any erase layout is still proposal-only.
- No physical-disk writer is enabled by this layer.

## Recovery behaviour

If inventory validation or canonical serialization fails, plan creation stops with a clear `PlanError`. The caller should refresh read-only inventory and ask the user to review a newly generated plan. Do not auto-retry or execute a partially generated plan.
