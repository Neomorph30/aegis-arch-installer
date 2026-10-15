# Layer 06 — Virtual-only execution boundary

## Scope

The new `aegis.virtual_executor.simulate_execution` module is a test boundary, not an installation executor. It does not call subprocesses and does not partition, format, encrypt, mount, or write boot assets. It validates a plan and records a simulation journal while leaving the synthetic image bytes unchanged.

## Required gates

- Verify the canonical plan digest before using any plan fields.
- Accept only `PROPOSAL_ONLY` plans with `execution_enabled=false`, no blockers, and an explicit review state.
- Require a separate virtual-image mapping and explicit stable-identity confirmation for each destructive target.
- Refuse missing stable serial/WWN identity, mismatched identity, symlinks, block devices, targets outside the private workspace, and non-private files.
- Require a private workspace (mode 0700 or stricter) and synthetic regular files (mode 0600 or stricter).
- Create a new journal exclusively; never overwrite an existing journal or follow a journal symlink.
- Record `execution_performed=false`, `physical_devices_accessed=false`, the plan digest, and that all mutating operations were not performed.

## Recovery

Any failed gate stops the simulation before journal creation. The message identifies a safe next action: regenerate the plan, recreate the private workspace, repair the virtual image mapping, or review the displayed device identity. An existing journal is preserved; choose a new filename rather than overwriting evidence.

## Explicit limitations

This layer does **not** provide a privileged service, does not grant consent for real devices, and does not enable physical-disk writes. Stable identity fields in synthetic fixtures are test data. A future guest installation engine must execute inside the disposable VM against virtual disks and must be tested separately for crash recovery, interrupted transactions, identity substitution, and guest-level verification. Physical-device execution remains disabled pending independent review and real-hardware qualification.
