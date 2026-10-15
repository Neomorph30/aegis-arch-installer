# Layer 07 — Minimal Arch guest installation contract

**Status: preflight specification implemented; guest installation engine remains unimplemented.** The pure `lab.install_spec` module validates a guest observation and creates a tamper-detectable review spec. The read-only `lab.guest_probe` adapter collects lsblk, sysfs, and active-swap observations with fixed commands and bounded timeouts. The `python -m lab.guest_preflight` entry point prints a JSON review spec or a blocked recovery record. These modules do not run installation commands or modify disks.

The existing QEMU lab proves that QEMU, paired OVMF firmware, and a software TPM can start together. It does not prove that the Arch ISO boots or that an installed guest can boot. Layer 07 must close that gap using disposable virtual disks only.

## Required environment

- Launch from the unprivileged host-side lab. Never run the guest installer directly on the host.
- The host creates new sparse regular files inside a private temporary workspace and attaches only those files to QEMU.
- The guest has no host directory sharing, USB passthrough, host block-device paths, or bridged networking. Any future package-download networking must be a separate, explicit lab mode with bounded access and no inbound forwarding.
- The primary virtual disk must have a fixed lab-only serial marker and be independently re-identified inside the guest immediately before every destructive phase.
- The boot ISO and its integrity/provenance must be verified before use. Do not trust an arbitrary ISO simply because it boots.
- All target writes are confined to the guest's synthetic disk; no host-side loop, NBD, mount, partition, or format operations are permitted.

## Required transaction phases

1. **Preflight** — verify QEMU guest identity, expected virtual disk serial and capacity, no target mount/holder/swap state, and a separate read-only boot medium. Stop on any missing or contradictory observation.
2. **Plan review** — display the exact virtual target identity, partition layout, encryption intent and destructive steps. Require explicit confirmation within the guest. Do not accept a target path from free-form user input.
3. **Partition** — create GPT and EFI/root partitions using fixed, allowlisted operations. Record intent durably before each mutation. Never retry a destructive command automatically.
4. **Encryption and filesystem** — configure LUKS2 and Btrfs using secret input through a dedicated input channel, never command-line arguments or environment variables. Keep this layer independent from TPM enrollment.
5. **Base install** — install only a versioned, reviewed package set; verify package database and installed files rather than treating exit code zero as proof.
6. **Boot configuration** — generate initramfs and UEFI boot artifacts, record their hashes, and verify expected files and configuration before reboot.
7. **Guest reboot verification** — prove the guest actually boots from its installed virtual disk, unlocks encrypted root with the expected credential flow, reaches a usable system, and preserves recovery access.
8. **Report** — emit a truthful evidence record with PASSED, FAILED, UNVERIFIED, and SKIPPED states; never claim TPM/PIN, Secure Boot, recovery, or real-hardware support before those layers have separate evidence.

## Failure and recovery contract

- Classify failures as transient read-only probe, configuration, destructive-phase failure, boot failure, or integrity failure.
- Retry only bounded read-only transient probes. Never automatically repeat partitioning, formatting, encryption, package removal, or bootloader writes.
- On interruption, inspect the durable journal and re-probe target identity before deciding whether to resume. If the state is ambiguous, stop and preserve evidence.
- The safest initial recovery for the disposable lab is to preserve the journal, destroy only the ephemeral VM workspace after evidence capture, and create fresh virtual disks. Do not claim rollback if writes already occurred.
- Never place LUKS credentials, TPM PINs, recovery keys, or signing secrets in logs, reports, command arguments, environment variables, or CI artifacts.

## Acceptance gates

- Unit tests for plan validation, identity substitution, command allowlisting, secret redaction, and each failure phase.
- Disposable VM tests that actually boot the ISO, run the installer against only the synthetic primary disk, reboot from the installed disk, and prove the host workspace contains no unexpected files.
- Crash injection after each destructive step, followed by restart/recovery verification.
- Tests for missing network, mirror failure, corrupt ISO, insufficient disk, wrong serial, active swap/mount/holder, package failure, interrupted initramfs generation, and failed first boot.
- Independent review of guest isolation and the privileged boundary before enabling any destructive guest operation by default.

## Not in scope for this layer

TPM PIN enrollment and signed UKIs belong to Layer 09; secondary-drive management and offline recovery drills belong to Layer 08; graphics, gaming, VR, biometrics and optimization are later layers. A passing guest install does not qualify physical-device installation.
