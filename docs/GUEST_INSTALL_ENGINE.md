# Layer 07 — Minimal Arch guest installation contract

**Status: preflight specification implemented; guest installation engine remains unimplemented.** The pure `lab.install_spec` module validates a guest observation and creates a tamper-detectable review spec. The read-only `lab.guest_probe` adapter collects lsblk, sysfs, and active-swap observations with fixed commands and bounded timeouts. The `python -m lab.guest_preflight` entry point prints a JSON review spec or a blocked recovery record. `lab.iso_validation` verifies a local ISO's ISO9660 descriptor, Arch volume label and SHA-256 against a digest supplied independently; the VM launcher refuses `--iso` unless `--iso-sha256` is supplied. The read-only `lab.guest_probe` retries an `lsblk` timeout at most once; other probe failures stop immediately. The `lab.transaction_journal` module adds a private, append-only, hash-chained journal and a recovery assessment that refuses automatic phase retries and stops on ambiguous destructive state. Its hash chain detects changed or truncated records, but it is not a digital signature and cannot prove authenticity against an attacker who can rewrite the entire journal; independent signed checkpoints remain future work. These modules do not run installation commands or modify disks. `lab.workflow_plan` now builds a deterministic, review-only phase plan by validating the original spec digest and comparing it with a freshly validated observation. It blocks on changed serials, capacities, mount/swap/holder state, network mode, or phase order. Each phase records required gates, including a fresh read-only observation before every future mutation, explicit human confirmation, and durable journal intent. This is a planning contract only; the actual executor must implement and independently enforce those gates.

The existing QEMU lab proves that QEMU, paired OVMF firmware, and a software TPM can start together. It does not prove that the Arch ISO boots or that an installed guest can boot. Layer 07 must close that gap using disposable virtual disks only.

## Offline ISO verification

Verify a local ISO independently before starting the VM lab:

```bash
python -m lab.iso_validation --iso /path/to/archlinux-x86_64.iso --sha256 <trusted-64-character-sha256>
```

The command is read-only and emits JSON with either `VERIFIED_ARCH_ISO` or `BLOCKED`. Obtain the expected digest from an independently trusted official Arch Linux source; a digest copied from an untrusted mirror or message does not establish provenance. The lab repeats verification on the private copy before QEMU receives the image.

## Required environment

- Launch from the unprivileged host-side lab. Never run the guest installer directly on the host.
- The host creates new sparse regular files inside a private temporary workspace and attaches only those files to QEMU.
- The guest has no host directory sharing, USB passthrough, host block-device paths, or bridged networking. Any future package-download networking must be a separate, explicit lab mode with bounded access and no inbound forwarding.
- The primary virtual disk must have a fixed lab-only serial marker and be independently re-identified inside the guest immediately before every destructive phase.
- The boot ISO must be a regular, non-symlink file with an Arch-labelled ISO9660 primary volume descriptor, and its SHA-256 must match an independently trusted expected digest before QEMU receives it. A hash only proves equality with the expected digest; it does not establish provenance if the digest itself came from an untrusted source.
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
- On interruption, validate the hash-chained journal and re-probe target identity before any new decision. The initial journal implementation is a recording/recovery-policy primitive, not yet wired to an installer executor. If state is ambiguous, stop and preserve evidence.
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
## Review-only workflow-plan CLI

The plan builder can be run against a saved preflight spec and a separately captured fresh observation. Both inputs must be bounded, single-link regular JSON files; symlinks, devices, pipes, malformed JSON, oversized inputs, and changed target evidence are rejected. The command emits a review-only plan to stdout and never runs hardware probes or installation commands:

```bash
python -m lab.workflow_plan_cli --spec preflight-spec.json --observation fresh-observation.json
```

This CLI is a review aid, not authorization to mutate a disk. A future executor must obtain its own fresh observation immediately before each mutation and enforce operator confirmation and durable journal intent independently.
## Explicit outbound networking for package installation

The disposable VM remains network-isolated by default (`-nic none`). When a reviewed guest-install experiment needs package downloads, the host launcher supports an explicit QEMU user-mode NAT option:

```bash
python -m lab.runtime --run --iso /path/to/archlinux-x86_64.iso --iso-sha256 <trusted-sha256> --network-mode user-nat-explicit
```

Use the exact ISO checksum from the official Arch release page and verify the release signature where possible. User-mode NAT allows outbound guest traffic through QEMU's userspace network stack; AEGIS adds no host port-forwarding rules and does not enable bridged networking. This is an opt-in transport setting, not a network allowlist: the guest may reach destinations permitted by QEMU user networking and the host's network policy. Keep credentials and sensitive data out of the lab, and return to the default `disabled` mode when networking is not needed.

## Verified ISO boot-menu observation

For CI and development, the bounded smoke runner also supports a stronger, opt-in observation mode:

```bash
python -m lab --smoke --observe-boot --seconds 20 \
  --iso /path/to/archlinux-x86_64.iso \
  --iso-sha256 <trusted-sha256>
```

This mode requires Tesseract OCR, binds the QEMU VNC display to loopback, captures a screenshot through the local QMP socket, and looks for both `Arch Linux` and `install medium` in OCR text. It reports `guest_boot_verified=true` only when the expected boot-menu text is detected. The ordinary `--smoke` mode does not make that claim.

Boot-menu detection is a limited milestone, not proof that the kernel or live environment became usable, and not proof that an installation, encryption, recovery, KDE, drivers, or optimization work. The current CI run does not perform installation or mutate anything except disposable virtual-disk files in a private temporary workspace.

For the next validation step, `--observe-live --live-timeout-seconds 120` waits for an OCR match containing both `archiso` and `root`, consistent with the Arch live environment's root prompt. It is separate from `--observe-boot`; the two modes cannot be combined. The timeout is bounded to 30–240 seconds and no automatic installation starts after detection. This is still not proof of successful storage setup, package installation, reboot, or physical-system compatibility.
## Review-only per-phase gate

`lab.execution_gate.assess_phase_request` adds a fail-closed, non-executing gate for one requested phase. It validates the reviewed plan's fixed phase/gate contract, compares fresh synthetic-target observations against the plan digest, checks prior hash-chained journal events, refuses phase retries or unresolved/failed prior phases, and requires a target-bound exact confirmation phrase for mutating phases.

This is still **not an executor**. The function does not write journal records, execute commands, open disks, or authorize a future process cryptographically. A returned `GATE_PASSED_REVIEW_ONLY` means only that the request met these local review checks. A real executor must independently re-probe immediately before each mutation, persist durable intent before the operation, use a fixed command/argument allowlist without a shell, verify results, and stop on ambiguity. The current preview safety lint remains a guardrail, not a sandbox or proof of safety.

## Journaled guest review session

The read-only guest session now connects the guest probe, deterministic review plan, per-phase review gate, and transaction journal:

```bash
python -m lab.guest_review_session
```

Run only inside the Arch live environment as root. The command creates a private, unique session under `/run/aegis`, records preflight intent and outcome, re-probes target identity, and displays the proposed layout. It then requires the exact target-bound confirmation phrase before recording `explicit_target_review`. The command accepts no target path or journal path from arguments.

This session is deliberately incapable of partitioning, formatting, opening LUKS, mounting filesystems, installing packages, or writing boot configuration. Both successful phase results still report `execution_enabled=false` and `disk_changes_performed=false`. A failed or interrupted session must not be reused; preserve its journal and start a fresh live session after reviewing the failure. This is a safety integration milestone, not the installation engine.
