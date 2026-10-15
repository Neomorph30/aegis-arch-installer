# Layer 07 — disposable Arch guest installation design

**Status: specification only. No installation executor is implemented by this document.**
The existing AEGIS preview remains read-only. This design applies only to the two
new regular-file-backed virtual disks created by `python -m lab`; it must never
accept a host block device, partition, arbitrary QEMU argument, host path to a disk,
or a physical-disk authorization token.

## Objective

Prove a reproducible installation into the disposable primary VM disk, boot into
the installed guest, and collect evidence for each step. The secondary VM disk
remains read-only and is used for negative tests. A successful ISO boot or live
prompt is not an installation result.

## Preconditions (all fail closed)

1. Run as an unprivileged Linux user in the existing private, per-run workspace.
2. Verify the Arch ISO against a SHA-256 digest obtained independently from a
   trusted Arch distribution/checksum channel. Record the digest and source.
3. Verify QEMU, matching OVMF CODE/VARS, and swtpm availability; never silently
   switch firmware, accelerator, display, disk, or TPM settings.
4. Create both virtual disks exclusively as regular files under the workspace.
   Verify their canonical paths, device/inode identity, expected sizes, and lab-only
   serials. No host block-device paths or passthrough are accepted.
5. Keep guest networking disabled by default. Any future opt-in networking must be
   outbound user-mode NAT only, without inbound forwarding, and separately tested.
6. Verify sufficient free workspace capacity and record the initial virtual disk
   sizes and SHA-256 hashes of the ISO and relevant configuration artifacts.
7. If any identity, firmware, ISO, TPM, workspace, or safety check is ambiguous,
   stop before modifying either virtual disk.

## Required state machine

Each transition must be recorded durably in a versioned journal before the next
mutating operation. Journal records contain timestamps, state, operation ID,
input identities, exit status, verification result, and sanitized diagnostics;
they never contain passwords, PINs, LUKS keys, tokens, or recovery secrets.

- `PREFLIGHT`: validate dependencies, trusted ISO digest, workspace permissions,
  virtual-disk identities, and free space.
- `MEDIA_VERIFIED`: verify the copied ISO digest again immediately before launch.
- `LIVE_ENVIRONMENT_VERIFIED`: independently detect the Arch live environment;
  QMP running state alone is insufficient.
- `TARGET_REVALIDATED`: inside the guest, identify the primary by the exact
  `AEGIS-LAB-PRIMARY` marker and expected capacity; assert that the secondary
  `AEGIS-LAB-SECONDARY` is read-only. Require exactly the expected target set.
- `PLAN_APPROVED`: produce a machine-readable proposed partition/filesystem/mount
  plan and display it. For unattended CI, approval is an explicit test-only fixture
  token that cannot be used outside the disposable lab.
- `PARTITIONED`, `FILESYSTEMS_CREATED`, `BASE_INSTALLED`, `BOOT_CONFIGURED`:
  perform one bounded stage at a time. After each stage, independently inspect the
  resulting partition table/filesystems/mounts/packages/boot entries rather than
  trusting only command exit codes.
- `INSTALLED_SYSTEM_VERIFIED`: verify expected partitions, encrypted root
  mapping where applicable, installed base packages, kernel/initramfs, boot entry,
  and configuration. Do not claim TPM-bound unlock, Secure Boot, or recovery
  passed unless each is actually exercised.
- `REBOOT_REQUESTED`, `INSTALLED_GUEST_BOOT_VERIFIED`: reboot from the virtual
  disk with installation media detached or lower priority; verify the installed
  system using multiple independent signals, not a single OCR substring.
- `COMPLETE`: emit a final report and preserve only explicitly requested evidence.

## Interruption and recovery rules

- On timeout, signal, process exit, malformed QMP response, journal corruption,
  changed disk identity, unexpected mount, or failed postcondition: stop the
  current stage and terminate QEMU/swtpm with bounded graceful shutdown then kill.
- Never blindly repeat a destructive command. A retry is allowed only when the
  prior stage's postcondition proves the operation did not occur, the target
  identity is unchanged, and the retry count is bounded.
- On restart, treat an incomplete journal as untrusted input. Revalidate its schema,
  workspace ownership/mode, ISO digest, and both disk identities before offering
  recovery. If the current disk state does not match a known stage, mark the run
  `NEEDS_MANUAL_RECOVERY`; do not auto-format or resume.
- Preserve a failed disposable workspace only through an explicit developer
  diagnostic option, with strict permissions and a documented cleanup command.
  Default behavior must clean up temporary state without hiding the failure report.
- A recovery test must intentionally interrupt every mutating stage and prove that
  AEGIS either resumes from verified state or stops safely without repeating writes.

## Required test matrix

- Wrong or changed ISO digest; missing QEMU/OVMF/swtpm; mismatched firmware pair.
- Primary/secondary serial swap, duplicate/missing serial, wrong capacity, unexpected
  third disk, secondary writable, or any host-device path supplied as input.
- No TPM, QMP disconnect, emulator exits early, malformed journal, low disk space,
  timeout, SIGINT/SIGTERM, and abrupt guest power-off at every stage.
- Partition geometry and filesystem verification after each mutation.
- Successful boot from the installed virtual disk with the ISO no longer bootable.
- Repeated runs produce the same declared configuration and equivalent test results.
- Final report labels each check `PASSED`, `FAILED`, `WARNING`, `SKIPPED`, or
  `UNVERIFIED`, includes evidence and recovery instructions, and redacts all secrets.

## Release boundary

Layer 07 is not complete until the verified ISO reaches the live environment, the
installer is implemented and reviewed inside the disposable guest, the guest boots
from its virtual disk, and interruption/recovery tests pass in CI. Layer 02's QEMU
smoke test only proves emulator startup and TPM registration. OCR evidence alone is
not a security guarantee. No physical-disk installation, TPM key enrollment, Secure
Boot key changes, or host firewall changes are authorized by this specification.

Before enabling even this virtual-disk-only executor, complete the existing release
gates for privilege boundaries, independent review, expected partition-table
assertions, fault injection, and offline recovery. Physical installation remains a
separate future authorization and release gate.
