# Layer 07 — guest installation test plan

This is a test plan, not an implementation or permission to write physical disks.
It complements `LAYER_07_GUEST_INSTALLATION_DESIGN.md`.

## Test categories and acceptance

| Category | Required evidence | Failure behavior |
|---|---|---|
| ISO provenance | Expected SHA-256 sourced independently and copied-image digest matches | Refuse launch |
| Workspace | Private owner-controlled directory; exclusive regular-file images | Refuse launch and clean up |
| Target identity | Primary serial + expected size; secondary serial + read-only status; no other targets | Stop before partitioning |
| Firmware / TPM | Matching OVMF pair; QMP confirms running state and TPM registration | Refuse launch |
| Live media | Live environment verified beyond QMP status | Mark boot unverified |
| Partitioning | Exact expected partition table independently reread | Stop; never blindly repeat |
| Encryption | LUKS metadata and mapping verified without exporting secret material | Stop; do not claim recovery tested |
| Base system | Package and filesystem postconditions independently checked | Mark stage failed |
| Boot | Kernel/initramfs and boot entry inspected; installed virtual disk boots with ISO detached | Installation not complete |
| Fault injection | Interrupt each mutating stage; no unintended repeat; cleanup and report verified | Release blocker |
| Reporting | Versioned JSON + readable HTML; evidence, warnings, recovery steps; secret redaction | Release blocker |

## Negative tests

1. Replace the primary image with a symlink, device path, wrong inode, or wrong size.
2. Swap primary and secondary identities or make the secondary writable.
3. Add a third block device or provide any host block-device path.
4. Modify the ISO after digest acquisition or provide a mismatching digest.
5. Remove/replace firmware or TPM dependencies between preflight and launch.
6. Simulate QMP disconnect, malformed replies, unexpected QEMU exit, timeout, and
   termination signals at each state transition.
7. Exhaust available space before and during a bounded stage.
8. Corrupt or truncate the journal; change disk identity between stages.
9. Interrupt immediately before and after every mutation, then verify that restart
   refuses unsafe replay and never assumes a command failed merely because its
   completion record is missing.
10. Supply strings containing commas, newlines, option prefixes, and shell metacharacters
    in all accepted user-controlled paths/fields; assert no extra QEMU arguments
    or shell execution are possible.

## Evidence and reporting

Every run records a unique run ID, AEGIS commit, OS/runtime versions, emulator and
firmware identities, ISO digest/source, virtual disk serials/capacities, stage
transitions, verification method/results, sanitized stderr excerpts, and cleanup
outcome. Do not record credentials, LUKS key material, TPM PINs, tokens, or full
secret-bearing command lines. Public reports redact stable host identifiers.

The test harness must use synthetic images and a disposable VM only. CI evidence
must distinguish unit-test mocks, successful emulator startup, detected live media,
and a successfully booted installed guest. These are different assurance levels.
