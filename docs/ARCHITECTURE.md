# Architecture — AEGIS developer preview 0.2

AEGIS is designed as *separate* read-only and privileged boundaries:

1. **Discovery** collects observations, never requires root and executes only
   allowlisted `lsblk` and `lspci` probes with no shell.
2. **Planning** is pure Python. It proposes explicit byte-aligned partitions,
   identifies candidate devices and annotates blockers. It cannot write disks.
3. **Review and consent** (in the future) will require a human to inspect each
   affected device, its immutable identity, existing data and intended action.
4. **Executor** is **not implemented**. It will be developed separately in a
   disposable-VM-only branch and should have a narrow privileged API. It must
   not trust paths, stale inventories, arbitrary shell commands, UI state or
   signed policy claims without independent validation.
5. **Verification** must independently prove boot, TPM PIN, offline recovery,
   security controls, networking and installed packages.
6. **Reporting** emits event evidence. A successful command exit is not proof
   that a security control was verified.
7. **Optimization** will be profile-driven, benchmark-informed and reversible.

## Data flow

```text
Linux sysfs + allowlisted lsblk/lspci        Fixed test fixtures
                |                                 |
                +---------- inventory ----------+
                                |
                     immutable proposal logic
                                |
                  annotated storage/profile plans
                                |
                     JSON plan / HTML report
                                |
              [STOP: no installation execution exists]
```

Storage plan schema v0.2 includes: `schema_version`, `status=PROPOSAL_ONLY`,
`execution_enabled=false`, `review_state`, device identities, actions with
partition byte ranges (`offset_bytes` inclusive, `end_exclusive_bytes`),
`blockers`, `warnings`, and non-PASSED test states. Proposed partitions are
aligned to 1 MiB, with 4 GiB EFI and at least 16 MiB GPT headroom.

The reference system layout uses a separate unencrypted FAT32 EFI System
Partition, encrypted LUKS2 root, and Btrfs subvolumes, with ext4 as a proposed
alternative. The secondary disk is **preserved by default**. If the user chooses
an erase proposal for it, that action must receive independent confirmation in
any future installer. The root TPM 2.0 + PIN flow will require signed UKIs,
explicit TPM-policy verification and an offline LUKS2 recovery credential.

## Isolation and upgrade model

- No privileged functions reside in `aegis.cli`, `aegis.planner`,
  `aegis.hardware`, `aegis.profiles`, or `aegis.reporting`.
- User-supplied JSON can change a *proposal* but cannot trigger a write.
- File outputs use exclusive creation and mode 0600. Existing files are not
  silently overwritten.
- Human-facing HTML uses escaping, a restrictive CSP and redaction. Default
  shareable HTML hides serial and WWN fields; local JSON is NOT shareable.
- A future stateful executor must pin a validated policy and kernel artifacts,
  survive interrupted steps, and require explicit non-reusable authorization
  for each destructive drive change.
- Updates must preserve signed boot fallback and independently usable recovery
  credentials. Filesystem snapshots are not backups.

## Supported scope

The first production target will be x86-64 UEFI systems. TPM 2.0, firmware,
Wi-Fi, fingerprint readers, GPU drivers and VR headset support are separate
capabilities that require tests on real hardware before claiming compatibility.

## Engineering notes

The reported EFI Secure Boot variable is informational, not a cryptographic
proof of Secure Boot or platform trust. `lsblk` device names may be reassigned
across boots. We must not imply that the safety checks in the planner are
sufficient for actual disk writes: they are necessary preflight warnings, not
a substitute for stable device re-identification, installation-media exclusion,
conflicting partition detection, and consent in the eventual executor.


## Network preflight and Wi-Fi onboarding

The CLI `aegis network` makes bounded read-only HTTPS reachability attempts to
independent public hosts. Failure is labelled **unverified**, never definitive
"offline". AEGIS reads wireless interface hints from Linux sysfs; it does not
assume Wi-Fi from an interface name. The main menu performs this check on real
hardware, but explicitly skips it when demonstrating a fixture.

On an unverified connection with detected Wi-Fi and a supported management tool,
the user may authorize launching NetworkManager's `nmtui connect` or iwd's
`iwctl`. These tools handle credentials interactively; AEGIS does not receive,
log, or pass passwords on command lines. Setup requires a local TTY. The
application then rechecks connectivity. No service starts, firewall changes,
network profiles, or pacman mirrors are configured by AEGIS itself.

Later releases must validate selected package mirrors and configure a suitable
persistent networking manager in the installed system independently of the ISO.
Captive portals, proxies, enterprise Wi-Fi, IPv6-only and missing firmware are
not yet fully supported by the guided interface.

## Layer 02 host-side virtual laboratory

Source checkout module `lab/runtime.py` (separate from the `aegis` package)
creates private temporary files and drives an opt-in QEMU/OVMF/swtpm virtual
machine. It does **not** add a privileged installer/executor to AEGIS. Only
new sparse files are attached as guest disks; all files created by the lab
live inside its private workspace, and these limited claims are tested. Lab
smoke tests observe running QEMU state and registered TPM through a private
QMP Unix socket, not through guest-installed software. No guest networking
or host passthrough is configured. No physical host disk is knowingly attached.

See [VIRTUAL_LAB](VIRTUAL_LAB.md) for reproducible commands and remaining risks.


## Layer 06 virtual-only execution gate

`aegis.virtual_executor` is a simulation harness only. It validates proposal integrity, requires explicit virtual-file mapping and identity confirmation, rejects symlinks/block devices/non-private paths, and writes a new private journal. It does not call subprocesses or mutate virtual images. It cannot execute physical device operations. See [VIRTUAL_EXECUTION_BOUNDARY](VIRTUAL_EXECUTION_BOUNDARY.md).
