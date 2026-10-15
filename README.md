# AEGIS — Secure Arch Linux Installer

**Developer preview 0.2 (pre-alpha): no disk writes. It cannot install Arch, wipe disks,
enroll TPM keys, change Secure Boot, configure a firewall, or apply optimizations.**

AEGIS aims to make a secure Arch Linux installation understandable, auditable and
recoverable, with optional gaming and VR support. The initial phase provides a
cross-hardware planning engine and a safe terminal experience before a separately
reviewed and tested installation executor is ever introduced.

## What works today

- Inspects CPU, RAM, UEFI presence, kernel-advertised TPM version, reported Secure
  Boot variable, GPU vendor hints and complete block-device tree (read-only).
- Presents an interactive terminal storage wizard with Btrfs or ext4, a proposed
  GPT + 4 GiB EFI + LUKS2 root, and explicit secondary-drive policies.
- Computes byte-aligned, **illustrative** partition offsets; does not apply them.
- Flags mounted devices, installation USBs, missing disk identity, readonly disks,
  duplicate disk identity, unsuitable capacity, unsupported architectures and
  UEFI prerequisites.
- Runs a read-only HTTPS internet preflight; if connectivity is unverified, offers
  to open the existing interactive Wi-Fi tool with explicit consent. No passwords
  are received or stored by AEGIS. Network settings can change only if the user
  chooses to launch that tool.
- Builds advisory workstation/gaming package profiles without installing packages
  or assuming a detected GPU has compatible drivers. KDE Plasma is the initial
  default desktop candidate; unqualified alternatives are rejected, and all
  package lists remain recommendations rather than executed install commands. The profile CLI accepts explicit desktop identifiers, but GNOME, Xfce and custom desktops fail closed until qualified.
- Produces 0600 JSON proposals and sanitized HTML planning reports that never
  claim a real security operation passed.
- Provides a **fictional hardware fixture** so the CLI and wizard can be tested
  without querying the user's machine at all.
- Runs a standard-library-only Python test suite, plus GitHub Actions CI.

## Security assurance baseline (Layer 01)

`aegis assurance --json` prints a machine-readable declaration of which
capabilities are only previews or not implemented; it is **not a security scan**.
`python tools/security_lint.py` provides a fail-closed regression check against
privileged process execution in the preview, but does not replace security review.
See [requirements](docs/SECURITY_REQUIREMENTS.json),
[threat model](docs/THREAT_MODEL.md),
[risk register](docs/RISK_REGISTER.md),
[support matrix](docs/SUPPORT_MATRIX.md), and
[quality standards](docs/QUALITY_STANDARDS.md).

## Quick start

Requires Python 3.11+ on Linux. Live discovery requires `lsblk`; `lspci` is optional.
No root access or network access is required for the included fixture demo.

```bash
# Clone/extract this repository and run from its root directory:
python -m aegis --help
python -m aegis assurance --json
python tools/security_lint.py
python -m aegis menu --inventory fixtures/desktop-example.json  # interactive start screen
python -m aegis inspect --inventory fixtures/desktop-example.json
python -m aegis assess --inventory fixtures/block-device-observation-example.json
python -m aegis wizard --inventory fixtures/desktop-example.json
python -m aegis profile --inventory fixtures/desktop-example.json  # KDE Plasma default
python -m aegis profile --inventory fixtures/desktop-example.json --desktop kde-plasma
python -m aegis plan --inventory fixtures/desktop-example.json \
  --primary /dev/nvme0n1 --secondary /dev/sda --output proposal.json
python -m aegis report --plan proposal.json --output proposal.html
python -m unittest discover -s tests -v
```

The fixtures contain **entirely fictional hardware**. `/dev/nvme0n1` above
refers only to its example JSON entry. The `assess` command accepts a separate
structured observation fixture with a top-level `devices` list; it reports
`blocked` for incomplete or unsafe observations and never authorizes writes.
It does not probe live hardware and is not yet wired into the live planner.
No partition or filesystem operations exist in this version.

For a live, **read-only** inventory on Linux:

```bash
python -m aegis inspect
python -m aegis inspect --json
python -m aegis network             # Read-only internet verification
python -m aegis network --connect   # Interactive opt-in Wi-Fi setup
python -m aegis wizard
```

The live wizard merely **proposes** erasing the chosen primary disk. It never
executes a disk change. Make sure you understand the proposals before sharing
reports publicly: default HTML reports redact disk serial and WWN, while locally
saved JSON proposals retain disk identifiers and are created with mode 0600.

Connectivity checks require access to public HTTPS endpoints and do not guarantee
that package mirrors are reachable. If connectivity is unverified, possible causes
include no connection, DNS, incorrect system clock, captive portal and network
restrictions. On the official Arch ISO the setup prompt opens `iwctl` (iwd); on
a running NetworkManager system it prefers `nmtui connect`. Any passwords are
handled by those tools, not by AEGIS. Declining leaves the network unchanged.
The actual installed system must receive its own verified persistent network
configuration; the live ISO connection alone is not sufficient.

An editable Python package can be installed into a private venv via `python -m
pip install -e .`. On the official Arch ISO, installing a package or unpacking
verified release code is an **anticipated future distribution route**, not yet
a tested or signed bootstrap. Do not pipe an arbitrary URL into `sh`.

## Roadmap

| Stage | State |
|---|---|
| Hardware detection and read-only partition planning | Implemented, pre-alpha |
| Reproducible virtual-machine installation and recovery | Not implemented |
| TPM 2.0 + PIN, signed boot and offline recovery | Not implemented |
| Kernel/GPU selection and gaming/VR configuration | Advisory profile only |
| Security Guardian (firewall, malware, AppArmor) | Not implemented |
| Hardware-specific optimization and safe rollback | Not implemented |
| Signed ArchISO, public hardware qualification | Not implemented |

For design and security boundaries, see [Architecture](docs/ARCHITECTURE.md),
[Threat Model](docs/THREAT_MODEL.md), [Release Gates](docs/RELEASE_GATES.md),
[Report Specification](docs/REPORT_SPEC.md), and [Roadmap](docs/ROADMAP.md).

## Privacy and safety

This software makes no security guarantees about a real machine. It is intended
for local testing and review. No real install should rely on an unreviewed plan.
Device paths are not stable hardware identifiers. Even plans without preflight
blockers must be revalidated by a future executor immediately before writing.
The absence of warnings is not evidence that an installation is safe.

## Licensing and contributing

See [LICENSE](LICENSE) (MIT) and [CONTRIBUTING.md](CONTRIBUTING.md).
Security concerns can be reported according to [SECURITY.md](SECURITY.md).

## Layer 02: disposable VM laboratory (developer-only)

AEGIS includes a **source-checkout-only** `python -m lab` launcher for
QEMU/OVMF/swtpm with two ephemeral virtual disks and no host-device passthrough.
The no-write planning CLI is unchanged. No Arch installation engine exists.

```bash
python -m lab --check
python -m lab --smoke --seconds 8  # Requires local QEMU, OVMF and swtpm
```

The smoke test confirms QEMU machine state and TPM registration via a local QMP
socket; it **does not** demonstrate successful guest OS boot, Secure Boot,
Linux installation, encryption or recovery. Read [the lab safety and operation
manual](docs/VIRTUAL_LAB.md) before experiments. The disposable VM runner
has not been independently security-audited and does not sandbox a compromised
QEMU process beyond unprivileged execution and restricted device arguments.
