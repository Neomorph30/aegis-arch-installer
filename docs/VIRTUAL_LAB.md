# Layer 02 — disposable UEFI virtual-machine laboratory

**Scope:** a developer-only, deliberately restricted QEMU environment with synthetic disks and a software TPM. It does **not** install Arch, enroll TPM keys, prove an Arch boot, test LUKS recovery or authorize access to physical devices.

## Requirements

- Linux x86-64 host, Python 3.11+, unprivileged local account; no root execution.
- QEMU system x86-64, a compatible **paired** OVMF CODE/VARS firmware installation, and `swtpm`.
- On Arch, install the documented `qemu-desktop`, `edk2-ovmf` and `swtpm` packages. For other Linux distributions firmware locations may differ; see supported pairs in `lab/runtime.py`.
- A local ISO must be a regular (not symlink/device) file, up to 8 GiB. Only use trusted installation ISOs. AEGIS copies it into the ephemeral private VM workspace.

From the **source checkout** (the lab is intentionally not distributed as an installer executable):

```bash
python -m lab --check               # no modifications
python -m lab --smoke --seconds 8   # temporary VM / QMP launch verification
python -m lab --run --iso /path/to/verified-arch.iso
```

`--run` needs a graphical desktop and a QEMU build with GTK display support. QEMU's window is used to interact with guest firmware/ISO; exiting the VM destroys its **temporary** disks and TPM state. This is intentionally not a persistent installation environment. There is no manual device passthrough or guest networking.

## How the launcher protects the host

- Refuses to run as root. Creates only a process-owned private directory with an unpredictable name under `/tmp`, and deletes it after exit or failure.
- Creates **two new sparse regular files** as the only guest disks (24 GiB + 8 GiB), using exclusive creation without following symlinks. The primary and secondary expose fixed lab-only serial markers; the secondary disk is attached read-only for the Layer 07 preflight. No API accepts a host disk path, partition path, `-drive` arguments or QEMU device passthrough.
- Copies the firmware *variable template* and optional ISO into the private directory; firmware CODE is mounted read-only. Firmware files must be a supported matching pair of regular files. No firmware keys are enrolled or modified on the host.
- Software TPM uses only a private Unix socket and private per-run state directory.
- QEMU runs in portable TCG mode without KVM, host networking, bridged interfaces, host directory sharing, host USB passthrough or VM file sharing. QMP is local to the private workspace.
- The smoke test waits for `swtpm`, queries QEMU's status and registered TPM via local QMP, then keeps it alive for a bounded interval, and terminates both processes. A passing smoke test proves **emulation startup and TPM registration only**. It does not prove UEFI firmware finished booting, that the ISO booted, or that host isolation is formally guaranteed.
- If QEMU is compromised via a hypervisor escape, it still runs with its host user's file permissions. AEGIS does **not** claim a hardened host sandbox: run only trusted ISOs; further confinement must be reviewed before executing adversarial guest code.

## Safety and recovery checks

Run the no-write tests:

```bash
python tools/security_lint.py
python -m unittest discover -s tests -v
```

Tests exercise missing dependencies, wrong firmware combinations, rejected device/symlink inputs, refused pre-existing disk files, private workspace permissions, size bounds, explicit network isolation, attempts to substitute `/dev/sda`, QMP TPM-absence detection and cleanup logic. GitHub Actions also attempts a **real disposable QEMU/OVMF/swtpm launch** on an ephemeral runner.

## Remaining work

Layer 06 will design the privileged *guest installer* (not part of this lab); Layer 07 will boot a minimal encrypted Arch guest; Layer 08 will demonstrate offline recovery, key/header backup and deliberate failures. This lab is a testing foundation, not evidence those later acceptance tests passed.
See [Virtual Write Authorization Gates](VIRTUAL_WRITE_AUTHORIZATION.md) for the
required review, consent, identity and recovery conditions before any guest-side
disk writer may be enabled. The current guest storage gate is preflight-only.

References: [ArchWiki QEMU](https://wiki.archlinux.org/title/QEMU), [ArchWiki archiso](https://wiki.archlinux.org/title/archiso), [QEMU system security documentation](https://www.qemu.org/docs/master/system/security.html).
\nWhen a verified ISO is attached, QEMU's boot order is explicitly set to optical media first; this only requests boot order and is not proof that the guest booted.\n