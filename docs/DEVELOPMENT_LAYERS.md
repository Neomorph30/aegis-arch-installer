# AEGIS — Layer-by-layer development plan

Status: **developer preview 0.2 / pre-alpha**, reviewed against repository contents on **2026-10-15**. This document is a work plan, **not proof that an item is implemented**.

> Guiding rule: design → implement → test failure paths → review → merge → advance. Do not activate a physical-disk writer until independent security review, virtual-machine recovery tests, user authorization and physical-device safety gates pass.

## Scope and guiding decisions

- Public, open-source x86-64 UEFI Arch installer; a text UI first and optional GUI later.
- Security-first profiles: LUKS2 + Btrfs default; TPM 2.0 + PIN only when fully validated; per-volume offline recovery.
- Hardware-dependent desktop, kernel, graphics, gaming, VR and biometrics modules; unsupported components remain optional and explicitly reported.
- Network connectivity preflight and opt-in Wi-Fi setup; persistent network configuration must be implemented separately.
- Dedicated signed ISO plus verified installer package bootstrap on standard Arch media.
- Final HTML/JSON/evidence reports and a later post-install management utility; secrets NEVER logged.
- Riskier features such as dual-boot resizing, live-disk migration, firmware key enrollment, hibernation and custom-compiled kernels require independent qualification; they are **not assumed v1-ready**.

## Current capabilities — Layer 00

**Layer 00 — Non-destructive foundation** — **IMPLEMENTED (pre-alpha)**

Read-only hardware probes, storage proposals, Btrfs/ext4 layout proposals, TUI wizard, advisory gaming packages, local JSON and sanitized HTML reports, opt-in `iwctl`/`nmtui` Wi-Fi onboarding, fixture tests and CI. Recent regression suite: 68 tests, with CI verified passing on the latest merge. No installer executor exists. These passes do **not** certify safe physical installation.

## Foundation and protected execution

### Layer 01 — Requirements, threat model and quality gates
**State: PARTIAL. Depends on Layer 00.**
- Version the system profile, security requirements, hardware support states and risk register.
- Formalize threat model for remote compromise, evil-maid boot tampering, wrong-drive destruction, key disclosure, and malicious installer inputs.
- Add static checks, dependency review, adversarial fixtures and CI gates; ensure actual evidence, not raw success exit codes, determines report status.
**Exit:** documented v1 support matrix and reviewed gates; reproducible, green tests; explicit security review signoff required before privileged executor.

### Layer 02 — Disposable virtual test laboratory
**State: IMPLEMENTED AS A RESTRICTED SMOKE LAB; guest installation remains untested. Depends on Layer 01.**
- QEMU/KVM or other QEMU accelerator, OVMF UEFI, virtual TPM (swtpm), synthetic NVMe/SATA disk images.
- Isolate the guest from host block devices and host-mounted filesystems.
- Build repeatable snapshot/rollback harness and simulated interruption/reboot tests.
**Exit:** tests prove intended guest disks are accessible and host drives are not; unattended disposable VM reset works.

### Layer 03 — Production-grade hardware inventory
**State: PARTIAL; conservative structured inventory analysis and bounded read-only recovery are merged, but live hardware coverage is incomplete. Depends on Layer 01.**
- Replace loose probe output with a typed, versioned inventory: CPU/microcode, GPU IDs, NICs, RAM, firmware, TPM capabilities, drive serial/WWN/by-id, partitions, mount holders, swap, RAID/LVM/mapper trees.
- Never infer writable eligibility from a device path, unused mountpoint, or missing warnings.
- Redact identifying details from shareable diagnostics.
**Exit:** fixtures cover NVMe, SATA, MMC, USB live media, arrays, hotplug, duplicate IDs and ambiguous configurations, all failing closed when necessary.

### Layer 04 — Complete accessible installer wizard and networking
**State: PARTIAL; the guided storage proposal flow and bounded input recovery are merged, but full installer configuration and persistent networking are not implemented. Depends on Layers 01,03.**
- TUI keyboard navigation, help and accessibility; language, region, user, device, filesystem, security, desktop and optional-module steps.
- Read-only connectivity diagnostic; opt-in Wi-Fi via system tools; distinguish DNS/TLS/captive portal and unreachable mirrors.
- Present constraints and dependencies *before* user commits choices; support going back safely.
**Exit:** scripted TUI flows and negative tests; no raw credentials handled by AEGIS; offline states are truthful.

### Layer 05 — Advanced storage planner and consent
**State: PARTIAL; validated identities, inventory fingerprint and tamper-detection digest are merged. Digest verification is not authorization, and no storage write is enabled. Depends on Layers 03,04.**
- Design EFI/system/data partitions with checked alignment, size/headroom, encryption, Btrfs subvolumes and mountpoints; preserve secondary drives by default.
- Model manual partitioning, existing ESPs and existing data without automatically enabling risky dual-boot shrinking.
- Generate immutable, schema-versioned plans; show before/after maps and per-device destructive warnings.
**Exit:** fuzz/geometry tests, device-collision and boot-medium exclusions; every proposed write identifies its exact target and requires independent authorization later.

### Layer 06 — Narrow privileged execution boundary (virtual only)
**State: PARTIAL; a virtual-only review/simulation gate is merged, but no privileged executor or disk-writing operation exists. Depends on Layers 02,03,05 and independent review.**
- Standalone executor with allowlisted structured operations, no shell interpolation, immutable reviewed plans, capability separation and just-in-time device revalidation.
- Constrain to disposable virtual disk images; no access to physical host disk devices.
- Durable operation journal, restart logic, rollback where feasible, refuse stale or tampered plans.
**Exit:** red-team/negative tests prove arbitrary paths and host devices cannot be accessed; crash injection leaves an inspectable recoverable state.

## Bootable secure Arch in a virtual machine

### Layer 07 — Minimal Arch installation engine
**State: PARTIAL; a pure guest preflight specification and negative tests exist, but no guest command is executed and no Arch installation has been tested. Depends on Layer 06.**
- On *disposable virtual disks only*: partition, create a root LUKS2 container with temporary/recovery credentials, format Btrfs, mount, `pacstrap`, set locale/timezone/users, generate fstab/crypttab/initramfs and provision initial UEFI boot.
- Pin expected package inputs and verify output rather than trusting process exit alone.
**Exit:** boots a minimal Arch VM from encrypted root and withstands interrupted install/retry tests; all state reported accurately.

### Layer 08 — Recovery-first LUKS2 and multi-drive management
**State: NOT STARTED. Depends on Layer 07.**
- Distinct cryptographic keys for secondary volumes, stored only inside encrypted root; per-volume offline recovery.
- Verify secondary unlock behaviour, lost-primary-drive recovery, LUKS header backup protection and key rotation.
- Never silently write or erase a secondary disk.
**Exit:** independent recovery test per volume; no secret material in logs or reports; fault injection does not strand accessible volumes.

### Layer 09 — Secure Boot + measured boot + TPM/PIN
**State: NOT STARTED. Depends on Layers 07,08.**
- Signed UKIs, policy-controlled Secure Boot setup, systemd TPM2 enrollment with boot PIN and suitable measured/signed PCR policy.
- Ensure kernel updates/signing preserve a known-good boot/recovery choice.
- Treat firmware key enrollment as a separate verified, platform-dependent ceremony, never silently disable Secure Boot.
**Exit:** approved boot unlocks; modified boot fails trusted unlock; changed TPM/PCR, locked-out PIN and failed update retain offline LUKS recovery.

## Workstation and workload modules

### Layer 10 — Network persistence, users and KDE baseline
**State: NOT STARTED. Depends on Layers 07,09.**
- Install supported network service and persist user-approved Wi-Fi/network configuration without exposing credentials; verify DNS, DHCP, IPv6 and mirror reachability after reboot.
- User creation, secure PAM baseline, KDE Plasma/Wayland, display manager, PipeWire/WirePlumber and packages.
**Exit:** encrypted VM boots to a usable session, reconnects as intended, and preserves working password login.

### Layer 11 — Kernel selection, GPU drivers and fallback
**State: NOT STARTED. Depends on Layers 09,10.**
- `linux`, `linux-zen`, optionally `linux-lts`; matching headers and signed boot assets.
- Detect Intel/AMD/NVIDIA GPU and install qualified Mesa/Vulkan/DKMS/module signing stack.
- Monitor kernel upgrade and driver compatibility without speculative unsafe defaults.
**Exit:** standard and fallback kernels boot; GPU/display/3D driver and UKI/module signing tests pass on qualified hardware.

### Layer 12 — Gaming profile
**State: NOT STARTED. Depends on Layer 11.**
- Opt-in Steam, Proton, 32-bit graphics, Vulkan, GameMode, MangoHud and optionally Lutris.
- Validate Wayland/XWayland compatibility; no blanket disabled security mitigations.
**Exit:** representative game workloads launch, recover from faults and document version/performance compatibility.

### Layer 13 — VR profile
**State: NOT STARTED. Depends on Layers 10–12.**
- Optional WiVRn and/or ALVR, OpenXR and SteamVR bridge evaluation, GPU encoding readiness, audio/controller tracking and required network permissions.
- Qualify Quest 3 first; add more headsets after independently tested support.
**Exit:** live headset pairing and repeatable VR test sessions on real hardware, with failures and unsupported games reported accurately.

### Layer 14 — Biometric desktop sign-in
**State: NOT STARTED. Depends on Layer 10 and security review.**
- Device-specific fingerprint detection; preserve password login and distinguish SDDM vs screen unlock support.
- Facial authentication an optional experimental module with documented spoofing limitations; no biometrics-only privileged sudo baseline.
**Exit:** deliberately failed/unavailable sensor cannot lock out password login; PAM and wallet integration tested.

### Layer 15 — Conservative adaptive optimizer
**State: NOT STARTED. Depends on Layers 11–13.**
- Read-only baseline of storage, thermals, CPU frequency policy and performance; reversible recommended tuning.
- Benchmarks and user-approved changes with measured frametime/thermal results; snapshot plus non-filesystem rollback where applicable.
- Custom-built kernels, overclocking and risky mitigation changes excluded from safe defaults.
**Exit:** every applied change has justification, before/after evidence and tested rollback; regression reverts.

### Layer 16 — Security Guardian
**State: NOT STARTED. Depends on Layers 10–15.**
- firewalld/nftables safe profiles; service discovery; preserve remote administration and rollback watchdog; scoped gaming/VR exceptions.
- Optional ClamAV with signature updater and scheduled scans, compatible AppArmor, audit hygiene and package verification.
**Exit:** remote management lockout simulated and rollback proven; DNS/DHCP/IPv6/VR tested; controls classified passed, failed, skipped or unverified.

### Layer 17 — Post-install verification, report and recovery manager
**State: PARTIAL (proposal reports only). Depends on Layers 07–16.**
- Schema-versioned evidence manifests and readable HTML/PDF-if-needed reports: storage, LUKS, secure boot, package versions, kernel drivers, firewall, optimization and recovery.
- Redacted public exports; private local files restrictive permissions; never store PINs, credentials, LUKS keys or signing secrets.
- Diagnostics and system-baseline/drift reporting, with recovery instructions.
**Exit:** results are evidence-backed; no unexecuted control marked passed; shareable exports pass secrets-redaction tests.

## Distribution and release

### Layer 18 — Verified bootable ISO and normal-Arch bootstrap
**State: NOT STARTED. Depends on Layers 01–17.**
- Reproducible `archiso` installer image that launches the TUI; provide terminal fallback and installer rescue environment.
- Signed source/releases/package distribution; integrity verification; planned Secure Boot-compatible boot medium enrollment route.
- Support verified installation from official Arch ISO without `curl | sh`.
**Exit:** bootable image runs hardware discovery and the full gated VM install; users can independently verify artifacts.

### Layer 19 — Public v1.0 qualification and long-term maintenance
**State: NOT STARTED. Depends on all prior layers.**
- Diverse real-hardware test matrix (CPU, GPU, UEFI vendor, TPM, storage, network, laptops), adversarial inputs, interruption and recovery drills.
- Independent security audit, supported/unsupported list, vulnerability response policy and accessible user documentation.
- Signed releases, regression CI, contributor process and clearly defined update maintenance policy.
**Exit:** all public release gates pass; never promise 100% error-free installation. Real disks remain prohibited before all physical-device security gates are independently satisfied.

## Sequencing rules

1. **No real-disk installer** before virtual harness, privilege boundary, full recovery, threat-model review and qualified hardware tests.
2. **No trusted-boot claim** from reading a Secure Boot variable alone; require cryptographic/measured verification.
3. **No TPM-only key path** without verified offline recovery; never print secrets in installation logs.
4. **No forced performance tweaks** that disable security or jeopardize bootability.
5. **No public-ready label** while essential controls are merely proposed, skipped or unverified.
6. Every layer produces implementation, tests, documentation, explicit exit evidence and a reviewed pull request. Tracked GitHub issues link to the applicable layers.

## Existing GitHub issues

- #1 virtual installation harness → Layer 02
- #2 privileged executor → Layer 06
- #3 TPM + PIN and recovery → Layers 08–09
- #4 Security Guardian → Layer 16
- #5 signed ArchISO → Layer 18
- #6 evidence and reporting → Layer 17
- #7 kernels/GPU/gaming/VR → Layers 11–13
- #8 independent security and privacy review → Layers 01,06,19

## Immediate next task

**Layer 01**: review the threat model and build quality requirements; close remaining baseline gaps in the typed hardware inventory and release-gate evidence. **Layer 02** then provides the disposable VM harness before any write-capable installer code is introduced.
