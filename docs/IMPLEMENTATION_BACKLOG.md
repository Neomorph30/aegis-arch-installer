# Engineering backlog — ready for GitHub issues

These are implementation specifications, not authorizations for physical disk operations.

## P0: preview foundation

**AEGIS-001 — Typed hardware inventory schema**
- Migrate raw `lsblk` objects into a versioned typed inventory with strict bounds.
- Detect by-id links, namespaces, LVM, MDRAID, mapper and mounted swap recursively.
- Maintain invariant: no privileged commands; never trust a device name alone.
- Acceptance: fixture tests for NVMe, SATA, MMC, USB, iSCSI, loop and mixed storage.

**AEGIS-002 — Storage geometry and collision validator**
- Add explicit partition sizes, labels, mountpoints and user-resizable regions.
- Validate alignment, overlap, GPT reserve, encryption payload headroom.
- Include special cases for multi-boot EFI and occupied ESPs.
- Acceptance: property-based fuzz tests; invalid plans are rejected and reported.

**AEGIS-003 — Installer USB / system disk provenance detector**
- Resolve mounted device trees, overlay roots, boot media, swap and all holders.
- Mark physically ambiguous devices as blocked, never clear silently.
- Acceptance: fabricated nested tree tests and QEMU evidence.

**AEGIS-004 — Pure install plan schema and deterministic review**
- Model operations as typed, immutable declarative data separate from any executor.
- Version schema, add compatibility checker and deterministic planning tests.
- Acceptance: JSON round-trip, replay validation, tampering/collision tests.

**AEGIS-005 — TUI usability/accessibility**
- Introduce a robust keyboard interface with cancellation and detailed help.
- Keep terminal fallback and no mutation paths.
- Acceptance: scripted terminal interactions; no dependency on KDE or GPU.

**AEGIS-006 — CI hardening and independent review**
- Test across supported Python versions and Arch containers.
- Add static analysis, dependency pinning/audit, reproducible releases.
- Acceptance: clean CI and independent sign-off on threat model.

## P1: virtual-disk-only installer (gated)

**AEGIS-007 — Privileged executor in a disposable VM**
- Strictly separated daemon/service with restricted input schema.
- Never accept raw shell arguments from UI; use allowlisted structured operations.
- Recheck stable device identity and mount holders before and after each step.
- Acceptance: cannot open physical host devices even with malicious input.

**AEGIS-008 — Recovery-first LUKS2 enrollment**
- Plan ephemeral installation credentials, independent recovery per LUKS volume,
  secure header backups and test reopen before removing temporary credentials.
- Acceptance: injected failures leave a documented recoverable state.

**AEGIS-009 — Trusted boot and TPM integration**
- Signed UKIs + Secure Boot policy + TPM 2.0 boot PIN, with signed PCR policies.
- Acceptance: success after kernel update; failure on untrusted boot; recovery
  using offline credentials when TPM state changes.

## P2: workstation and public release

**AEGIS-010 — Stable kernels and driver matching**
- Install stable, Zen, LTS; preserve signed rollback images, verify module loading.
- Acceptance: fallback boots even if new NVIDIA build fails.

**AEGIS-011 — Steam, VR and optimization profiles**
- Introduce qualified GPU packages, benchmark-led conservative tuning, supported
  Quest/Pico headset runtime integrations and automatic rollback where safe.
- Acceptance: real hardware compatibility report, no unsupported claims.

**AEGIS-012 — Security Guardian**
- Safe firewalld changes with remote-session rollback; optional ClamAV;
  test AppArmor, package integrity, networking and recovery.
- Acceptance: not possible to permanently lock out remote user through a
  failed firewall self-test; all unverified controls reported as such.

**AEGIS-013 — Installer and security completion reports**
- Signed/redacted human-readable reports and machine-readable evidence manifest.
- Acceptance: no PIN, LUKS key, token, private signing key or raw credentials.

**AEGIS-014 — Public ISO and installer bootstrap**
- Trusted ArchISO builds, signatures, verifiable release/checksum procedure,
  Secure Boot-friendly distribution policy and recovery media.
- Acceptance: independent installation/recovery audit on hardware matrix.
