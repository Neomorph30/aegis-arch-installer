# AEGIS development roadmap

## Phase 0: non-destructive public preview
- [x] Linux hardware inspection and read-only storage proposals
- [x] Keyboard-driven terminal wizard (fixture or live observations)
- [x] Btrfs or ext4 partition geometry proposals and secondary-disk policies
- [x] Safety blockers for mounted, USB, read-only, ambiguous target devices
- [x] Software/security package profile *recommendations* (not installation)
- [x] Sanitary proposal-only HTML report and local protected JSON
- [x] Fictional fixtures, automated tests, GitHub workflow
- [ ] External design and security review
- [x] Publish repository and verify GitHub Actions execution

## Phase 1: virtualized installer (NOT IMPLEMENTED)
- [ ] Narrow, standalone privileged executor; disposable virtual disks only
- [ ] Virtual GPT + LUKS2 + Btrfs installation with recovery testing
- [ ] QEMU/OVMF/swtpm harness; crash/restart fault-injection tests
- [ ] Recovery-first key management with offline export

## Phase 2: trusted boot (NOT IMPLEMENTED)
- [ ] UEFI, signed UKIs, validated Secure Boot enrollment procedure
- [ ] TPM 2.0 + boot PIN and signed PCR policies, recovery fallback
- [ ] Three-kernel boot/update and NVIDIA module-signing validation

## Phase 3: workstation and game-ready profiles (NOT IMPLEMENTED)
- [ ] KDE Plasma, standard/Zen/LTS kernels, proven GPU support
- [ ] Steam/Proton and optional VR on qualified headsets
- [ ] Fingerprint/face support only when independently tested

## Phase 4: Security Guardian (NOT IMPLEMENTED)
- [ ] firewalld rules with preserved remote access and rollback watchdog
- [ ] ClamAV scheduled scan option, AppArmor, least-privilege maintenance
- [ ] Evidence-driven installation and security report + drift auditing

## Phase 5: public 1.0 (NOT IMPLEMENTED)
- [ ] Signed custom ArchISO and trusted update/verification process
- [ ] Reversible, measured optimization engine; no unsafe performance claims
- [ ] Independent security audit, hardware matrix, tested recovery path

## Layer 01 — assurance and security quality baseline
- [x] Versioned security requirements and explicit support matrix
- [x] Threat model and prioritized preliminary risk register
- [x] Security guardrail executable and malicious-code regression tests
- [x] SHA-pinned CI actions and constrained GitHub workflow permissions
- [x] Machine-readable CLI readiness status with honest unimplemented capabilities
- [ ] External independent reviewer endorsement (not falsely claimed)

See [Development Layers](DEVELOPMENT_LAYERS.md) for the full 20-layer plan.

## Layer 02 developer VM lab status
- [x] Non-root disposable synthetic disks, OVMF variable-store copy and swtpm socket.
- [x] No-host-passthrough QEMU command construction; no networking or KVM.
- [x] QMP launch/TPM inspection and automated negative tests.
- [ ] Complete independent security review and verify actual GitHub Actions QEMU smoke.
- [ ] Install Arch inside VM (future Layer 07).
