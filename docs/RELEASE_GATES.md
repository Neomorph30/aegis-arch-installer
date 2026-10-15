# AEGIS release and safety gates

## Preview 0.2 — read-only; Layer 01 engineering requirements

- [x] No disk installation/execution subsystem exists.
- [x] Device enumeration runs only allowlisted read-only commands.
- [x] Fixture-based end-to-end CLI flow and interactive wizard.
- [x] Storage proposal includes partition geometry, blocking hazards and states.
- [x] Reports identify every unexecuted control as unverified.
- [x] Local JSON files created with exclusive 0600 permissions.
- [ ] Independent technical review of code and threat model.
- [x] Published public repository and verified GitHub Actions across Python 3.11–3.13.
- [x] Versioned requirements, formalized threat register and supported-scope documentation.
- [x] Developer CLI `aegis assurance` reports unimplemented security capabilities honestly.
- [x] CI AST guardrail forbids new privileged command interfaces in this preview.
- [ ] Independent technical security review remains outstanding (cannot self-certify).

## Before even enabling *virtual-disk-only* executor

- [ ] Explicitly separate executor permissions from UI and planning.
- [ ] Data flow and privilege-boundary review with an independent reviewer.
- [ ] Disposable QEMU/OVMF/virtual TPM environment, never host real disks.
- [ ] Offline tested backup/recovery procedure for LUKS headers and keys.
- [ ] Full expected partition-table assertions before and after writes.
- [ ] Fault injection for interrupts, simulated power loss and stale devices.
- [ ] Recover without data loss from TPM policy mismatch / failed kernel update.

## Before any *physical* disk install (NOT YET ALLOWED)

- [ ] Re-identify device by stable by-id path, WWN/serial, major/minor and capacity
      immediately before access; reject ambiguous identities.
- [ ] Enumerate and reject mounted or active LVM/RAID/swap/root/installer targets.
- [ ] Provide exact per-drive before/after partition maps and backup warnings.
- [ ] Explicitly authorize each destructive physical device, separately.
- [ ] Require recovery credential enrollment and verified offline export.
- [ ] Test TPM 2.0 PIN enrollment and fallback recovery path on target hardware.
- [ ] Verify Secure Boot keys, signed UKIs and the chosen PCR policy.
- [ ] Validate rollback and boot fallback across all installed kernels.
- [ ] Independent security review, hardware matrix and signed release images.

## Security Guardian release requirements

- [ ] No firewall rule can silently disable active remote management.
- [ ] Firewall changes use a verified rollback timer or a proven local console.
- [ ] Verify DHCP, DNS, IPv6 neighbour discovery, VR streaming and game services.
- [ ] Document ClamAV scanning limitations and opt-in heavy on-access scanning.
- [ ] AppArmor restrictiveness is opt-in unless hardware/software tested.
- [ ] Final reports distinguish PASSED, FAILED, WARNING, SKIPPED, UNVERIFIED.
- [ ] Report exports never disclose passwords, encryption keys, PINs or tokens.
