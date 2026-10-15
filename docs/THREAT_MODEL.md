# AEGIS threat model — Layer 01 baseline (review pending)

**Status: engineering baseline. Not independently audited.** This describes
where AEGIS trusts inputs and how later security features must be verified.
Nothing in this model authorizes disk, firmware, TPM, firewall or boot changes.

## 1. Assets

- Existing user data on internal and external disks and backup media.
- Encryption keys, TPM PINs, recovery passphrases, Secure Boot signing keys.
- Live running system, installation USB, firmware state and boot integrity.
- Network access, remote administrator session and VR/gaming connectivity.
- User-sensitive identifiers in hardware inventory and installation reports.
- Software supply-chain provenance and the install plan's integrity.

## 2. Adversaries and assumptions

- Accidental user mistakes, malicious external input, compromised downloads,
  untrusted installation source or malicious plugin/package.
- A local attacker with physical possession of a powered-off device (theft) or
  opportunity to tamper with boot media (evil-maid scenario).
- An attacker able to submit tampered inventories, plans or malicious code changes.
- Adversarial hardware/firmware reporting and failures caused by bugs/power loss.
- An attacker with full root privileges after unlocking is **not guaranteed to
  be contained** by TPM/LUKS/Secure Boot/antivirus. No absolute security claim.
- Public GitHub CI and unrelated machines are treated as untrusted environments.

## 3. Trust boundaries

| Boundary | Untrusted input | Control now | Required before privileged execution |
|---|---|---|---|
| Hardware observations → inventory | sysfs, lsblk/lspci, device metadata | Allowlisted read-only probes | Typed/versioned input, size validation, provenance, re-probing |
| Inventory → storage plan | Filename, device paths, fixture JSON | Pure proposals, safe refusal cases | Immutable schema, collision and active-holder validation |
| Plan → executor | User-modified JSON, stale identities | **No executor exists** | Narrow audited API, anti-replay approval, just-in-time device identity |
| Network → installer | DNS/TLS/portal/wireless tooling | Bounded HTTPS hints, Wi-Fi opt-in | Trusted mirrors, verified source provenance, credentials isolation |
| Installed system → updates | Packages, kernels, signing metadata | **Not implemented** | Verified packages, signed UKIs, recovery and fallback |
| Reports → users/public | Serial numbers, logs, credentials | 0600 local JSON, sanitized HTML | Evidence schema, exhaustive secret leakage tests |

## 4. Security goals (future)

1. Never silently modify a disk, even when users select a broad install profile.
2. Before any write, prove target stable identity to the extent hardware permits;
   reject mounted/active disks and all ambiguous/unsupported configurations.
3. Require explicit per-device action confirmation. Secondary drive defaults to
   preserve; unlocking existing encrypted volumes requires consent and secrets
   isolated from logs.
4. Use LUKS2 encryption and offline per-volume recovery. TPM2 + PIN is a boot
   convenience tied to validated trusted-boot policy, not a substitute for backup.
5. Signed UKIs and Secure Boot enforcement remain recoverable across firmware
   changes and rolling kernel upgrades; never silently disable Secure Boot.
6. No firewall policy may permanently lock out established management access
   without explicit local-console recovery and a verified rollback mechanism.
7. Security reports classify PASSED only from actual test evidence; unexecuted,
   unsupported or unverified features must never appear as operational.
8. Optimization changes must be reversible, documented and not degrade mandatory
   exploit mitigations without an explicit, separately reviewed policy.

## 5. Abuse-case matrix

| Abuse / fault input | Expected behavior | Current coverage |
|---|---|---|
| Duplicate path or serial, USB live disk, mounted root | Reject destructive *proposal* or mark BLOCKED | Fixture tests |
| Edited plan claiming execution enabled | Reject report; never execute | Regression tests |
| Symlink exists where report file would be written | Refuse overwrite | Regression tests |
| Privileged code added to preview package | Reject in AST regression and PR review | Static test (best effort only) |
| User enters invalid Wi-Fi password | Delegated manager handles it; no AEGIS secret logging | Mocked onboarding tests |
| HTTPS blocked but DNS/local network available | Status `unverified`, not definitive offline | Network tests |
| Stale inventory after drive hotplug | Executor must refuse and re-probe | **Not implemented** |
| TPM clear or PCR mismatch | Require offline recovery, not unrecoverable boot | **Not implemented** |
| Power cut while repartitioning | Recoverable or halt with explicit status | **Not implemented** |
| Untrusted root-level compromise | Limit claim; prompt incident response and recovery | No containment guarantee |

## 6. Accepted limitations and out of scope

- Secure Boot EFI variable alone is **not** proof of trust.
- Serial/WWN/by-id alone may be spoofed; even live identity rechecks have limits.
- Recovery from a destroyed LUKS header requires external header backups and
  surviving recovery materials; snapshots are not backups.
- Antivirus cannot detect all threats; biometric sensors vary in spoofing
  resistance and driver support.
- VPN, captive-portal, enterprise Wi-Fi, IPv6-only networks and proprietary VR
  stacks need separate qualification.
- Dual-boot shrinking, live migration, arbitrary RAID/LVM, custom kernels and
  firmware key changes are explicitly not auto-enabled in initial v1.

## 7. Threat review and decision record

- Baseline: 2026-10-15, Layer 01 documentation and automated guardrails.
- Independent reviewer approval: **NOT COMPLETED**.
- Host drive write authorization: **NOT GRANTED**.
- Security certification: **NOT CLAIMED**.
- Re-evaluate at Layer 06 (executor boundary), Layer 09 (trusted boot),
  Layer 16 (firewall), and Layer 19 (public release).

See `SECURITY_REQUIREMENTS.json`, `RISK_REGISTER.md`, `QUALITY_STANDARDS.md`
and `RELEASE_GATES.md` for machine-readable requirements and quality gates.
