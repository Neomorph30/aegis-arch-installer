# Support matrix (AEGIS pre-alpha)

**No system is qualified for real installation.** The list below describes what
can be *observed and proposed* today, not certified installers/drivers.

| Feature | Current support | Later qualification required |
|---|---|---|
| x86-64 Linux host | Read-only preview, tested with fixtures and CI | ArchISO live tests, physical hardware |
| UEFI detection | Hint read from sysfs | Bootloader/Secure Boot verification |
| Intel/AMD CPU | Basic CPU label only | Microcode, frequency drivers, thermals, stability |
| NVIDIA/AMD/Intel graphics | lspci hints and advisory package profiles | Driver/firmware/DKMS/Wayland/VR matrix |
| NVMe/SATA | lsblk observation and proposals | Device identity/holder revalidation, VM install |
| USB/MMC/RAID/LVM | Potentially observable, not qualified for writes | Clear exclusion and special-case tests |
| Btrfs/ext4 | Read-only proposed layout | Format/mount/restore and crash testing |
| LUKS2 | Proposed root encryption | Secure provisioning, keys, offline recovery |
| TPM 2.0 | Kernel-exposed version hint | Attestation policy and PIN anti-lockout tests |
| Secure Boot | EFI variable hint only | Signed UKIs, key lifecycle and firmware tests |
| Ethernet/Wi-Fi | Bounded HTTPS test, opt-in iwctl/nmtui | Actual networking hardware/driver tests, persistence |
| KDE Plasma | Not installed | Real workstation smoke tests |
| Steam/Proton/Quest 3 | Package recommendations only | Live gaming/VR compatibility and benchmarks |
| Biometrics | Not implemented | Sensor driver, PAM, recovery and lockout tests |

## Initial v1 target

- x86-64 UEFI workstations; single Linux install on explicitly erased, internal
  local disk, with separate optional encrypted secondary volumes.
- Installed Arch is reproducibly bootable and recoverable after supported kernel updates.
- Btrfs + LUKS2 default; ext4 optional after independent qualification.
- TPM2 + PIN is hardware-dependent, not mandatory. Passphrase-only recovery
  path always required for a TPM configuration.
- KDE/gaming/VR available only on tested hardware/software combinations.

## Out of scope until explicitly qualified

In-place conversion of live systems, automatic shrinking of existing partitions,
dual-boot resizing, external USB destructive installation, remote unattended disk
writes, hibernation, unsupported firmware key enrollment, arbitrary RAID/LVM
layouts, custom-compiled kernel as default, anti-cheat gaming guarantees.

Unsupported or uncertain features must show **UNVERIFIED / UNSUPPORTED**, not pass.
